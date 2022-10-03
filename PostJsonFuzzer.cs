using System.Net.Http.Headers;
using Newtonsoft.Json;

class PostJsonFuzzer
{
    public string Url;
    public string[] RequestLines;
    private HttpClient Client = new HttpClient();

    public PostJsonFuzzer(string url, string pathToFile)
    {
        Url = url;
        RequestLines = File.ReadAllLines(pathToFile);
    }

    public Task Fuzz()
    {
        var requestContent = JsonConvert.DeserializeObject<Dictionary<string, object>>(
            RequestLines.Last()
        );

        var fuzzedContent = requestContent
            .Select(keyValue => Fuzz(keyValue))
            .Where(fuzzableKeyValue =>
            {
                (var isFuzzed, var _) = fuzzableKeyValue;
                return isFuzzed;
            })
            .Select(fuzzedKeyValue =>
            {
                (var _, var pair) = fuzzedKeyValue;

                // place the fuzzed value in the dictionary
                var fuzzedBody = new Dictionary<string, object>(requestContent);
                fuzzedBody[pair.Key] = pair.Value;

                return (pair.Key, fuzzedBody);
            });

        return Task.Run(async () =>
        {
            var nrOfVulnerabilities = 0;

            foreach ((var key, var content) in fuzzedContent)
            {
                var response = await PostFuzzedContent(content);
                var isVulnerable = response.Contains("syntax error") || response.Contains("unterminated");

                if (isVulnerable)
                {
                    nrOfVulnerabilities++;
                    Console.WriteLine($"SQL injection vector in property: \"{key}\"");
                }
            }

            if (nrOfVulnerabilities == 0)
            {
                Console.WriteLine("Nothing found");
            }
        });
    }

    private (bool, KeyValuePair<string, object>) Fuzz(KeyValuePair<string, object> pair)
    {
        var fuzzableTypes = new[]{
            typeof(string),
            typeof(Int16),
            typeof(Int32),
            typeof(Int64),
        };

        if (Array.Exists(fuzzableTypes, type => type == pair.Value.GetType()))
        {
            // add an apostrophe to fuzz for SQL injections
            var fuzzedKeyValue = new KeyValuePair<string, object>(
                pair.Key, pair.Value.ToString() + "'"
            );

            return (true, fuzzedKeyValue);
        }

        // return unchanged
        return (false, pair);
    }

    private async Task<string> PostFuzzedContent(Dictionary<string, object> requestBody)
    {
        // prepare the request
        var body = JsonConvert.SerializeObject(requestBody);
        var bodyBuffer = System.Text.Encoding.ASCII.GetBytes(body);
        var byteContent = new ByteArrayContent(bodyBuffer);
        byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/javascript");

        // execute the request
        var response = await Client.PostAsync(Url, byteContent);
        return await response.Content.ReadAsStringAsync();
    }
}
