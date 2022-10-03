class GetFuzzer
{
    private HttpClient Client = new HttpClient();
    private string Name;
    private string Dirt;
    private string ExpectedFeedback;

    public GetFuzzer(string name, string dirt, string expectedFeedback)
    {
        Name = name;
        Dirt = dirt;
        ExpectedFeedback = expectedFeedback;
    }

    public async Task<IEnumerable<string?>> Fuzz(string url)
    {
        // create some dirty urls
        var parameters = url.Remove(0, url.IndexOf('?') + 1).Split('&');
        var paramsAndDirtyUrl = parameters.Select(param => (
            param,
            url.Replace(param, param + Dirt)
        ));

        // get the responses and check if the dirt is still there
        var paramsAndResponses = new List<(string, string)>();
        foreach ((var param, var dirtyUrl) in paramsAndDirtyUrl)
        {
            paramsAndResponses.Add((param, await Client.GetStringAsync(dirtyUrl)));
        }

        var result = paramsAndResponses
            .Where(paramAndResponse => paramAndResponse.Item2.Contains(ExpectedFeedback))
            .Select(paramAndResponse =>
            {
                var parameterName = paramAndResponse.Item1.Split('=').First();
                return $"{Name} point found in parameter: \"{parameterName}\"";
            });

        return result;
    }
}
