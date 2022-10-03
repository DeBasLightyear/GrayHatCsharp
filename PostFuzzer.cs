using System.Text;
using System.Net;
using System.Net.Sockets;

class PostFuzzer
{
    public string Host;
    public string Request;
    public string[] Parameters;
    private string[] RequestLines;

    public PostFuzzer(string pathToFile)
    {
        // read the request file
        RequestLines = File.ReadAllLines(pathToFile);
        Request = String.Join('\n', RequestLines);

        // get the parameters and the host
        Parameters = RequestLines.Last().Split('&');
        Host = RequestLines
            .Where(line => line.StartsWith("Host:"))
            .Select(line => line.Split(' ')[1].Replace("\r", string.Empty))
            .First();
    }


    public IEnumerable<string?> FuzzParameters()
    {
        var remoteHost = new IPEndPoint(IPAddress.Parse(Host), 80);

        return Parameters
            .Select(parameter => FuzzParameter(remoteHost, parameter))
            .Where(result => result != null);
    }

    public IEnumerable<string?> FuzzJson()
    {
        return new [] {"foo"};
    }

    private string? FuzzParameter(IPEndPoint remoteHost, string parameter)
    {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            // connect to the websocket
            socket.Connect(remoteHost);

            // malform the request
            var value = parameter.Split('=')[1];
            var fuzzedValue = value + "'";
            var fuzzedRequest = Request.Replace("=" + value, "=" + value + "'");

            // convert the string to a byte array and send it over
            var requestBytes = Encoding.ASCII.GetBytes(fuzzedRequest);
            socket.Send(requestBytes);

            // receive the buffer
            var buffer = new byte[socket.ReceiveBufferSize];
            socket.Receive(buffer);
            var response = Encoding.ASCII.GetString(buffer);

            // check if there are any vulnerabilities
            var parameterName = parameter.Split('=').First();

            return response.Contains("SQL syntax")
                ? $"Parameter \"{parameterName}\" seems vulnerable to SQL injection with value: {fuzzedValue}"
                : null;
        }
    }
}
