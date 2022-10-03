using System.Text;
using System.Net;
using System.Net.Sockets;

class PostParameterFuzzer
{
    public string[] RequestLines;

    public PostParameterFuzzer(string pathToFile)
    {
        // read the request file
        RequestLines = File.ReadAllLines(pathToFile);
    }

    public IEnumerable<string?> Fuzz()
    {
        // prepare the connection to the remote host
        var hostAddress = RequestLines
            .Where(line => line.StartsWith("Host:"))
            .Select(line => line.Split(' ')[1].Replace("\r", string.Empty))
            .First();
        var remoteHost = new IPEndPoint(IPAddress.Parse(hostAddress), 80);

        // get the request and its separate parameters
        var parameters = RequestLines.Last().Split('&');
        var request = String.Join('\n', RequestLines);

        return parameters
            .Select(parameter => FuzzParameter(remoteHost, parameter, request))
            .Where(result => result != null);
    }

    private string? FuzzParameter(IPEndPoint remoteHost, string parameter, string request)
    {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            // connect to the websocket
            socket.Connect(remoteHost);

            // malform the request
            var value = parameter.Split('=')[1];
            var fuzzedValue = value + "'";
            var fuzzedRequest = request.Replace("=" + value, "=" + value + "'");

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
