// our arguments
string url = args[0];
string pathToFile = args[1];

var logItems = delegate (IEnumerable<string?> items)
{
    if (items.Count() == 0)
    {
        Console.WriteLine("Nothing found");
        return;
    }

    foreach (string item in items)
    {
        Console.WriteLine(item);
    }
};

// fuzz GET requests
var sqlFuzzer = new GetFuzzer("SQL injection", "fd'sa", "SQL syntax");
var xssFuzzer = new GetFuzzer("XSS", "fd<xss>sa", "<xss>");

var sqlInjectionPoints = await sqlFuzzer.Fuzz(url);
var xssPoints = await xssFuzzer.Fuzz(url);

Console.WriteLine("SQL injection:");
logItems(sqlInjectionPoints);

Console.WriteLine("\nXSS points:");
logItems(xssPoints);


// fuzz a POST requests with parameters
var postParameterFuzzer = new PostParameterFuzzer(pathToFile);

Console.WriteLine("\nPOST request with parameters:");
var postParameterPoints = postParameterFuzzer.FuzzParameters();

logItems(postParameterPoints);

// fuzz a POST with JSON
// var postJsonFuzzer = new PostFuzzer(pathToFile);

// Console.WriteLine("\nPOST request with JSON:");
// var postJsonPoints = postJsonFuzzer.FuzzJson();

// logItems(postJsonPoints);

