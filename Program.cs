// our arguments
string url = args[0];
string pathToFile = args[1];

// fuzz GET requests
var sqlFuzzer = new GetFuzzer("SQL injection", "fd'sa", "SQL syntax");
var xssFuzzer = new GetFuzzer("XSS", "fd<xss>sa", "<xss>");

var sqlInjectionPoints = await sqlFuzzer.Fuzz(url);
var xssPoints = await xssFuzzer.Fuzz(url);

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

Console.WriteLine("SQL injection:");
logItems(sqlInjectionPoints);

Console.WriteLine("\nXSS points:");
logItems(xssPoints);


// fuzz a POST requests with parameters
var postFuzzer = new PostFuzzer(pathToFile);

Console.WriteLine("\nPOST request:");
var postPoints = postFuzzer.FuzzParameters();

logItems(postPoints);

// fuzz a POST with JSON

