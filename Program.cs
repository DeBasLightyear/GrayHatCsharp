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

var fuzzBadstoreGetRequest = async delegate ()
{
    // fuzz GET requests
    var sqlFuzzer = new GetFuzzer("SQL injection", "fd'sa", "SQL syntax");
    var xssFuzzer = new GetFuzzer("XSS", "fd<xss>sa", "<xss>");

    var url = "http://192.168.56.100/cgi-bin/badstore.cgi?searchquery=foo&action=search&x=0&y=0";

    // SQL injections
    var sqlInjectionPoints = await sqlFuzzer.Fuzz(url);
    logItems(sqlInjectionPoints);

    // XSS
    var xssPoints = await xssFuzzer.Fuzz(url);
    logItems(xssPoints);
};

var fuzzBadStorePost = delegate ()
{
    // fuzz a POST requests with parameters
    var pathToFile = "./post/BadStore.txt";
    var postParameterFuzzer = new PostParameterFuzzer(pathToFile);

    Console.WriteLine("\nPOST request with parameters:");
    var postParameterPoints = postParameterFuzzer.Fuzz();

    logItems(postParameterPoints);
};

var fuzzVulnJsonPost = async delegate ()
{
    // fuzz a POST with JSON
    var url = "http://192.168.2.29/Vulnerable.ashx";
    var pathToFile = "./post/CsharpVulnJson.txt";
    var postJsonFuzzer = new PostJsonFuzzer(url, pathToFile);

    Console.WriteLine("\nPOST request with JSON:");
    await postJsonFuzzer.Fuzz();
};


await fuzzBadstoreGetRequest();
fuzzBadStorePost();
await fuzzVulnJsonPost();
