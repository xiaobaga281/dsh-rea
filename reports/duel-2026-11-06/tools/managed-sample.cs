using System;
using System.Net;

class Agent
{
    static string c2 = "https://dotnet.example-corp.net/gate";
    static string key = "managed-stage-key";

    static void Main()
    {
        var client = new WebClient();
        client.Headers.Add("X-Orbit", "managed");
        Console.WriteLine(c2 + key);
    }
}
