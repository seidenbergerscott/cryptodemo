using System;
using System.IO;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using System.Threading;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// --------------------------
// 1) In-Memory State
// --------------------------

// Method call counters
ConcurrentDictionary<string, int> methodCounts = new ConcurrentDictionary<string, int>();

// Current block number (start at decimal 12345 = 0x3039)
long blockNumber = 0x3039; 

// Simple address => balance mapping (long). In real Ethereum, you'd need bigger integers.
Dictionary<string, long> balances = new Dictionary<string, long>
{
    // Example addresses + balances:
    ["0x1111111111111111111111111111111111111111"] = 0xDE0B6B3A7640000, // 1 ETH in wei
    ["0x2222222222222222222222222222222222222222"] = 0x2540BE400        // 1e10 decimal
};

// --------------------------
// 2) JSON-RPC Endpoint (POST /)
// --------------------------
app.MapPost("/", async context =>
{
    using var reader = new StreamReader(context.Request.Body);
    string requestBody = await reader.ReadToEndAsync();

    // For logging/demo:
    Console.WriteLine($"[Server] Received request: {requestBody}");

    try
    {
        var requestJson = JsonNode.Parse(requestBody);
        string method = requestJson?["method"]?.GetValue<string>() ?? "unknown";
        int id = requestJson?["id"]?.GetValue<int>() ?? 1;
        var paramArray = requestJson?["params"]?.AsArray();

        // Increment the counter for this method
        methodCounts.AddOrUpdate(method, 1, (_, oldVal) => oldVal + 1);

        // Switch on the method name
        JsonObject responseJson;
        switch (method)
        {
            case "eth_blockNumber":
                // Return blockNumber as hex
                responseJson = BuildResult(id, $"0x{blockNumber:X}");
                break;

            case "eth_getBalance":
                // params: [ address, blockParameter ], we ignore blockParameter for demo
                if (paramArray == null || paramArray.Count < 1)
                {
                    responseJson = BuildError(id, -32602, "Invalid params for eth_getBalance");
                }
                else
                {
                    string address = paramArray[0]?.GetValue<string>()?.ToLower() ?? "";
                    long bal = 0;
                    if (balances.TryGetValue(address, out long foundBal))
                    {
                        bal = foundBal;
                    }
                    // Return as hex
                    responseJson = BuildResult(id, $"0x{bal:X}");
                }
                break;

            case "eth_sendTransaction":
                // Accept a simplified object: { from, to, value }
                if (paramArray == null || paramArray.Count < 1)
                {
                    responseJson = BuildError(id, -32602, "No transaction object");
                    break;
                }
                var txObj = paramArray[0];
                string from = txObj?["from"]?.GetValue<string>()?.ToLower() ?? "";
                string to = txObj?["to"]?.GetValue<string>()?.ToLower() ?? "";
                string valueHex = txObj?["value"]?.GetValue<string>() ?? "0x0";

                long valueWei = HexToLong(valueHex);

                // Adjust balances (extremely simplified)
                if (!balances.ContainsKey(from)) balances[from] = 0;
                if (!balances.ContainsKey(to)) balances[to] = 0;

                balances[from] -= valueWei;
                balances[to]   += valueWei;

                // Increment block number for each transaction (fake mining)
                Interlocked.Increment(ref blockNumber);

                // Return a fake tx hash
                string fakeTxHash = "0xFAKE" + Guid.NewGuid().ToString("N").Substring(0, 24);
                responseJson = BuildResult(id, fakeTxHash);
                break;

            default:
                responseJson = BuildError(id, -32601, $"Method {method} not found");
                break;
        }

        // Write the response
        string respString = responseJson.ToJsonString();
        Console.WriteLine($"[Server] Response: {respString}");
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(respString);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Server] Error: {ex.Message}");
        var errorJson = BuildError(1, -32700, "Parse error");
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(errorJson.ToJsonString());
    }
});

// ------------------------------------------
// 3) Stats Endpoint (GET /stats)
// ------------------------------------------
app.MapGet("/stats", (HttpContext context) =>
{
    // Build an object containing:
    //   - Method counts
    //   - Current blockNumber (both hex and decimal, if you like)
    //   - Balances (in hex or decimal)
    var stats = new
    {
        methodCounts = methodCounts,  // Key: methodName, Value: callCount
        blockNumberHex = $"0x{blockNumber:X}",
        blockNumberDec = blockNumber,
        balances = BuildHexBalanceDict(balances)
    };

    context.Response.ContentType = "application/json";
    return JsonSerializer.Serialize(stats);
});

app.Run();

// ------------------------------------------------------------------
// Helper Methods
// ------------------------------------------------------------------
static JsonObject BuildResult(int id, string result)
{
    return new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["result"] = result,
        ["id"] = id
    };
}

static JsonObject BuildError(int id, int code, string message)
{
    return new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["error"] = new JsonObject
        {
            ["code"] = code,
            ["message"] = message
        },
        ["id"] = id
    };
}

static long HexToLong(string hex)
{
    if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
    {
        hex = hex.Substring(2);
    }
    return Convert.ToInt64(hex, 16);
}

static Dictionary<string, string> BuildHexBalanceDict(Dictionary<string, long> balances)
{
    // Return a new dict with the same keys, but hex-encoded string values
    var result = new Dictionary<string, string>();
    foreach (var kvp in balances)
    {
        string addr = kvp.Key;
        long bal = kvp.Value;
        result[addr] = $"0x{bal:X}";
    }
    return result;
}
