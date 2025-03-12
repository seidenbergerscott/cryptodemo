using System;
using System.IO;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

public class Program
{
    // -----------------------------
    //  In-Memory State Simulation
    // -----------------------------
    private static long _blockNumber = 0x3039; // 0x3039 = 12345 in decimal
    private static Dictionary<string, long> _balances = new Dictionary<string, long>
    {
        // Pretend these are Ethereum addresses
        // The values are in "wei" (smallest unit), but we won't do real conversions here.
        { "0x1111111111111111111111111111111111111111", 0xDE0B6B3A7640000 }, // 1 ETH in wei (hex) = 0xDE0B6B3A7640000
        { "0x2222222222222222222222222222222222222222", 0x2540BE400 },        // 1e10 decimal
    };

    public static void Main(string[] args)
    {
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.Configure(app =>
                {
                    // Default to http://localhost:5000
                    app.Run(async context =>
                    {
                        if (context.Request.Method == "POST")
                        {
                            using var reader = new StreamReader(context.Request.Body);
                            string requestBody = await reader.ReadToEndAsync();

                            // Log for demonstration
                            Console.WriteLine($"[Server] Request: {requestBody}");

                            try
                            {
                                var requestJson = JsonNode.Parse(requestBody);
                                var method = requestJson?["method"]?.GetValue<string>();
                                var id = requestJson?["id"]?.GetValue<int>() ?? 1;
                                var paramArray = requestJson?["params"]?.AsArray();

                                JsonObject responseJson;

                                switch (method)
                                {
                                    case "net_version":
                                        // Return "1" for Mainnet (in reality, it might be a different chain ID)
                                        responseJson = BuildResultResponse(id, "1");
                                        await WriteResponse(context, responseJson);
                                        break;

                                    case "eth_blockNumber":
                                        // Return the block number in hex string format, e.g. "0x3039"
                                        // Real spec: "result" must be a hex string
                                        responseJson = BuildResultResponse(id, $"0x{_blockNumber:X}");
                                        await WriteResponse(context, responseJson);
                                        break;

                                    case "eth_getBalance":
                                        // Expects: [ address, blockParameter ], e.g. ["0xabc...", "latest"]
                                        // We'll ignore blockParameter for simplicity and just do "latest".
                                        if (paramArray == null || paramArray.Count < 1)
                                        {
                                            responseJson = BuildErrorResponse(id, -32602, "Invalid params");
                                        }
                                        else
                                        {
                                            var address = paramArray[0]?.GetValue<string>()?.ToLower();
                                            // Return balance in hex
                                            if (!string.IsNullOrEmpty(address) && _balances.ContainsKey(address))
                                            {
                                                long bal = _balances[address];
                                                responseJson = BuildResultResponse(id, $"0x{bal:X}");
                                            }
                                            else
                                            {
                                                // If address not found, assume zero balance
                                                responseJson = BuildResultResponse(id, "0x0");
                                            }
                                        }
                                        await WriteResponse(context, responseJson);
                                        break;

                                    case "eth_sendTransaction":
                                        // Typically: "params" => [ { from, to, value, ... } ]
                                        // We'll do a simplified transaction with just (from, to, value)
                                        if (paramArray == null || paramArray.Count < 1)
                                        {
                                            responseJson = BuildErrorResponse(id, -32602, "No transaction object provided");
                                            await WriteResponse(context, responseJson);
                                            break;
                                        }

                                        var txObj = paramArray[0];
                                        var from = txObj?["from"]?.GetValue<string>()?.ToLower();
                                        var to = txObj?["to"]?.GetValue<string>()?.ToLower();
                                        var valueHex = txObj?["value"]?.GetValue<string>(); // e.g. "0x10"

                                        if (string.IsNullOrEmpty(from) || string.IsNullOrEmpty(to) || string.IsNullOrEmpty(valueHex))
                                        {
                                            responseJson = BuildErrorResponse(id, -32602, "Transaction object missing fields");
                                            await WriteResponse(context, responseJson);
                                            break;
                                        }

                                        // Convert hex string to long (wei)
                                        // In real Ethereum, these can exceed 64-bit range, but let's keep it simple
                                        long weiValue = HexToLong(valueHex);

                                        // Deduct from "from" balance, add to "to" balance
                                        // (No real checks for insufficient balance, gas, etc.)
                                        if (!_balances.ContainsKey(from))
                                        {
                                            // if not found, assume 0
                                            _balances[from] = 0;
                                        }
                                        if (!_balances.ContainsKey(to))
                                        {
                                            _balances[to] = 0;
                                        }

                                        _balances[from] -= weiValue;
                                        _balances[to] += weiValue;

                                        // Fake: increment block number each time a tx is "mined"
                                        Interlocked.Increment(ref _blockNumber);

                                        // Return a fake transaction hash
                                        var fakeTxHash = $"0xFAKE{Guid.NewGuid().ToString().Replace("-", "").Substring(0, 24)}";
                                        responseJson = BuildResultResponse(id, fakeTxHash);
                                        await WriteResponse(context, responseJson);
                                        break;

                                    default:
                                        // Method not found
                                        responseJson = BuildErrorResponse(id, -32601, $"Method {method} not found");
                                        await WriteResponse(context, responseJson);
                                        break;
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[Server] Error parsing request: {ex}");
                                var errorJson = BuildErrorResponse(1, -32700, "Parse error");
                                await WriteResponse(context, errorJson);
                            }
                        }
                        else
                        {
                            // Only POST is supported for JSON-RPC
                            context.Response.StatusCode = 404;
                        }
                    });
                });
            })
            .Build()
            .Run();
    }

    // Build a success JSON-RPC response { "jsonrpc":"2.0", "result":..., "id":... }
    private static JsonObject BuildResultResponse(int id, string result)
    {
        return new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["result"] = result,
            ["id"] = id
        };
    }

    // Build an error JSON-RPC response { "jsonrpc":"2.0", "error":{ "code":..., "message":... }, "id":... }
    private static JsonObject BuildErrorResponse(int id, int code, string message)
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

    private static async Task WriteResponse(HttpContext context, JsonObject responseJson)
    {
        string responseString = responseJson.ToJsonString();
        Console.WriteLine($"[Server] Response: {responseString}");
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(responseString);
    }

    // Convert hex string (e.g. "0x1A") to a long
    private static long HexToLong(string hexStr)
    {
        if (hexStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            hexStr = hexStr.Substring(2);
        }
        return Convert.ToInt64(hexStr, 16);
    }
}
