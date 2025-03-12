using System;
using System.IO;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

Host.CreateDefaultBuilder(args)
    .ConfigureWebHostDefaults(webBuilder =>
    {
        webBuilder.Configure(app =>
        {
            // A simple JSON-RPC handler for demonstration.
            app.Run(async context =>
            {
                // We only handle POST requests for this demo
                if (context.Request.Method == "POST")
                {
                    // Read the JSON request body
                    using var reader = new StreamReader(context.Request.Body);
                    var requestBody = await reader.ReadToEndAsync();
                    var requestJson = JsonNode.Parse(requestBody);

                    // Basic extraction
                    var method = requestJson?["method"]?.GetValue<string>();
                    var id = requestJson?["id"]?.GetValue<int>() ?? 1; // default if missing
                    var paramArray = requestJson?["params"]?.AsArray();

                    // Switch on the "method"
                    switch (method)
                    {
                        case "getBlockNumber":
                            {
                                // Return a fixed block number
                                var responseJson = new JsonObject
                                {
                                    ["jsonrpc"] = "2.0",
                                    ["result"] = 12345,
                                    ["id"] = id
                                };
                                await WriteJsonResponse(context, responseJson);
                                break;
                            }
                        case "getBlockHash":
                            {
                                // Expect a single param: block number (int)
                                int blockNumber = 0;
                                if (paramArray != null && paramArray.Count > 0)
                                {
                                    blockNumber = paramArray[0]?.GetValue<int>() ?? 0;
                                }

                                // Fake block hash generation
                                string fakeHash = $"0xFAKEHASH_FOR_BLOCK_{blockNumber}";

                                var responseJson = new JsonObject
                                {
                                    ["jsonrpc"] = "2.0",
                                    ["result"] = fakeHash,
                                    ["id"] = id
                                };
                                await WriteJsonResponse(context, responseJson);
                                break;
                            }
                        default:
                            {
                                // Unknown method
                                var responseJson = new JsonObject
                                {
                                    ["jsonrpc"] = "2.0",
                                    ["error"] = "Method not found",
                                    ["id"] = id
                                };
                                await WriteJsonResponse(context, responseJson);
                                break;
                            }
                    }
                }
                else
                {
                    // If not a POST, return a simple 404
                    context.Response.StatusCode = 404;
                }
            });
        });
    })
    .Build()
    .Run();

static async Task WriteJsonResponse(HttpContext context, JsonObject responseJson)
{
    var responseString = responseJson.ToJsonString();
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(responseString);
    return;
}
