use reqwest::Client;
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    // -------------------------------------------------------------------------
    // 1) Call "getBlockNumber" with no parameters
    // -------------------------------------------------------------------------
    let request_1 = json!({
        "jsonrpc": "2.0",
        "method": "getBlockNumber",
        "params": [],
        "id": 1
    });

    let response_1 = client
        .post("http://localhost:5000")
        .json(&request_1)
        .send()
        .await?
        .json::<Value>()
        .await?;

    println!("Response from getBlockNumber: {}", response_1);


    // -------------------------------------------------------------------------
    // 2) Call "getBlockHash" with a block number parameter
    // -------------------------------------------------------------------------
    let request_2 = json!({
        "jsonrpc": "2.0",
        "method": "getBlockHash",
        "params": [ 9001 ], // pass a block number param
        "id": 2
    });

    let response_2 = client
        .post("http://localhost:5000")
        .json(&request_2)
        .send()
        .await?
        .json::<Value>()
        .await?;

    println!("Response from getBlockHash(9001): {}", response_2);

    Ok(())
}
