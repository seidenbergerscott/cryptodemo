use reqwest::Client;
use serde_json::{json, Value};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    // 1) net_version
    let version = eth_net_version(&client).await?;
    println!("net_version => {}", version);

    // 2) eth_blockNumber (before)
    let block_num_hex_before = eth_block_number(&client).await?;
    let block_num_dec_before = hex_to_u128(&block_num_hex_before).unwrap_or_default();
    println!("eth_blockNumber (before) => hex: {}, decimal: {}", block_num_hex_before, block_num_dec_before);

    // 3) eth_getBalance for two addresses
    let addr1 = "0x1111111111111111111111111111111111111111";
    let addr2 = "0x2222222222222222222222222222222222222222";

    let bal_addr1_hex_before = eth_get_balance(&client, addr1).await?;
    let bal_addr1_dec_before = hex_to_u128(&bal_addr1_hex_before).unwrap_or(0);
    println!("Balance of {} => hex: {}, decimal: {}", addr1, bal_addr1_hex_before, bal_addr1_dec_before);

    let bal_addr2_hex_before = eth_get_balance(&client, addr2).await?;
    let bal_addr2_dec_before = hex_to_u128(&bal_addr2_hex_before).unwrap_or(0);
    println!("Balance of {} => hex: {}, decimal: {}", addr2, bal_addr2_hex_before, bal_addr2_dec_before);

    // 4) eth_sendTransaction
    // We'll send 0x10 wei (decimal 16) from addr1 to addr2
    let tx_hash = eth_send_transaction(&client, addr1, addr2, "0x10").await?;
    println!("eth_sendTransaction => tx_hash: {}", tx_hash);

    // 5) eth_blockNumber (after)
    let block_num_hex_after = eth_block_number(&client).await?;
    let block_num_dec_after = hex_to_u128(&block_num_hex_after).unwrap_or_default();
    println!("eth_blockNumber (after) => hex: {}, decimal: {}", block_num_hex_after, block_num_dec_after);

    // 6) eth_getBalance again
    let bal_addr1_hex_after = eth_get_balance(&client, addr1).await?;
    let bal_addr1_dec_after = hex_to_u128(&bal_addr1_hex_after).unwrap_or(0);
    println!("Balance of {} => hex: {}, decimal: {}", addr1, bal_addr1_hex_after, bal_addr1_dec_after);

    let bal_addr2_hex_after = eth_get_balance(&client, addr2).await?;
    let bal_addr2_dec_after = hex_to_u128(&bal_addr2_hex_after).unwrap_or(0);
    println!("Balance of {} => hex: {}, decimal: {}", addr2, bal_addr2_hex_after, bal_addr2_dec_after);

    Ok(())
}

// -----------------------------------------------------------------------------
//  JSON-RPC Call Implementations
// -----------------------------------------------------------------------------

async fn eth_net_version(client: &Client) -> Result<String, Box<dyn Error>> {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "net_version",
        "params": [],
        "id": 1
    });
    let resp = send_rpc_request(client, &request).await?;
    Ok(resp["result"].as_str().unwrap_or_default().to_string())
}

async fn eth_block_number(client: &Client) -> Result<String, Box<dyn Error>> {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    });
    let resp = send_rpc_request(client, &request).await?;
    Ok(resp["result"].as_str().unwrap_or("0x0").to_string())
}

async fn eth_get_balance(client: &Client, address: &str) -> Result<String, Box<dyn Error>> {
    let request = json!({
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [ address, "latest" ],
        "id": 1
    });
    let resp = send_rpc_request(client, &request).await?;
    Ok(resp["result"].as_str().unwrap_or("0x0").to_string())
}

async fn eth_send_transaction(
    client: &Client,
    from: &str,
    to: &str,
    value_hex: &str
) -> Result<String, Box<dyn Error>> {
    // For real usage, transactions can have more fields, but we keep it simple
    let tx_obj = json!({
        "from": from,
        "to": to,
        "value": value_hex
    });
    let request = json!({
        "jsonrpc": "2.0",
        "method": "eth_sendTransaction",
        "params": [ tx_obj ],
        "id": 1
    });
    let resp = send_rpc_request(client, &request).await?;
    Ok(resp["result"].as_str().unwrap_or_default().to_string())
}

// -----------------------------------------------------------------------------
//  Reusable HTTP JSON-RPC Sender
// -----------------------------------------------------------------------------

async fn send_rpc_request(client: &Client, request_body: &Value) -> Result<Value, Box<dyn Error>> {
    let response = client
        .post("http://localhost:5000")
        .json(request_body)
        .send()
        .await?;

    let json_resp = response.json::<Value>().await?;
    Ok(json_resp)
}

// -----------------------------------------------------------------------------
//  Hex Parsing Helper
// -----------------------------------------------------------------------------

fn hex_to_u128(hex_str: &str) -> Option<u128> {
    let no_prefix = hex_str.trim_start_matches("0x");
    u128::from_str_radix(no_prefix, 16).ok()
}
