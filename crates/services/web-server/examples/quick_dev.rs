#![allow(unused)] // For example code.

pub type Result<T> = core::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>; // For examples.

use serde_json::{json, Value};
use lib_decrypt::model;

// 定义自己的加密和转换宏
#[macro_export]
macro_rules! encrypt_and_json {
    ($data:expr) => {{
        let login_data = $data;
        let from_json = serde_json::to_string(&login_data)?;
        let encrypted_data = model::EncryptedData::encrypt_and_sign(&from_json)?;
        serde_json::json!(encrypted_data)
    }};
}

#[tokio::main]
async fn main() -> Result<()> {

	let hc = httpc_test::new_client("http://localhost:8080")?;

	// hc.do_get("/index.html").await?.print().await?;

	let login_data = json!({
		"username": "demo1",
		"pwd": "welcome"
	});

	let from_json = serde_json::to_string(&login_data)?;

	let encrypted_data = model::EncryptedData::encrypt_and_sign(&from_json)?;
	// -- Login
	let req_login = hc.do_post(
		"/api/login",
		json!(encrypted_data),
	);
	req_login.await?.print().await?;
	
	// -- Create Agent
	let req_create_agent = hc.do_post(
		"/api/rpc",
		encrypt_and_json!(json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "create_agent",
			"params": {
				"data": {
					"name": "agent AAA"
				}
			}
		})),
	);
	let result = req_create_agent.await?;
	result.print().await?;
	let agent_id = result.json_value::<i64>("/result/data/id")?;



	// -- Get Agent
	let req_get_agent = hc.do_post(
		"/api/rpc",
		encrypt_and_json!(json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "get_agent",
			"params": {
					"id": agent_id
			}
		})),
	);
	let result = req_get_agent.await?;
	result.print().await?;

	// -- Create Conv
	let req_create_conv = hc.do_post(
		"/api/rpc",
		encrypt_and_json!(json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "create_conv",
			"params": {
				"data": {
					"agent_id": agent_id,
					"title": "conv 01"
				}
			}
		})),
	);
	let result = req_create_conv.await?;
	result.print().await?;
	let conv_id = result.json_value::<i64>("/result/data/id")?;

	// -- Create ConvMsg
	let req_create_conv = hc.do_post(
		"/api/rpc",
		encrypt_and_json!(json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "add_conv_msg",
			"params": {
				"data": {
					"conv_id": conv_id,
					"content": "This is the first comment"
				}
			}
		})),
	);
	let result = req_create_conv.await?;
	result.print().await?;
	let conv_msg_id = result.json_value::<i64>("/result/data/id")?;

	// -- Logoff
	let req_logoff = hc.do_post(
		"/api/logoff",
		encrypt_and_json!(json!({
			"logoff": true
		})),
	);
	req_logoff.await?.print().await?;

	Ok(())
}
