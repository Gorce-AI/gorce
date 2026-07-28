use std::io;

use gorce_provider_abi::ToolInvokeParams;
use provider_template::TOOL_WEB_SEARCH;
use serde_json::{json, Value};

fn main() -> io::Result<()> {
    let package = gorce_provider_runtime::load_self_verified_package()?;
    gorce_provider_runtime::serve(&package, &handle_tool)
}

fn handle_tool(tool_name: &str, params: &ToolInvokeParams) -> Result<Value, String> {
    match tool_name {
        // EDIT ME: replace the deterministic body with a real call to your
        // vendor API, authenticated with the host-delivered scoped secret.
        TOOL_WEB_SEARCH => Ok(web_search(params)),
        other => Err(format!("tool is not implemented: {other}")),
    }
}

fn web_search(params: &ToolInvokeParams) -> Value {
    let query = params
        .input
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let max_results = params
        .input
        .get("max_results")
        .and_then(Value::as_u64)
        .unwrap_or(3)
        .min(5);
    json!({
        "query": query,
        "results": (0..max_results).map(|index| json!({
            "title": format!("{query} result {index}"),
            "url": format!("https://search.example.invalid/{index}"),
            "snippet": format!("deterministic result for {query}")
        })).collect::<Vec<_>>()
    })
}
