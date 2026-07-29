use std::io;

use gorce_provider_abi::ToolInvokeParams;
use serde_json::{json, Value};

use claude_code::{TOOL_WEB_FETCH, TOOL_WEB_SEARCH};

fn main() -> io::Result<()> {
    let package = gorce_provider_runtime::load_self_verified_package()?;
    gorce_provider_runtime::serve(&package, &handle_tool)
}

fn handle_tool(tool_name: &str, params: &ToolInvokeParams) -> Result<Value, String> {
    match tool_name {
        TOOL_WEB_SEARCH => Ok(web_search(params)),
        TOOL_WEB_FETCH => Ok(web_fetch(params)),
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
            "url": format!("https://search.anthropic.invalid/{index}"),
            "snippet": format!("deterministic result for {query}")
        })).collect::<Vec<_>>()
    })
}

fn web_fetch(params: &ToolInvokeParams) -> Value {
    let url = params
        .input
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "url": url,
        "content": format!("deterministic fetch preview for {url}")
    })
}
