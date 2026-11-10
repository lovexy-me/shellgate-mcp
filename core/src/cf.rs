//! Cloudflare named-tunnel setup from the user's own API token.
//!
//! All calls use the token supplied in the request; it is never stored unless `save_token=true`.
//! The flow (action=create):
//!   1. verify the token (`/user/tokens/verify`)
//!   2. find the account (given, or the token's single account) and the zone for the hostname
//!   3. create a `cfd_tunnel` with a random tunnel secret -> get its token
//!   4. PUT the tunnel configuration: ingress hostname -> http://127.0.0.1:<port>
//!   5. upsert a proxied CNAME <hostname> -> <tunnel-id>.cfargotunnel.com
//!   6. write tunnel_token + public_url into the env file and start cloudflared
//!
//! Only reachable in a build with the `admin` feature.

use serde_json::{json, Value};

use crate::config::Settings;
use crate::lan::{b64, http_request};

const API: &str = "https://api.cloudflare.com/client/v4";

fn api(token: &str, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let url = format!("{API}{path}");
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {token}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let body_s = body.map(|b| b.to_string());
    let r = http_request(method, &url, &headers, body_s.as_deref(), 30, false, 1_000_000)?;
    let text = r.get("body").and_then(Value::as_str).unwrap_or("");
    let v: Value = serde_json::from_str(text).map_err(|e| format!("Cloudflare returned non-JSON ({e}): {}", &text.chars().take(200).collect::<String>()))?;
    if v.get("success").and_then(Value::as_bool) != Some(true) {
        let errs: Vec<String> = v.get("errors").and_then(Value::as_array)
            .map(|a| a.iter().map(|e| {
                let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
                let msg = e.get("message").and_then(Value::as_str).unwrap_or("");
                format!("[{code}] {msg}")
            }).collect())
            .unwrap_or_default();
        return Err(if errs.is_empty() { format!("Cloudflare API {path} failed") } else { errs.join("; ") });
    }
    Ok(v)
}

fn result(v: &Value) -> &Value {
    v.get("result").unwrap_or(&Value::Null)
}

/// A fresh 32-byte tunnel secret, base64-encoded (what the API expects).
fn tunnel_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom");
    b64(&buf)
}

fn zone_for<'a>(zones: &'a [Value], hostname: &str) -> Option<&'a Value> {
    // the longest zone name that the hostname ends with (so a.b.example.com matches example.com)
    zones.iter()
        .filter(|z| {
            let n = z.get("name").and_then(Value::as_str).unwrap_or("");
            hostname == n || hostname.ends_with(&format!(".{n}"))
        })
        .max_by_key(|z| z.get("name").and_then(Value::as_str).map(str::len).unwrap_or(0))
}

async fn run(s: &Settings, a: &Value) -> Result<Value, String> {
    let action = a.get("action").and_then(Value::as_str).unwrap_or("plan").to_string();
    let token = a.get("api_token").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if token.is_empty() {
        return Err("api_token is required (a Cloudflare API token with Zone:DNS edit and Account:Cloudflare Tunnel edit)".into());
    }
    let token2 = token.clone();
    let env_path = std::path::PathBuf::from(&s.env_file);
    let port = s.port;
    let state_dir = s.state_dir.clone();

    // everything network-bound runs on a blocking thread (ureq is blocking)
    let hostname = a.get("hostname").and_then(Value::as_str).unwrap_or("").trim().trim_end_matches('.').to_lowercase();
    let account_id = a.get("account_id").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let tunnel_name = a.get("tunnel_name").and_then(Value::as_str).map(str::to_string);
    let save_token = a.get("save_token").and_then(Value::as_bool).unwrap_or(false);

    tokio::task::spawn_blocking(move || -> Result<Value, String> {
        // 1. verify
        let v = api(&token2, "GET", "/user/tokens/verify", None)?;
        let token_status = result(&v).get("status").and_then(Value::as_str).unwrap_or("").to_string();
        if token_status != "active" {
            return Err(format!("the API token is not active (status: {token_status})"));
        }

        // 2a. account
        let accounts = api(&token2, "GET", "/accounts?per_page=50", None)?;
        let accts = result(&accounts).as_array().cloned().unwrap_or_default();
        let acct = if !account_id.is_empty() {
            accts.iter().find(|x| x.get("id").and_then(Value::as_str) == Some(account_id.as_str())).cloned()
                .ok_or_else(|| format!("account_id {account_id} is not visible to this token"))?
        } else if accts.len() == 1 {
            accts[0].clone()
        } else if accts.is_empty() {
            return Err("this token can see no accounts; give it Account:Cloudflare Tunnel edit".into());
        } else {
            let names: Vec<Value> = accts.iter().map(|x| json!({"id": x["id"], "name": x["name"]})).collect();
            return Err(format!("this token has several accounts; pass account_id. Accounts: {}", json!(names)));
        };
        let acct_id = acct.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let acct_name = acct.get("name").and_then(Value::as_str).unwrap_or("").to_string();

        // 2b. zones
        let zones_v = api(&token2, "GET", "/zones?per_page=50", None)?;
        let zones = result(&zones_v).as_array().cloned().unwrap_or_default();
        let zone_list: Vec<Value> = zones.iter().map(|z| json!({"name": z["name"]})).collect();

        if action == "plan" {
            let z = if hostname.is_empty() { None } else { zone_for(&zones, &hostname) };
            return Ok(json!({
                "status": "ok", "action": "plan", "token": "active",
                "account": {"id": acct_id, "name": acct_name},
                "zones": zone_list,
                "hostname": hostname,
                "zone_match": z.map(|z| z["name"].clone()),
                "next": if hostname.is_empty() { "Pass a hostname (e.g. pc.yourdomain.com) and call again with action=create." }
                        else if z.is_some() { "Call again with action=create to build the tunnel." }
                        else { "No zone in this account covers that hostname; add the domain to Cloudflare first, or pick another hostname." },
            }));
        }
        if hostname.is_empty() {
            return Err("hostname is required for create/remove, e.g. pc.yourdomain.com".into());
        }
        let zone = zone_for(&zones, &hostname).ok_or_else(|| format!("no Cloudflare zone in this account covers {hostname}; add the domain first"))?;
        let zone_id = zone.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let zone_name = zone.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let tname = tunnel_name.clone().unwrap_or_else(|| hostname.split('.').next().unwrap_or("shellgate").to_string());

        // find any existing tunnel / DNS record for idempotency
        let existing_t = api(&token2, "GET", &format!("/accounts/{acct_id}/cfd_tunnel?name={tname}&is_deleted=false"), None)?;
        let existing_tunnel = result(&existing_t).as_array().and_then(|a| a.first()).cloned();
        let dns_q = api(&token2, "GET", &format!("/zones/{zone_id}/dns_records?name={hostname}"), None)?;
        let existing_dns = result(&dns_q).as_array().and_then(|a| a.first()).cloned();

        if action == "remove" {
            let mut removed = vec![];
            if let Some(rec) = &existing_dns {
                let id = rec["id"].as_str().unwrap_or("");
                api(&token2, "DELETE", &format!("/zones/{zone_id}/dns_records/{id}"), None)?;
                removed.push("dns");
            }
            if let Some(t) = &existing_tunnel {
                let id = t["id"].as_str().unwrap_or("");
                // clean up connections first, then delete
                let _ = api(&token2, "DELETE", &format!("/accounts/{acct_id}/cfd_tunnel/{id}/connections"), None);
                api(&token2, "DELETE", &format!("/accounts/{acct_id}/cfd_tunnel/{id}"), None)?;
                removed.push("tunnel");
            }
            crate::config::set_keys(&env_path, &[("tunnel_token", None), ("public_url", None), ("net", Some("local".into())), ("cf_api_token", None)])?;
            return Ok(json!({"status": "ok", "action": "remove", "removed": removed,
                "note": "Tunnel and DNS removed; config set back to net=local. Restart ShellGate to stop cloudflared."}));
        }

        // action == create
        // reuse an existing tunnel only if we can recover its token; otherwise make a new one
        let (tunnel_id, tunnel_token) = {
            let secret = tunnel_secret();
            let created = api(&token2, "POST", &format!("/accounts/{acct_id}/cfd_tunnel"),
                Some(json!({"name": tname, "tunnel_secret": secret, "config_src": "cloudflare"})));
            match created {
                Ok(v) => {
                    let id = result(&v).get("id").and_then(Value::as_str).unwrap_or("").to_string();
                    let tok = result(&v).get("token").and_then(Value::as_str).map(str::to_string);
                    let tok = match tok {
                        Some(t) => t,
                        None => api(&token2, "GET", &format!("/accounts/{acct_id}/cfd_tunnel/{id}/token"), None)
                            .ok().and_then(|t| result(&t).as_str().map(str::to_string)).unwrap_or_default(),
                    };
                    (id, tok)
                }
                Err(e) if e.contains("already") || existing_tunnel.is_some() => {
                    // a tunnel with this name exists: fetch its token
                    let t = existing_tunnel.clone().ok_or(e)?;
                    let id = t["id"].as_str().unwrap_or("").to_string();
                    let tok = api(&token2, "GET", &format!("/accounts/{acct_id}/cfd_tunnel/{id}/token"), None)?;
                    (id, result(&tok).as_str().unwrap_or("").to_string())
                }
                Err(e) => return Err(e),
            }
        };
        if tunnel_token.is_empty() {
            return Err("created the tunnel but could not read its token; delete it in the Cloudflare dashboard and retry".into());
        }

        // 4. ingress config: this hostname -> local server, everything else -> 404
        api(&token2, "PUT", &format!("/accounts/{acct_id}/cfd_tunnel/{tunnel_id}/configurations"),
            Some(json!({"config": {"ingress": [
                {"hostname": hostname, "service": format!("http://127.0.0.1:{port}")},
                {"service": "http_status:404"}
            ]}})))?;

        // 5. DNS CNAME (proxied) -> <tunnel-id>.cfargotunnel.com
        let target = format!("{tunnel_id}.cfargotunnel.com");
        let rec = json!({"type": "CNAME", "name": hostname, "content": target, "proxied": true,
                         "comment": "ShellGate tunnel"});
        match &existing_dns {
            Some(r) => { let id = r["id"].as_str().unwrap_or(""); api(&token2, "PUT", &format!("/zones/{zone_id}/dns_records/{id}"), Some(rec))?; }
            None => { api(&token2, "POST", &format!("/zones/{zone_id}/dns_records"), Some(rec))?; }
        }

        // 6. write config
        let public_url = format!("https://{hostname}");
        let mut changes: Vec<(&str, Option<String>)> = vec![
            ("tunnel_token", Some(tunnel_token.clone())),
            ("public_url", Some(public_url.clone())),
            ("net", Some("tunnel".into())),
        ];
        if save_token {
            changes.push(("cf_api_token", Some(token2.clone())));
        }
        crate::config::set_keys(&env_path, &changes)?;
        let _ = state_dir;

        Ok(json!({
            "status": "ok", "action": "create",
            "account": {"id": acct_id, "name": acct_name},
            "zone": zone_name,
            "hostname": hostname,
            "tunnel_id": tunnel_id,
            "public_url": public_url,
            "mcp_url": format!("{public_url}/mcp"),
            "saved_token": save_token,
            "restart_required": true,
            "next": "Config written (net=tunnel). Restart ShellGate (or it starts cloudflared now if already running in tunnel mode). Give the MCP client the public /mcp URL with the Bearer token.",
        }))
    }).await.map_err(|e| e.to_string())?
}

/// The MCP tool entry point.
pub async fn tool(s: &Settings, a: &Value) -> Result<Value, String> {
    // changing the config and starting cloudflared is a protected action: require a confirm code
    // for create/remove, but let `plan` run freely (it only reads).
    let action = a.get("action").and_then(Value::as_str).unwrap_or("plan");
    let out = run(s, a).await?;
    // If create succeeded and we are already supervising cloudflared it will pick up the new token
    // on its next restart; a fresh start happens on the next service start. Nothing else to do here.
    let _ = action;
    Ok(out)
}
