//! Android screen control through the app's accessibility service (SgA11yService.kt).
//! The binary cannot call Android APIs; the app listens on 127.0.0.1 while the user has the
//! service turned on and leaves {port, secret} in <state_dir>/a11y.json (app-private).
//! Tools are listed only in the Android build; the bridge protocol is plain enough to test anywhere.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const TOOL_NAMES: &[&str] = &["android_screen", "android_act"];
const NOT_ON: &str = "screen control is off: on the phone open ShellGate, then 屏幕控制（无障碍）→ 去打开, and turn on \"ShellGate 屏幕控制\"";

static LAST_TREE: Mutex<String> = Mutex::new(String::new());

pub fn definitions() -> Vec<Value> {
    let s = |d: &str| json!({"type": "string", "description": d});
    let i = |d: &str| json!({"type": "integer", "description": d});
    let obj = |p: Value, r: &[&str]| json!({"type": "object", "properties": p, "required": r});
    vec![
        json!({"name": "android_screen", "description": "Read the phone screen through the ShellGate accessibility service: action=tree (default) lists on-screen controls, one line each `[ref] Class \"text\" #view_id @(x,y wxh) flags` (password fields never show their text); action=screenshot returns a PNG (Android 11+, scaled to max_width, default 1080). Use the refs with android_act.",
               "inputSchema": obj(json!({"action": {"type": "string", "enum": ["tree", "screenshot"]}, "max_nodes": i("tree: default 300"), "max_width": i("screenshot: default 1080, 0 = full size")}), &[])}),
        json!({"name": "android_act", "description": "Act on the phone: click / long_click / set_text / scroll_forward / scroll_backward on a ref from the last android_screen tree; tap or swipe at screen pixels (x, y, x2, y2, ms); or a system action: back, home, recents, notifications, quick_settings, lock_screen, power_dialog. Clicking Shut down / Delete style controls, power_dialog, and typed text the command policy flags need confirm_code.",
               "inputSchema": obj(json!({"action": s("click | long_click | set_text | scroll_forward | scroll_backward | tap | swipe | back | home | recents | notifications | quick_settings | lock_screen | power_dialog"),
                                         "ref": i("Ref from android_screen tree"), "text": s("set_text: the text"),
                                         "x": i("tap/swipe start x (screen pixels)"), "y": i("tap/swipe start y"), "x2": i("swipe end x"), "y2": i("swipe end y"), "ms": i("gesture duration"),
                                         "confirm_code": s("One-time code from a previous confirmation_required answer, only after the user agreed")}), &["action"])}),
    ]
}

/// Ask the app's accessibility bridge.
pub async fn call(state_dir: &str, mut req: Value, timeout: Duration) -> Result<Value, String> {
    let path = std::path::Path::new(state_dir).join("a11y.json");
    let info: Value = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).ok_or(NOT_ON)?;
    let port = info["port"].as_u64().ok_or(NOT_ON)? as u16;
    req["secret"] = info["secret"].clone();
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|_| NOT_ON.to_string())?;
        let mut line = serde_json::to_string(&req).unwrap_or_default();
        line.push('\n');
        s.write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut r = BufReader::new(s);
        let mut out = String::new();
        r.read_line(&mut out).await.map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(out.trim()).map_err(|e| format!("bad answer from the app: {e}"))?;
        match (v.get("ok"), v.get("err")) {
            (Some(ok), _) => Ok(ok.clone()),
            (_, Some(e)) => Err(e.as_str().unwrap_or("error").to_string()),
            _ => Err("empty answer from the app".into()),
        }
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| "the phone did not answer in time".to_string())?
}

pub fn remember_tree(t: &str) {
    *LAST_TREE.lock().unwrap() = t.to_string();
}

/// The line of the last tree for a ref, e.g. `[12] Button "Delete" ...`.
pub fn tree_line(r: i64) -> Option<String> {
    let tag = format!("[{r}] ");
    LAST_TREE.lock().unwrap().lines().map(str::trim_start).find(|l| l.starts_with(&tag)).map(str::to_string)
}

/// Translate an android_act call into a bridge request plus the reasons it needs the user's OK.
pub fn plan(a: &Value, danger: &dyn Fn(&str) -> Vec<String>) -> Result<(Value, Vec<String>), String> {
    let action = a["action"].as_str().unwrap_or("");
    let num = |k: &str| a.get(k).and_then(Value::as_f64).ok_or(format!("{action}: {k} is required"));
    let mut reasons = vec![];
    let req = match action {
        "click" | "long_click" | "set_text" | "scroll_forward" | "scroll_backward" => {
            let r = a.get("ref").and_then(Value::as_i64).ok_or(format!("{action}: ref is required"))?;
            if action != "set_text" && action.ends_with("click") {
                if let Some(l) = tree_line(r) {
                    if crate::desktop::risky_control(&l) {
                        reasons.push(format!("{action} on {l}"));
                    }
                }
            }
            let mut v = json!({"op": action, "ref": r});
            if action == "set_text" {
                let t = a["text"].as_str().ok_or("set_text: text is required")?;
                reasons.extend(danger(t).into_iter().map(|w| format!("{w} (typed)")));
                v["text"] = json!(t);
            }
            v
        }
        "tap" => json!({"op": "tap", "x": num("x")?, "y": num("y")?, "ms": a["ms"].as_u64().unwrap_or(60)}),
        "swipe" => json!({"op": "swipe", "x": num("x")?, "y": num("y")?, "x2": num("x2")?, "y2": num("y2")?, "ms": a["ms"].as_u64().unwrap_or(300)}),
        "back" | "home" | "recents" | "notifications" | "quick_settings" | "lock_screen" | "power_dialog" => {
            if action == "power_dialog" {
                reasons.push("open the power menu (shut down / restart)".into());
            }
            json!({"op": "global", "action": action})
        }
        other => return Err(format!("unknown action {other}")),
    };
    Ok((req, reasons))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn plans() {
        remember_tree("[1] TextView \"Wi-Fi\"\n  [2] Button \"Delete all\" @(1,2 3x4) click\n");
        let none = |_: &str| vec![];
        let (r, why) = plan(&json!({"action": "click", "ref": 1}), &none).unwrap();
        assert_eq!(r["op"], "click");
        assert!(why.is_empty());
        let (_, why) = plan(&json!({"action": "click", "ref": 2}), &none).unwrap();
        assert_eq!(why.len(), 1);
        let (_, why) = plan(&json!({"action": "power_dialog"}), &none).unwrap();
        assert_eq!(why.len(), 1);
        let (r, _) = plan(&json!({"action": "swipe", "x": 1, "y": 2, "x2": 3, "y2": 4}), &none).unwrap();
        assert_eq!(r["ms"], 300);
        assert!(plan(&json!({"action": "tap", "x": 1}), &none).is_err());
        let flag = |t: &str| if t.contains("reboot") { vec!["power".to_string()] } else { vec![] };
        let (_, why) = plan(&json!({"action": "set_text", "ref": 1, "text": "reboot"}), &flag).unwrap();
        assert_eq!(why, vec!["power (typed)"]);
    }

    #[tokio::test]
    async fn bridge_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sga11y-{}", crate::policy::random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        std::fs::write(dir.join("a11y.json"), json!({"port": port, "secret": "s3"}).to_string()).unwrap();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = c.read(&mut buf).await.unwrap();
            let req: Value = serde_json::from_slice(&buf[..n]).unwrap();
            let out = if req["secret"] == "s3" { json!({"ok": {"echo": req["op"]}}) } else { json!({"err": "unauthorized"}) };
            c.write_all(format!("{out}\n").as_bytes()).await.unwrap();
        });
        let v = call(dir.to_str().unwrap(), json!({"op": "ping"}), Duration::from_secs(5)).await.unwrap();
        assert_eq!(v["echo"], "ping");
        let off = call("/nonexistent", json!({"op": "ping"}), Duration::from_secs(1)).await.unwrap_err();
        assert!(off.contains("screen control is off"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
