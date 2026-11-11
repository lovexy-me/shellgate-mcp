//! Desktop control on Linux (X11 / Wayland) through the usual command-line tools:
//! screenshots with grim (Wayland), import (ImageMagick) or scrot (X11); mouse and keyboard with
//! xdotool (X11) or, for moves / clicks / typing only, ydotool (Wayland); windows with wmctrl.
//! The service needs the session's DISPLAY or WAYLAND_DISPLAY (set them in shellgate.env, e.g.
//! DISPLAY=:0 and XAUTHORITY=/home/<user>/.Xauthority); without them :0 is tried.
//! Coordinates are physical screen pixels (screenshots are not scaled).

#![cfg(all(unix, not(target_os = "android")))]

use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::desktop::{Action, Mapping};
use crate::platform;

fn env_display(c: &mut Command) {
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        c.env("DISPLAY", ":0");
    }
}

fn wayland() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some()
}

fn run(prog: &str, args: &[String]) -> Result<Vec<u8>, String> {
    let mut c = Command::new(prog);
    c.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    env_display(&mut c);
    let o = c.output().map_err(|e| format!("{prog}: {e}"))?;
    if !o.status.success() {
        let e = String::from_utf8_lossy(&o.stderr);
        return Err(format!("{prog} failed: {}", e.trim().chars().take(400).collect::<String>()));
    }
    Ok(o.stdout)
}

fn sv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// PNG of the screen (or a region x,y,w,h). Returns (png bytes, tool used).
pub fn screenshot(region: Option<(i64, i64, i64, i64)>) -> Result<(Vec<u8>, &'static str), String> {
    let mut tried = vec![];
    if wayland() && platform::which("grim").is_some() {
        let mut a = vec![];
        if let Some((x, y, w, h)) = region {
            a.extend(sv(&["-g", &format!("{x},{y} {w}x{h}")]));
        }
        a.push("-".into());
        match run("grim", &a) {
            Ok(b) => return Ok((b, "grim")),
            Err(e) => tried.push(e),
        }
    }
    if platform::which("import").is_some() {
        let mut a = sv(&["-window", "root"]);
        if let Some((x, y, w, h)) = region {
            a.extend(sv(&["-crop", &format!("{w}x{h}+{x}+{y}")]));
        }
        a.push("png:-".into());
        match run("import", &a) {
            Ok(b) => return Ok((b, "import")),
            Err(e) => tried.push(e),
        }
    }
    for (prog, mk) in [("scrot", 0), ("gnome-screenshot", 1)] {
        if platform::which(prog).is_none() {
            continue;
        }
        let tmp = std::env::temp_dir().join(format!("sgshot-{}.png", crate::policy::random_hex(4)));
        let t = tmp.display().to_string();
        let mut a = if mk == 0 { sv(&["-o", &t]) } else { sv(&["-f", &t]) };
        if let (Some((x, y, w, h)), 0) = (region, mk) {
            a = sv(&["-a", &format!("{x},{y},{w},{h}"), "-o", &t]);
        }
        let r = run(prog, &a).and_then(|_| std::fs::read(&tmp).map_err(|e| e.to_string()));
        let _ = std::fs::remove_file(&tmp);
        match r {
            Ok(b) => return Ok((b, if mk == 0 { "scrot" } else { "gnome-screenshot" })),
            Err(e) => tried.push(e),
        }
    }
    if tried.is_empty() {
        return Err("no screenshot tool found: install grim (Wayland), imagemagick or scrot (X11)".into());
    }
    Err(tried.join("; "))
}

/// PNG width and height from the IHDR chunk.
pub fn png_size(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() < 24 || &b[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    Some((u32::from_be_bytes(b[16..20].try_into().ok()?), u32::from_be_bytes(b[20..24].try_into().ok()?)))
}

/// xdotool key name for one part of a combo like "ctrl+shift+esc".
pub fn keysym(k: &str) -> String {
    let l = k.trim().to_lowercase();
    let m = match l.as_str() {
        "ctrl" | "control" => "ctrl", "alt" => "alt", "shift" => "shift",
        "win" | "super" | "meta" | "cmd" => "super",
        "esc" | "escape" => "Escape", "enter" | "return" => "Return", "tab" => "Tab", "space" => "space",
        "backspace" => "BackSpace", "delete" | "del" => "Delete", "insert" | "ins" => "Insert",
        "home" => "Home", "end" => "End", "pageup" | "pgup" => "Prior", "pagedown" | "pgdn" => "Next",
        "up" => "Up", "down" => "Down", "left" => "Left", "right" => "Right",
        "printscreen" | "prtsc" => "Print", "menu" | "apps" => "Menu",
        _ => "",
    };
    if !m.is_empty() {
        return m.to_string();
    }
    if l.len() >= 2 && l.starts_with('f') && l[1..].parse::<u8>().is_ok_and(|n| (1..=24).contains(&n)) {
        return l.to_uppercase();
    }
    k.trim().to_string()
}

pub fn combo(text: &str) -> String {
    text.split('+').map(keysym).collect::<Vec<_>>().join("+")
}

/// The xdotool argument lists for a batch (one invocation per action, waits included as None).
pub fn xdotool_plan(actions: &[Action], map: &Mapping) -> Vec<Option<Vec<String>>> {
    let pt = |x: f64, y: f64| { let (a, b) = map.to_physical(x, y); (a.to_string(), b.to_string()) };
    let btn = |b: u8| match b { 1 => "3", 2 => "2", _ => "1" }.to_string();
    actions.iter().map(|a| match a {
        Action::Move { x, y } => { let (x, y) = pt(*x, *y); Some(vec!["mousemove".into(), x, y]) }
        Action::Click { x, y, button, count } => {
            let mut v = vec![];
            if let (Some(x), Some(y)) = (x, y) {
                let (x, y) = pt(*x, *y);
                v.extend(["mousemove".into(), x, y]);
            }
            v.extend(["click".into(), "--repeat".into(), count.to_string(), btn(*button)]);
            Some(v)
        }
        Action::Drag { x, y, x2, y2 } => {
            let (a, b) = pt(*x, *y);
            let (c, d) = pt(*x2, *y2);
            Some(vec!["mousemove".into(), a, b, "mousedown".into(), "1".into(), "mousemove".into(), c, d, "mouseup".into(), "1".into()])
        }
        Action::Scroll { x, y, delta, horizontal } => {
            let mut v = vec![];
            if let (Some(x), Some(y)) = (x, y) {
                let (x, y) = pt(*x, *y);
                v.extend(["mousemove".into(), x, y]);
            }
            let b = match (horizontal, *delta > 0) { (false, true) => "4", (false, false) => "5", (true, true) => "7", (true, false) => "6" };
            v.extend(["click".into(), "--repeat".into(), delta.unsigned_abs().max(1).to_string(), b.into()]);
            Some(v)
        }
        Action::Key { text, .. } => Some(vec!["key".into(), "--clearmodifiers".into(), combo(text)]),
        Action::Text { text } => Some(vec!["type".into(), "--delay".into(), "8".into(), "--".into(), text.clone()]),
        Action::Wait { .. } => None,
    }).collect()
}

pub fn input(actions: &[Action], map: &Mapping) -> Result<usize, String> {
    let have_x = platform::which("xdotool").is_some() && !(wayland() && std::env::var_os("DISPLAY").is_none());
    if !have_x {
        if platform::which("ydotool").is_some() {
            return input_ydotool(actions, map);
        }
        return Err("no input tool: install xdotool (X11) or ydotool (Wayland, needs ydotoold)".into());
    }
    let plan = xdotool_plan(actions, map);
    for (i, (a, p)) in actions.iter().zip(plan).enumerate() {
        match (a, p) {
            (Action::Wait { ms }, _) => std::thread::sleep(std::time::Duration::from_millis(*ms)),
            (_, Some(args)) => { run("xdotool", &args).map_err(|e| format!("action {i}: {e}"))?; }
            _ => {}
        }
    }
    Ok(actions.len())
}

fn input_ydotool(actions: &[Action], map: &Mapping) -> Result<usize, String> {
    for (i, a) in actions.iter().enumerate() {
        let mv = |x: f64, y: f64| -> Result<(), String> {
            let (x, y) = map.to_physical(x, y);
            run("ydotool", &sv(&["mousemove", "--absolute", "-x", &x.to_string(), "-y", &y.to_string()])).map(|_| ())
        };
        let r = match a {
            Action::Move { x, y } => mv(*x, *y),
            Action::Click { x, y, button, count } => (|| {
                if let (Some(x), Some(y)) = (x, y) { mv(*x, *y)?; }
                let code = match button { 1 => "0xC1", 2 => "0xC2", _ => "0xC0" };
                for _ in 0..*count { run("ydotool", &sv(&["click", code]))?; }
                Ok(())
            })(),
            Action::Text { text } => run("ydotool", &["type".into(), "--".into(), text.clone()]).map(|_| ()),
            Action::Wait { ms } => { std::thread::sleep(std::time::Duration::from_millis(*ms)); Ok(()) }
            _ => Err("with ydotool only move, click, text and wait are supported (install xdotool for keys, drag, scroll)".into()),
        };
        r.map_err(|e| format!("action {i}: {e}"))?;
    }
    Ok(actions.len())
}

/// wmctrl -lpG lines: id desktop pid x y w h host title
pub fn parse_wmctrl(out: &str) -> Vec<Value> {
    out.lines().filter_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 8 {
            return None;
        }
        let title = f[8..].join(" ");
        Some(json!({"handle": f[0], "desktop": f[1].parse::<i64>().unwrap_or(-1), "pid": f[2].parse::<u64>().unwrap_or(0),
                    "rect": [f[3].parse::<i64>().unwrap_or(0), f[4].parse::<i64>().unwrap_or(0), f[5].parse::<i64>().unwrap_or(0), f[6].parse::<i64>().unwrap_or(0)],
                    "title": title}))
    }).collect()
}

pub fn windows() -> Result<Vec<Value>, String> {
    if platform::which("wmctrl").is_none() {
        return Err("install wmctrl to list and manage windows".into());
    }
    Ok(parse_wmctrl(&String::from_utf8_lossy(&run("wmctrl", &sv(&["-lpG"]))?)))
}

pub fn find_window(spec: Option<&str>) -> Result<(String, String), String> {
    let list = windows()?;
    let spec = spec.unwrap_or("").trim();
    if spec.is_empty() {
        let id = String::from_utf8_lossy(&run("xdotool", &sv(&["getactivewindow"]))?).trim().parse::<u64>().map_err(|e| e.to_string())?;
        let hex = format!("0x{id:08x}");
        let t = list.iter().find(|w| u64::from_str_radix(w["handle"].as_str().unwrap_or("").trim_start_matches("0x"), 16).ok() == Some(id))
            .and_then(|w| w["title"].as_str()).unwrap_or("").to_string();
        return Ok((hex, t));
    }
    let l = spec.to_lowercase();
    list.iter().find(|w| w["handle"].as_str() == Some(spec))
        .or_else(|| list.iter().find(|w| w["title"].as_str().unwrap_or("").to_lowercase().contains(&l)))
        .map(|w| (w["handle"].as_str().unwrap_or("").to_string(), w["title"].as_str().unwrap_or("").to_string()))
        .ok_or_else(|| format!("no window matches {spec}"))
}

pub fn window_action(action: &str, id: &str) -> Result<Value, String> {
    let args = match action {
        "activate" => sv(&["-ia", id]),
        "close" => sv(&["-ic", id]),
        "maximize" => sv(&["-ir", id, "-b", "add,maximized_vert,maximized_horz"]),
        "restore" => sv(&["-ir", id, "-b", "remove,maximized_vert,maximized_horz,hidden"]),
        "minimize" => {
            run("xdotool", &sv(&["windowminimize", id]))?;
            return Ok(json!({"status": "ok", "window": id, "action": action}));
        }
        other => return Err(format!("unknown action {other}")),
    };
    run("wmctrl", &args)?;
    Ok(json!({"status": "ok", "window": id, "action": action}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(combo("ctrl+shift+esc"), "ctrl+shift+Escape");
        assert_eq!(combo("Win+L"), "super+L");
        assert_eq!(combo("alt+f4"), "alt+F4");
        assert_eq!(combo("ctrl+c"), "ctrl+c");
    }

    #[test]
    fn plan() {
        let acts = crate::desktop::parse_actions(&json!([
            {"type": "click", "x": 10, "y": 20}, {"type": "right_click"}, {"type": "scroll", "delta": -2},
            {"type": "key", "keys": "ctrl+s"}, {"type": "text", "text": "hi"}, {"type": "wait", "ms": 1}])).unwrap();
        let p = xdotool_plan(&acts, &Mapping { ox: 0, oy: 0, scale: 1.0 });
        assert_eq!(p[0].as_ref().unwrap().join(" "), "mousemove 10 20 click --repeat 1 1");
        assert_eq!(p[1].as_ref().unwrap().join(" "), "click --repeat 1 3");
        assert_eq!(p[2].as_ref().unwrap().join(" "), "click --repeat 2 5");
        assert_eq!(p[3].as_ref().unwrap().join(" "), "key --clearmodifiers ctrl+s");
        assert_eq!(p[4].as_ref().unwrap().join(" "), "type --delay 8 -- hi");
        assert!(p[5].is_none());
    }

    #[test]
    fn wmctrl() {
        let w = parse_wmctrl("0x03a00003  0 2481   0    0    1920 1080 box Terminal - bash\n");
        assert_eq!(w[0]["title"], "Terminal - bash");
        assert_eq!(w[0]["pid"], 2481);
    }

    #[test]
    fn png() {
        let mut b = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        b.extend(1920u32.to_be_bytes());
        b.extend(1080u32.to_be_bytes());
        assert_eq!(png_size(&b), Some((1920, 1080)));
    }
}
