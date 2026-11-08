//! Desktop control (screenshots, UI Automation tree, mouse/keyboard, windows) for Windows.
//!
//! Off by default: only `desktop=on` in the config enables the tools. This file holds the
//! platform-neutral parts (image scaling and encoding, Set-of-Marks drawing, coordinate mapping,
//! key-combo parsing, safety checks) so they are unit-tested on every platform; the Win32 calls
//! live in `desktop_win.rs`.
//!
//! Written from scratch for ShellGate (MIT). Ideas, not code, follow public descriptions of
//! winmcp, microsoft/Hybrid-Computer-Use, OpenControl and mcp-windows: control tree first with
//! short reference numbers, screenshot + coordinates as the fallback, one call for a batch.

#![allow(dead_code)]

use serde_json::{json, Value};

/// A captured frame: tightly packed BGRA rows, top-down.
#[derive(Clone)]
pub struct Frame {
    pub w: usize,
    pub h: usize,
    pub bgra: Vec<u8>,
}

/// Maps screenshot pixels back to physical screen pixels.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mapping {
    /// Physical position of the captured area's top-left corner (virtual-screen coordinates).
    pub ox: i32,
    pub oy: i32,
    /// physical pixels per screenshot pixel (>= 1.0 when the shot was scaled down)
    pub scale: f64,
}

impl Mapping {
    pub fn to_physical(&self, x: f64, y: f64) -> (i32, i32) {
        (self.ox + (x * self.scale).round() as i32, self.oy + (y * self.scale).round() as i32)
    }
    pub fn to_shot(&self, px: i32, py: i32) -> (i32, i32) {
        (((px - self.ox) as f64 / self.scale).round() as i32, ((py - self.oy) as f64 / self.scale).round() as i32)
    }
}

/// Output size for a frame of w x h limited to max_w (aspect kept, never upscaled).
pub fn fit(w: usize, h: usize, max_w: usize) -> (usize, usize, f64) {
    if max_w == 0 || w <= max_w {
        return (w, h, 1.0);
    }
    let scale = w as f64 / max_w as f64;
    let nh = ((h as f64 / scale).round() as usize).max(1);
    (max_w, nh, scale)
}

/// Area-average downscale (box filter); good for UI text at the 1.5x-3x factors we see.
pub fn downscale(f: &Frame, nw: usize, nh: usize) -> Frame {
    if nw == f.w && nh == f.h {
        return f.clone();
    }
    let mut out = vec![0u8; nw * nh * 4];
    let sx = f.w as f64 / nw as f64;
    let sy = f.h as f64 / nh as f64;
    for y in 0..nh {
        let y0 = (y as f64 * sy) as usize;
        let y1 = (((y + 1) as f64 * sy).ceil() as usize).min(f.h).max(y0 + 1);
        for x in 0..nw {
            let x0 = (x as f64 * sx) as usize;
            let x1 = (((x + 1) as f64 * sx).ceil() as usize).min(f.w).max(x0 + 1);
            let mut acc = [0u32; 4];
            let mut n = 0u32;
            for yy in y0..y1 {
                let row = yy * f.w * 4;
                for xx in x0..x1 {
                    let i = row + xx * 4;
                    for c in 0..4 {
                        acc[c] += f.bgra[i + c] as u32;
                    }
                    n += 1;
                }
            }
            let o = (y * nw + x) * 4;
            for c in 0..4 {
                out[o + c] = (acc[c] / n.max(1)) as u8;
            }
        }
    }
    Frame { w: nw, h: nh, bgra: out }
}

/// Cheap content hash used to skip re-sending an unchanged screen.
pub fn frame_hash(f: &Frame) -> u64 {
    // FNV-1a over every 7th byte plus size; enough to notice any visible change
    let mut h: u64 = 0xcbf29ce484222325;
    for v in [f.w as u64, f.h as u64] {
        h ^= v;
        h = h.wrapping_mul(0x100000001b3);
    }
    let mut i = 0;
    while i < f.bgra.len() {
        h ^= f.bgra[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 7;
    }
    h
}

// ---------------------------------------------------------------- encoders

fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (n, e) in t.iter_mut().enumerate() {
            let mut c = n as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    let mut c = 0xffffffffu32;
    for &b in data {
        c = t[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffffffff
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// RGB PNG (filter "up" per row: cheap and compresses UI screenshots well).
pub fn encode_png(f: &Frame) -> Vec<u8> {
    let stride = f.w * 3;
    let mut raw = Vec::with_capacity((stride + 1) * f.h);
    let mut prev = vec![0u8; stride];
    let mut cur = vec![0u8; stride];
    for y in 0..f.h {
        let row = &f.bgra[y * f.w * 4..(y + 1) * f.w * 4];
        for x in 0..f.w {
            cur[x * 3] = row[x * 4 + 2];
            cur[x * 3 + 1] = row[x * 4 + 1];
            cur[x * 3 + 2] = row[x * 4];
        }
        raw.push(2u8);
        raw.extend(cur.iter().zip(prev.iter()).map(|(c, p)| c.wrapping_sub(*p)));
        std::mem::swap(&mut prev, &mut cur);
    }
    let z = miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6);
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(f.w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(f.h as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    png_chunk(&mut out, b"IHDR", &ihdr);
    png_chunk(&mut out, b"IDAT", &z);
    png_chunk(&mut out, b"IEND", &[]);
    out
}

pub fn encode_jpeg(f: &Frame, quality: u8) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let enc = jpeg_encoder::Encoder::new(&mut out, quality.clamp(20, 95));
    enc.encode(&f.bgra, f.w as u16, f.h as u16, jpeg_encoder::ColorType::Bgra)
        .map_err(|e| format!("jpeg: {e}"))?;
    Ok(out)
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

// ---------------------------------------------------------------- Set-of-Marks

const DIGITS: [[u8; 5]; 10] = [
    [0b111, 0b101, 0b101, 0b101, 0b111],
    [0b010, 0b110, 0b010, 0b010, 0b111],
    [0b111, 0b001, 0b111, 0b100, 0b111],
    [0b111, 0b001, 0b111, 0b001, 0b111],
    [0b101, 0b101, 0b111, 0b001, 0b001],
    [0b111, 0b100, 0b111, 0b001, 0b111],
    [0b111, 0b100, 0b111, 0b101, 0b111],
    [0b111, 0b001, 0b010, 0b010, 0b010],
    [0b111, 0b101, 0b111, 0b101, 0b111],
    [0b111, 0b101, 0b111, 0b001, 0b111],
];

fn put(f: &mut Frame, x: i64, y: i64, bgr: [u8; 3]) {
    if x < 0 || y < 0 || x as usize >= f.w || y as usize >= f.h {
        return;
    }
    let i = (y as usize * f.w + x as usize) * 4;
    f.bgra[i] = bgr[0];
    f.bgra[i + 1] = bgr[1];
    f.bgra[i + 2] = bgr[2];
}

/// Draw a box (in frame pixels) with its number in a filled tag at the top-left corner.
pub fn draw_mark(f: &mut Frame, x: i64, y: i64, w: i64, h: i64, n: usize) {
    const RED: [u8; 3] = [0x20, 0x20, 0xe0];
    const WHITE: [u8; 3] = [0xff, 0xff, 0xff];
    for t in 0..2 {
        for xx in x..x + w {
            put(f, xx, y + t, RED);
            put(f, xx, y + h - 1 - t, RED);
        }
        for yy in y..y + h {
            put(f, x + t, yy, RED);
            put(f, x + w - 1 - t, yy, RED);
        }
    }
    let digits: Vec<usize> = n.to_string().bytes().map(|b| (b - b'0') as usize).collect();
    let s = 2i64; // font scale
    let tw = digits.len() as i64 * 4 * s + s;
    let th = 5 * s + 2 * s;
    for yy in y..y + th {
        for xx in x..x + tw {
            put(f, xx, yy, RED);
        }
    }
    for (k, d) in digits.iter().enumerate() {
        for (r, bits) in DIGITS[*d].iter().enumerate() {
            for c in 0..3 {
                if bits & (0b100 >> c) != 0 {
                    for dy in 0..s {
                        for dx in 0..s {
                            put(f, x + s + k as i64 * 4 * s + c * s + dx, y + s + r as i64 * s + dy, WHITE);
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- keys

/// Virtual-key code for one key name ("ctrl", "a", "f4", "enter", ...).
pub fn vk(name: &str) -> Option<u16> {
    let n = name.trim().to_lowercase();
    let v = match n.as_str() {
        "ctrl" | "control" | "lctrl" => 0x11,
        "shift" | "lshift" => 0x10,
        "alt" | "menu" | "lalt" => 0x12,
        "win" | "super" | "meta" | "lwin" | "cmd" => 0x5B,
        "enter" | "return" => 0x0D,
        "esc" | "escape" => 0x1B,
        "tab" => 0x09,
        "space" => 0x20,
        "backspace" | "bksp" => 0x08,
        "delete" | "del" => 0x2E,
        "insert" | "ins" => 0x2D,
        "home" => 0x24,
        "end" => 0x23,
        "pageup" | "pgup" => 0x21,
        "pagedown" | "pgdn" => 0x22,
        "left" => 0x25,
        "up" => 0x26,
        "right" => 0x27,
        "down" => 0x28,
        "printscreen" | "prtsc" => 0x2C,
        "apps" | "contextmenu" => 0x5D,
        "capslock" => 0x14,
        "numlock" => 0x90,
        _ => {
            if let Some(num) = n.strip_prefix('f').and_then(|d| d.parse::<u16>().ok()) {
                if (1..=24).contains(&num) {
                    return Some(0x70 + num - 1);
                }
                return None;
            }
            let b = n.as_bytes();
            if b.len() == 1 && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
                return Some(b[0].to_ascii_uppercase() as u16);
            }
            return match n.as_str() {
                "-" | "minus" => Some(0xBD),
                "=" | "plus" | "equal" => Some(0xBB),
                "," | "comma" => Some(0xBC),
                "." | "period" => Some(0xBE),
                "/" | "slash" => Some(0xBF),
                ";" => Some(0xBA),
                "'" => Some(0xDE),
                "[" => Some(0xDB),
                "]" => Some(0xDD),
                "\\" => Some(0xDC),
                "`" => Some(0xC0),
                _ => None,
            };
        }
    };
    Some(v)
}

/// "ctrl+shift+esc" -> [0x11, 0x10, 0x1B]
pub fn parse_combo(s: &str) -> Result<Vec<u16>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty key combo".into());
    }
    // allow "ctrl++" for the plus key
    let parts: Vec<&str> = if s.ends_with("++") {
        let mut p: Vec<&str> = s[..s.len() - 2].split('+').collect();
        p.push("plus");
        p
    } else {
        s.split('+').collect()
    };
    parts.iter().map(|p| vk(p).ok_or_else(|| format!("unknown key: {p}"))).collect()
}

/// Key combos that close or lock things, log off, or open a run box. They are confirmed first.
pub fn risky_combo(keys: &[u16]) -> Option<&'static str> {
    let has = |k: u16| keys.contains(&k);
    if has(0x12) && has(0x73) {
        return Some("Alt+F4 closes the active window (on the desktop it opens shut down)");
    }
    if has(0x11) && has(0x12) && has(0x2E) {
        return Some("Ctrl+Alt+Del");
    }
    if has(0x5B) && has(b'L' as u16) {
        return Some("Win+L locks the session");
    }
    if has(0x5B) && has(b'X' as u16) {
        return Some("Win+X opens the power-user menu (shut down, disk management)");
    }
    None
}

/// Win+R (run box) typed text becomes a command: check it like run_command.
pub fn opens_run_box(keys: &[u16]) -> bool {
    keys.contains(&0x5B) && keys.contains(&(b'R' as u16))
}

/// One action of a desktop_input batch, validated.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Move { x: f64, y: f64 },
    Click { x: Option<f64>, y: Option<f64>, button: u8, count: u8 },
    Drag { x: f64, y: f64, x2: f64, y2: f64 },
    Scroll { x: Option<f64>, y: Option<f64>, delta: i32, horizontal: bool },
    Key { keys: Vec<u16>, text: String },
    Text { text: String },
    Wait { ms: u64 },
}

fn num(a: &Value, k: &str) -> Option<f64> {
    a.get(k).and_then(Value::as_f64)
}

pub fn parse_actions(list: &Value) -> Result<Vec<Action>, String> {
    let arr = list.as_array().ok_or("actions must be an array")?;
    if arr.is_empty() || arr.len() > 50 {
        return Err("actions: 1 to 50 items".into());
    }
    let mut out = vec![];
    for (i, a) in arr.iter().enumerate() {
        let t = a.get("type").and_then(Value::as_str).unwrap_or("");
        let need = |k: &str| num(a, k).ok_or_else(|| format!("action {i} ({t}): {k} is required"));
        let button = match a.get("button").and_then(Value::as_str).unwrap_or("left") {
            "left" => 0,
            "right" => 1,
            "middle" => 2,
            b => return Err(format!("action {i}: unknown button {b}")),
        };
        out.push(match t {
            "move" => Action::Move { x: need("x")?, y: need("y")? },
            "click" | "double_click" | "right_click" => Action::Click {
                x: num(a, "x"),
                y: num(a, "y"),
                button: if t == "right_click" { 1 } else { button },
                count: if t == "double_click" { 2 } else { a.get("count").and_then(Value::as_u64).unwrap_or(1).clamp(1, 3) as u8 },
            },
            "drag" => Action::Drag { x: need("x")?, y: need("y")?, x2: need("x2")?, y2: need("y2")? },
            "scroll" => Action::Scroll {
                x: num(a, "x"),
                y: num(a, "y"),
                delta: a.get("delta").and_then(Value::as_i64).unwrap_or(-3).clamp(-50, 50) as i32,
                horizontal: a.get("horizontal").and_then(Value::as_bool).unwrap_or(false),
            },
            "key" => {
                let k = a.get("keys").and_then(Value::as_str).ok_or_else(|| format!("action {i}: keys is required"))?;
                Action::Key { keys: parse_combo(k)?, text: k.to_string() }
            }
            "text" | "type" => {
                let s = a.get("text").and_then(Value::as_str).ok_or_else(|| format!("action {i}: text is required"))?;
                if s.chars().count() > 5000 {
                    return Err(format!("action {i}: text longer than 5000 characters"));
                }
                Action::Text { text: s.to_string() }
            }
            "wait" => Action::Wait { ms: a.get("ms").and_then(Value::as_u64).unwrap_or(300).min(10_000) },
            other => return Err(format!("action {i}: unknown type '{other}' (move, click, double_click, right_click, drag, scroll, key, text, wait)")),
        });
    }
    Ok(out)
}

/// Reasons a batch needs the user's OK: risky combos, and text typed into a run box / console
/// that the command policy flags. `danger` is the command-policy check (text -> reasons).
pub fn batch_reasons(actions: &[Action], foreground_is_console: bool, danger: &dyn Fn(&str) -> Vec<String>) -> Vec<String> {
    let mut reasons = vec![];
    let mut run_box = foreground_is_console;
    for a in actions {
        match a {
            Action::Key { keys, text } => {
                if let Some(r) = risky_combo(keys) {
                    reasons.push(format!("{r} ({text})"));
                }
                if opens_run_box(keys) {
                    run_box = true;
                }
            }
            Action::Text { text } => {
                // Typed text is checked always; it is what a run box or console would execute.
                for r in danger(text) {
                    reasons.push(format!("{r} (typed{})", if run_box { " into a run box/console" } else { "" }));
                }
            }
            _ => {}
        }
    }
    let mut uniq = vec![];
    for r in reasons {
        if !uniq.contains(&r) {
            uniq.push(r);
        }
    }
    uniq
}

/// Compact control-tree line: `[12] Button "OK" @(x,y w×h)` plus flags.
pub fn tree_line(depth: usize, r: usize, ctype: &str, name: &str, aid: &str, rect: (i32, i32, i32, i32), enabled: bool, value: Option<&str>) -> String {
    let mut s = format!("{}[{r}] {ctype}", "  ".repeat(depth));
    let name: String = name.chars().filter(|c| !c.is_control()).take(80).collect();
    if !name.is_empty() {
        s.push_str(&format!(" \"{name}\""));
    }
    if !aid.is_empty() && aid.len() <= 40 {
        s.push_str(&format!(" #{aid}"));
    }
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        let v: String = v.chars().filter(|c| !c.is_control()).take(60).collect();
        s.push_str(&format!(" ={v:?}"));
    }
    s.push_str(&format!(" @({},{} {}x{})", rect.0, rect.1, rect.2, rect.3));
    if !enabled {
        s.push_str(" disabled");
    }
    s
}

pub fn control_type_name(id: i32) -> &'static str {
    match id {
        50000 => "Button",
        50001 => "Calendar",
        50002 => "CheckBox",
        50003 => "ComboBox",
        50004 => "Edit",
        50005 => "Hyperlink",
        50006 => "Image",
        50007 => "ListItem",
        50008 => "List",
        50009 => "Menu",
        50010 => "MenuBar",
        50011 => "MenuItem",
        50012 => "ProgressBar",
        50013 => "RadioButton",
        50014 => "ScrollBar",
        50015 => "Slider",
        50016 => "Spinner",
        50017 => "StatusBar",
        50018 => "Tab",
        50019 => "TabItem",
        50020 => "Text",
        50021 => "ToolBar",
        50022 => "ToolTip",
        50023 => "Tree",
        50024 => "TreeItem",
        50025 => "Custom",
        50026 => "Group",
        50027 => "Thumb",
        50028 => "DataGrid",
        50029 => "DataItem",
        50030 => "Document",
        50031 => "SplitButton",
        50032 => "Window",
        50033 => "Pane",
        50034 => "Header",
        50035 => "HeaderItem",
        50036 => "Table",
        50037 => "TitleBar",
        50038 => "Separator",
        50039 => "SemanticZoom",
        50040 => "AppBar",
        _ => "Element",
    }
}

/// Tool definitions; listed only when desktop=on (and only on Windows).
pub fn definitions() -> Vec<Value> {
    let s = |d: &str| json!({"type": "string", "description": d});
    let i = |d: &str| json!({"type": "integer", "description": d});
    let b = |d: &str| json!({"type": "boolean", "description": d});
    let obj = |p: Value, r: &[&str]| json!({"type": "object", "properties": p, "required": r});
    let confirm = s("One-time code from a previous confirmation_required answer, only after the user agreed");
    let win = s("Window: handle from desktop_windows (e.g. \"0x1234\") or part of its title; default the foreground window");
    vec![
        json!({"name": "desktop_tree", "description": "UI Automation control tree of a window (preferred over screenshots): one line per control `[ref] Type \"Name\" #AutomationId =value @(x,y wxh)` in physical pixels. Use the ref numbers with desktop_element. If UI Automation is unavailable (e.g. plain WinPE without UIAutomationCore) the answer says uia=false: use desktop_screenshot + desktop_input with coordinates instead.",
               "inputSchema": obj(json!({"window": win.clone(), "depth": i("Max depth, default 12"), "max_nodes": i("Max controls, default 300"), "all": b("Whole desktop instead of one window")}), &[])}),
        json!({"name": "desktop_element", "description": "Act on a control by its ref from the last desktop_tree: click (Invoke pattern, else a mouse click on its centre), set_value (Value pattern, else focus + type), value (read), focus, toggle, expand, collapse, select. Clicks on Close/Shut down style controls and typed text the command policy flags need confirm_code.",
               "inputSchema": obj(json!({"ref": i("Ref number from desktop_tree"), "action": {"type": "string", "enum": ["click", "double_click", "right_click", "set_value", "value", "focus", "toggle", "expand", "collapse", "select"]},
                                         "text": s("Text for set_value"), "confirm_code": confirm.clone()}), &["ref", "action"])}),
        json!({"name": "desktop_screenshot", "description": "Screenshot of the screen, a window or a region, scaled to max_width (default 1280) and returned as an MCP image. Coordinates you read off the image are what desktop_input expects by default (it maps them back to physical pixels, DPI-aware). With only_if_changed (default true) an unchanged screen returns changed=false and no image. marks=true draws numbered boxes around UI Automation controls (Set-of-Marks) when available.",
               "inputSchema": obj(json!({"window": win.clone(), "region": {"type": "array", "items": {"type": "integer"}, "description": "[x, y, width, height] in physical screen pixels"},
                                         "max_width": i("Default 1280; 0 = full size"), "format": {"type": "string", "enum": ["png", "jpeg"], "default": "png"}, "quality": i("JPEG quality 20-95, default 70"),
                                         "marks": b("Draw numbered control boxes (Set-of-Marks)"), "only_if_changed": b("Default true")}), &[])}),
        json!({"name": "desktop_input", "description": "Mouse and keyboard as one batch (SendInput). actions: [{type: move|click|double_click|right_click|drag|scroll|key|text|wait, x, y, x2, y2, button: left|right|middle, delta (wheel notches, negative = down), horizontal, keys: \"ctrl+shift+esc\", text: \"any Unicode incl. 中文\", ms}]. x/y are screenshot pixels of the last desktop_screenshot unless coords=physical. Risky combos (Alt+F4, Win+L, Win+X, Ctrl+Alt+Del) and typed text the command policy flags need confirm_code.",
               "inputSchema": obj(json!({"actions": {"type": "array", "items": {"type": "object"}}, "coords": {"type": "string", "enum": ["shot", "physical"], "default": "shot"}, "confirm_code": confirm.clone()}), &["actions"])}),
        json!({"name": "desktop_windows", "description": "List top-level windows (handle, title, class, process id, rect, state) or act on one: activate, maximize, minimize, restore, close (close needs confirm_code).",
               "inputSchema": obj(json!({"action": {"type": "string", "enum": ["list", "activate", "maximize", "minimize", "restore", "close"], "default": "list"}, "window": win, "confirm_code": confirm}), &[])}),
    ]
}

pub const TOOL_NAMES: &[&str] = &["desktop_tree", "desktop_element", "desktop_screenshot", "desktop_input", "desktop_windows"];

/// Names/classes whose "click" closes or shuts things down.
pub fn risky_control(name: &str) -> bool {
    let l = name.to_lowercase();
    ["shut down", "shutdown", "restart", "reboot", "sign out", "log off", "关机", "重启", "注销", "重新启动", "format", "格式化", "delete", "删除", "erase", "清除"]
        .iter()
        .any(|w| l.contains(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: usize, h: usize, v: u8) -> Frame {
        Frame { w, h, bgra: vec![v; w * h * 4] }
    }

    #[test]
    fn fit_and_mapping() {
        assert_eq!(fit(1920, 1080, 1280), (1280, 720, 1.5));
        assert_eq!(fit(1024, 768, 1280), (1024, 768, 1.0));
        assert_eq!(fit(2560, 1600, 0), (2560, 1600, 1.0));
        let m = Mapping { ox: -1920, oy: 0, scale: 1.5 };
        assert_eq!(m.to_physical(100.0, 200.0), (-1770, 300));
        assert_eq!(m.to_shot(-1770, 300), (100, 200));
    }

    #[test]
    fn downscale_averages() {
        let mut f = solid(4, 2, 0);
        for i in 0..4 {
            f.bgra[i * 4] = 200; // first row, blue channel
        }
        let d = downscale(&f, 2, 1);
        assert_eq!((d.w, d.h), (2, 1));
        assert_eq!(d.bgra[0], 100);
    }

    #[test]
    fn png_is_valid() {
        let mut f = solid(3, 2, 10);
        f.bgra[2] = 255;
        let p = encode_png(&f);
        assert_eq!(&p[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&p[12..16], b"IHDR");
        assert_eq!(u32::from_be_bytes(p[16..20].try_into().unwrap()), 3);
        // IHDR crc
        assert_eq!(crc32(b"IEND"), 0xae426082);
        // decompress IDAT back
        let idat_len = u32::from_be_bytes(p[33..37].try_into().unwrap()) as usize;
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&p[41..41 + idat_len]).unwrap();
        assert_eq!(raw.len(), (3 * 3 + 1) * 2);
        assert_eq!(&raw[..4], &[2, 255, 10, 10]); // filter up, first pixel R=255 G=10 B=10
    }

    #[test]
    fn jpeg_and_b64() {
        let j = encode_jpeg(&solid(16, 16, 128), 70).unwrap();
        assert_eq!(&j[..2], &[0xff, 0xd8]);
        assert_eq!(b64(b"Man"), "TWFu");
        assert_eq!(b64(b"Ma"), "TWE=");
        assert_eq!(b64(b"M"), "TQ==");
        assert_eq!(b64("中".as_bytes()), "5Lit");
    }

    #[test]
    fn hash_changes() {
        let a = solid(8, 8, 1);
        let mut b = a.clone();
        assert_eq!(frame_hash(&a), frame_hash(&b));
        b.bgra[0] = 9;
        assert_ne!(frame_hash(&a), frame_hash(&b));
    }

    #[test]
    fn marks_draw_inside() {
        let mut f = solid(40, 30, 0);
        draw_mark(&mut f, 2, 2, 30, 20, 7);
        assert_eq!(&f.bgra[(2 * 40 + 2) * 4..(2 * 40 + 2) * 4 + 3], &[0x20, 0x20, 0xe0]);
        draw_mark(&mut f, 35, 25, 30, 30, 123); // clipped, must not panic
    }

    #[test]
    fn combos() {
        assert_eq!(parse_combo("ctrl+shift+esc").unwrap(), vec![0x11, 0x10, 0x1B]);
        assert_eq!(parse_combo("Alt+F4").unwrap(), vec![0x12, 0x73]);
        assert_eq!(parse_combo("ctrl++").unwrap(), vec![0x11, 0xBB]);
        assert_eq!(parse_combo("win+r").unwrap(), vec![0x5B, 0x52]);
        assert!(parse_combo("ctrl+nosuchkey").is_err());
        assert!(risky_combo(&parse_combo("alt+f4").unwrap()).is_some());
        assert!(risky_combo(&parse_combo("ctrl+s").unwrap()).is_none());
        assert!(opens_run_box(&parse_combo("win+r").unwrap()));
    }

    #[test]
    fn actions_parse_and_reasons() {
        let a = parse_actions(&json!([{"type": "click", "x": 10, "y": 20}, {"type": "key", "keys": "win+r"},
                                      {"type": "text", "text": "format c: /q"}, {"type": "wait", "ms": 99999}])).unwrap();
        assert_eq!(a[0], Action::Click { x: Some(10.0), y: Some(20.0), button: 0, count: 1 });
        assert_eq!(a[3], Action::Wait { ms: 10_000 });
        let danger = |t: &str| if t.contains("format") { vec!["format".to_string()] } else { vec![] };
        let r = batch_reasons(&a, false, &danger);
        assert_eq!(r, vec!["format (typed into a run box/console)"]);
        let r = batch_reasons(&parse_actions(&json!([{"type": "key", "keys": "alt+f4"}])).unwrap(), false, &danger);
        assert_eq!(r.len(), 1);
        assert!(parse_actions(&json!([{"type": "fly"}])).is_err());
        assert!(parse_actions(&json!([{"type": "move", "x": 1}])).is_err());
        assert!(parse_actions(&json!([])).is_err());
    }

    #[test]
    fn tree_lines() {
        let l = tree_line(1, 3, "Button", "确定", "1", (10, 20, 80, 24), true, None);
        assert_eq!(l, "  [3] Button \"确定\" #1 @(10,20 80x24)");
        assert!(risky_control("关机"));
        assert!(!risky_control("确定"));
        assert_eq!(control_type_name(50000), "Button");
        assert_eq!(definitions().len(), TOOL_NAMES.len());
    }
}
