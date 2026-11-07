//! Win32 side of the desktop tools: GDI capture, SendInput, window management, display modes,
//! and UI Automation on one dedicated COM (MTA) thread that owns every UIA object.
//! The control tree falls back to a plain HWND child-window walk (works in WinPE, where
//! UIAutomationCore is usually missing), and that falls back to screenshot + coordinates.

use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::desktop::{self, Action, Frame};

// ---------------------------------------------------------------- helpers

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn hwnd_str(h: HWND) -> String {
    format!("0x{:x}", h as usize)
}

fn text_of(h: HWND) -> String {
    let mut buf = [0u16; 512];
    let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

fn class_of(h: HWND) -> String {
    let mut buf = [0u16; 256];
    let n = unsafe { GetClassNameW(h, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

fn rect_of(h: HWND) -> RECT {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetWindowRect(h, &mut r) };
    r
}

/// Per-monitor DPI awareness so every coordinate is a physical pixel. Called once.
pub fn dpi_aware() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| unsafe {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        let m = LoadLibraryW(wide("user32.dll").as_ptr());
        if !m.is_null() {
            if let Some(f) = GetProcAddress(m, b"SetProcessDpiAwarenessContext\0".as_ptr()) {
                let f: unsafe extern "system" fn(isize) -> BOOL = std::mem::transmute(f);
                if f(-4) != 0 {
                    return; // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
                }
            }
        }
        SetProcessDPIAware();
    });
}

pub fn virtual_screen() -> (i32, i32, i32, i32) {
    unsafe {
        let (x, y, w, h) = (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
                            GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
        if w > 0 && h > 0 { (x, y, w, h) } else { (0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) }
    }
}

/// Resolve "0x1234" or a title fragment to a top-level window; None = foreground.
pub fn find_window(spec: Option<&str>) -> Result<HWND, String> {
    let Some(spec) = spec.map(str::trim).filter(|s| !s.is_empty()) else {
        let h = unsafe { GetForegroundWindow() };
        return if h.is_null() { Err("no foreground window".into()) } else { Ok(h) };
    };
    if let Some(hex) = spec.strip_prefix("0x") {
        let v = usize::from_str_radix(hex, 16).map_err(|_| format!("bad window handle {spec}"))?;
        let h = v as HWND;
        if unsafe { IsWindow(h) } == 0 {
            return Err(format!("window {spec} no longer exists"));
        }
        return Ok(h);
    }
    let needle = spec.to_lowercase();
    list_windows().into_iter().find(|(_, t, _)| t.to_lowercase().contains(&needle)).map(|(h, _, _)| h)
        .ok_or_else(|| format!("no visible window whose title contains '{spec}'"))
}

fn list_windows() -> Vec<(HWND, String, String)> {
    unsafe extern "system" fn cb(h: HWND, l: LPARAM) -> BOOL {
        let v = &mut *(l as *mut Vec<(HWND, String, String)>);
        if IsWindowVisible(h) != 0 && GetWindowTextLengthW(h) > 0 {
            v.push((h, text_of(h), class_of(h)));
        }
        1
    }
    let mut v: Vec<(HWND, String, String)> = vec![];
    unsafe { EnumWindows(Some(cb), &mut v as *mut _ as LPARAM) };
    v
}

pub fn windows_json() -> Value {
    let fg = unsafe { GetForegroundWindow() };
    let list: Vec<Value> = list_windows().into_iter().map(|(h, t, c)| {
        let r = rect_of(h);
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(h, &mut pid) };
        let state = unsafe { if IsIconic(h) != 0 { "minimized" } else if IsZoomed(h) != 0 { "maximized" } else { "normal" } };
        json!({"window": hwnd_str(h), "title": t, "class": c, "pid": pid, "state": state, "foreground": h == fg,
               "rect": [r.left, r.top, r.right - r.left, r.bottom - r.top]})
    }).collect();
    json!({"windows": list})
}

pub fn foreground_is_console() -> bool {
    let h = unsafe { GetForegroundWindow() };
    !h.is_null() && matches!(class_of(h).as_str(), "ConsoleWindowClass" | "CASCADIA_HOSTING_WINDOW_CLASS" | "#32770")
        && (class_of(h) != "#32770" || text_of(h).contains("Run") || text_of(h).contains("运行"))
}

pub fn window_title(h: HWND) -> String {
    text_of(h)
}

pub fn window_action(action: &str, h: HWND) -> Result<Value, String> {
    unsafe {
        match action {
            "activate" => {
                if IsIconic(h) != 0 {
                    ShowWindow(h, SW_RESTORE);
                }
                // Alt tap lets SetForegroundWindow succeed from a background process
                send_keys_raw(&[(VK_MENU, false), (VK_MENU, true)]);
                BringWindowToTop(h);
                SetForegroundWindow(h);
            }
            "maximize" => { ShowWindow(h, SW_MAXIMIZE); }
            "minimize" => { ShowWindow(h, SW_MINIMIZE); }
            "restore" => { ShowWindow(h, SW_RESTORE); }
            "close" => { PostMessageW(h, WM_CLOSE, 0, 0); }
            other => return Err(format!("unknown window action {other}")),
        }
    }
    std::thread::sleep(Duration::from_millis(150));
    Ok(json!({"window": hwnd_str(h), "action": action, "title": text_of(h), "foreground": unsafe { GetForegroundWindow() } == h}))
}

// ---------------------------------------------------------------- capture

/// Capture a rectangle of the virtual screen (physical pixels).
pub fn capture(x: i32, y: i32, w: i32, h: i32) -> Result<Frame, String> {
    if w <= 0 || h <= 0 || w > 16384 || h > 16384 {
        return Err(format!("bad capture size {w}x{h}"));
    }
    unsafe {
        let screen = GetDC(std::ptr::null_mut());
        if screen.is_null() {
            return Err("GetDC failed (no interactive desktop in this session?)".into());
        }
        let mem = CreateCompatibleDC(screen);
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h; // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let bmp = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        if bmp.is_null() || bits.is_null() {
            DeleteDC(mem);
            ReleaseDC(std::ptr::null_mut(), screen);
            return Err("CreateDIBSection failed".into());
        }
        let old = SelectObject(mem, bmp);
        let ok = BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY | CAPTUREBLT);
        let len = (w * h * 4) as usize;
        let mut data = std::slice::from_raw_parts(bits as *const u8, len).to_vec();
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        ReleaseDC(std::ptr::null_mut(), screen);
        if ok == 0 {
            return Err("BitBlt failed (locked or secure desktop?)".into());
        }
        for px in data.chunks_mut(4) {
            px[3] = 255;
        }
        Ok(Frame { w: w as usize, h: h as usize, bgra: data })
    }
}

pub fn window_rect(h: HWND) -> (i32, i32, i32, i32) {
    let r = rect_of(h);
    (r.left, r.top, r.right - r.left, r.bottom - r.top)
}

// ---------------------------------------------------------------- input

fn key_input(vk: u16, scan: u16, flags: u32) -> INPUT {
    INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
}

fn mouse_input(flags: u32, data: u32) -> INPUT {
    INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: MOUSEINPUT { dx: 0, dy: 0, mouseData: data, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
}

fn send(inputs: &[INPUT]) -> Result<(), String> {
    if inputs.is_empty() {
        return Ok(());
    }
    let n = unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) };
    if n as usize != inputs.len() {
        return Err(format!("SendInput injected {n} of {} events (blocked by UIPI or a secure desktop?)", inputs.len()));
    }
    Ok(())
}

fn extended(vk: u16) -> bool {
    matches!(vk, 0x21..=0x28 | 0x2D | 0x2E | 0x5B | 0x5C | 0x5D | 0x6F | 0x90)
}

fn send_keys_raw(seq: &[(u16, bool)]) {
    let v: Vec<INPUT> = seq.iter().map(|(k, up)| {
        let mut f = if *up { KEYEVENTF_KEYUP } else { 0 };
        if extended(*k) {
            f |= KEYEVENTF_EXTENDEDKEY;
        }
        key_input(*k, 0, f)
    }).collect();
    let _ = send(&v);
}

pub fn press_combo(keys: &[u16]) -> Result<(), String> {
    let mut seq: Vec<(u16, bool)> = keys.iter().map(|k| (*k, false)).collect();
    seq.extend(keys.iter().rev().map(|k| (*k, true)));
    let v: Vec<INPUT> = seq.iter().map(|(k, up)| {
        let mut f = if *up { KEYEVENTF_KEYUP } else { 0 };
        if extended(*k) {
            f |= KEYEVENTF_EXTENDEDKEY;
        }
        key_input(*k, 0, f)
    }).collect();
    send(&v)
}

/// Any Unicode (Chinese included) as KEYEVENTF_UNICODE packets; \n becomes Enter.
pub fn type_text(text: &str) -> Result<(), String> {
    for chunk in text.split_inclusive('\n') {
        let (body, nl) = match chunk.strip_suffix('\n') { Some(b) => (b.trim_end_matches('\r'), true), None => (chunk, false) };
        let mut v = vec![];
        for u in body.encode_utf16() {
            v.push(key_input(0, u, KEYEVENTF_UNICODE));
            v.push(key_input(0, u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
        }
        for part in v.chunks(200) {
            send(part)?;
            std::thread::sleep(Duration::from_millis(5));
        }
        if nl {
            press_combo(&[0x0D])?;
        }
    }
    Ok(())
}

fn cursor() -> (i32, i32) {
    let mut p = POINT { x: 0, y: 0 };
    unsafe { GetCursorPos(&mut p) };
    (p.x, p.y)
}

fn move_to(x: i32, y: i32) -> Result<(), String> {
    if unsafe { SetCursorPos(x, y) } == 0 {
        return Err(format!("SetCursorPos({x},{y}) failed"));
    }
    std::thread::sleep(Duration::from_millis(15));
    Ok(())
}

fn button_flags(b: u8) -> (u32, u32) {
    match b {
        1 => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        2 => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
        _ => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
    }
}

pub fn click_at(x: i32, y: i32, button: u8, count: u8) -> Result<(), String> {
    move_to(x, y)?;
    let (d, u) = button_flags(button);
    for i in 0..count {
        send(&[mouse_input(d, 0), mouse_input(u, 0)])?;
        if i + 1 < count {
            std::thread::sleep(Duration::from_millis(60));
        }
    }
    Ok(())
}

/// Run a validated batch. `map` turns screenshot coordinates into physical ones.
pub fn run_actions(actions: &[Action], map: &dyn Fn(f64, f64) -> (i32, i32)) -> Result<Vec<Value>, String> {
    let mut done = vec![];
    for (i, a) in actions.iter().enumerate() {
        let r: Result<Value, String> = (|| {
            match a {
                Action::Move { x, y } => {
                    let (px, py) = map(*x, *y);
                    move_to(px, py)?;
                    Ok(json!({"move": [px, py]}))
                }
                Action::Click { x, y, button, count } => {
                    let (px, py) = match (x, y) { (Some(x), Some(y)) => map(*x, *y), _ => cursor() };
                    click_at(px, py, *button, *count)?;
                    Ok(json!({"click": [px, py], "button": button, "count": count}))
                }
                Action::Drag { x, y, x2, y2 } => {
                    let (ax, ay) = map(*x, *y);
                    let (bx, by) = map(*x2, *y2);
                    move_to(ax, ay)?;
                    send(&[mouse_input(MOUSEEVENTF_LEFTDOWN, 0)])?;
                    for s in 1..=12 {
                        move_to(ax + (bx - ax) * s / 12, ay + (by - ay) * s / 12)?;
                    }
                    send(&[mouse_input(MOUSEEVENTF_LEFTUP, 0)])?;
                    Ok(json!({"drag": [ax, ay, bx, by]}))
                }
                Action::Scroll { x, y, delta, horizontal } => {
                    if let (Some(x), Some(y)) = (x, y) {
                        let (px, py) = map(*x, *y);
                        move_to(px, py)?;
                    }
                    let f = if *horizontal { MOUSEEVENTF_HWHEEL } else { MOUSEEVENTF_WHEEL };
                    send(&[mouse_input(f, (delta * 120) as u32)])?;
                    Ok(json!({"scroll": delta}))
                }
                Action::Key { keys, text } => {
                    press_combo(keys)?;
                    // spelled with spaces so the output redactor leaves it alone
                    Ok(json!({"keys": text.split('+').collect::<Vec<_>>().join(" + ")}))
                }
                Action::Text { text } => {
                    type_text(text)?;
                    Ok(json!({"typed_chars": text.chars().count()}))
                }
                Action::Wait { ms } => {
                    std::thread::sleep(Duration::from_millis(*ms));
                    Ok(json!({"wait_ms": ms}))
                }
            }
        })();
        match r {
            Ok(v) => done.push(v),
            Err(e) => return Err(format!("action {i} failed: {e} (completed before it: {})", serde_json::to_string(&done).unwrap_or_default())),
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    Ok(done)
}

// ---------------------------------------------------------------- display modes (PE multi-resolution)

fn devmode() -> DEVMODEW {
    let mut d: DEVMODEW = unsafe { std::mem::zeroed() };
    d.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
    d
}

pub fn display_modes() -> Vec<(u32, u32, u32)> {
    let mut v = vec![];
    let mut i = 0;
    loop {
        let mut d = devmode();
        if unsafe { EnumDisplaySettingsW(std::ptr::null(), i, &mut d) } == 0 {
            break;
        }
        let m = (d.dmPelsWidth, d.dmPelsHeight, d.dmBitsPerPel);
        if m.2 >= 16 && !v.contains(&m) {
            v.push(m);
        }
        i += 1;
        if i > 2000 {
            break;
        }
    }
    v.sort();
    v
}

/// `spec`: "1920x1080", "max" (largest mode up to 1920 wide unless allow_huge), or "list".
pub fn set_display(spec: &str) -> Result<String, String> {
    let modes = display_modes();
    if spec == "list" {
        return Ok(modes.iter().map(|(w, h, b)| format!("{w}x{h}x{b}")).collect::<Vec<_>>().join("\n"));
    }
    let (w, h) = if spec == "max" {
        let best = modes.iter().filter(|m| m.0 <= 1920 && m.2 == 32).max_by_key(|m| (m.0 * m.1, m.0))
            .or_else(|| modes.iter().max_by_key(|m| m.0 * m.1)).ok_or("no display modes reported")?;
        (best.0, best.1)
    } else {
        let (a, b) = spec.split_once(['x', 'X', '*']).ok_or("expected WIDTHxHEIGHT, max or list")?;
        (a.trim().parse::<u32>().map_err(|e| e.to_string())?, b.trim().parse::<u32>().map_err(|e| e.to_string())?)
    };
    let mut d = devmode();
    d.dmPelsWidth = w;
    d.dmPelsHeight = h;
    d.dmBitsPerPel = 32;
    d.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;
    let mut r = unsafe { ChangeDisplaySettingsW(&d, CDS_UPDATEREGISTRY) };
    if r != DISP_CHANGE_SUCCESSFUL {
        d.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT;
        r = unsafe { ChangeDisplaySettingsW(&d, CDS_UPDATEREGISTRY) };
    }
    if r != DISP_CHANGE_SUCCESSFUL {
        return Err(format!("ChangeDisplaySettings {w}x{h} failed ({r}); modes: {}",
                           modes.iter().map(|(w, h, _)| format!("{w}x{h}")).collect::<Vec<_>>().join(" ")));
    }
    Ok(format!("{w}x{h}"))
}

// ---------------------------------------------------------------- control tree (UIA thread)

pub struct TreeNode {
    pub depth: usize,
    pub ctype: String,
    pub name: String,
    pub aid: String,
    pub rect: (i32, i32, i32, i32),
    pub enabled: bool,
    pub value: Option<String>,
}

enum Elem {
    Uia(windows::Win32::UI::Accessibility::IUIAutomationElement),
    Hwnd(HWND),
}

struct UiaState {
    auto: Option<windows::Win32::UI::Accessibility::IUIAutomation>,
    err: String,
    refs: Vec<(Elem, TreeNode)>,
}

type Job = Box<dyn FnOnce(&mut UiaState) + Send>;

fn worker() -> &'static Mutex<mpsc::Sender<Job>> {
    static W: OnceLock<Mutex<mpsc::Sender<Job>>> = OnceLock::new();
    W.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new().name("uia".into()).spawn(move || {
            use windows::Win32::System::Com::*;
            dpi_aware();
            let mut st = UiaState { auto: None, err: String::new(), refs: vec![] };
            unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
                match CoCreateInstance::<_, windows::Win32::UI::Accessibility::IUIAutomation>(
                    &windows::Win32::UI::Accessibility::CUIAutomation, None, CLSCTX_INPROC_SERVER) {
                    Ok(a) => st.auto = Some(a),
                    Err(e) => st.err = format!("UI Automation unavailable: {e}"),
                }
            }
            while let Ok(job) = rx.recv() {
                job(&mut st);
            }
        }).expect("uia thread");
        Mutex::new(tx)
    })
}

fn on_uia<T: Send + 'static>(f: impl FnOnce(&mut UiaState) -> T + Send + 'static) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    worker().lock().unwrap().send(Box::new(move |st| { let _ = tx.send(f(st)); })).map_err(|_| "uia thread gone".to_string())?;
    rx.recv_timeout(Duration::from_secs(60)).map_err(|_| "UI Automation call timed out (a hung window?)".to_string())
}

fn uia_walk(st: &mut UiaState, root: windows::Win32::UI::Accessibility::IUIAutomationElement, max_depth: usize, max_nodes: usize) -> Result<(), String> {
    use windows::Win32::UI::Accessibility::*;
    let auto = st.auto.clone().ok_or("no uia")?;
    let walker = unsafe { auto.ControlViewWalker() }.map_err(|e| e.to_string())?;
    let mut stack = vec![(root, 0usize)];
    while let Some((e, d)) = stack.pop() {
        if st.refs.len() >= max_nodes {
            break;
        }
        unsafe {
            let off = e.CurrentIsOffscreen().map(|b| b.as_bool()).unwrap_or(false);
            let r = e.CurrentBoundingRectangle().unwrap_or_default();
            let ct = e.CurrentControlType().map(|c| c.0).unwrap_or(0);
            let name = e.CurrentName().map(|b| b.to_string()).unwrap_or_default();
            let aid = e.CurrentAutomationId().map(|b| b.to_string()).unwrap_or_default();
            let enabled = e.CurrentIsEnabled().map(|b| b.as_bool()).unwrap_or(true);
            let value = e.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId).ok()
                .and_then(|p| p.CurrentValue().ok()).map(|b| b.to_string());
            if !off || d == 0 {
                st.refs.push((Elem::Uia(e.clone()), TreeNode { depth: d, ctype: desktop::control_type_name(ct).into(), name, aid,
                    rect: (r.left, r.top, r.right - r.left, r.bottom - r.top), enabled, value }));
            }
            if d < max_depth {
                let mut kids = vec![];
                let mut c = walker.GetFirstChildElement(&e).ok();
                while let Some(k) = c {
                    c = walker.GetNextSiblingElement(&k).ok();
                    kids.push(k);
                    if kids.len() > 500 {
                        break;
                    }
                }
                for k in kids.into_iter().rev() {
                    stack.push((k, d + 1));
                }
            }
        }
    }
    Ok(())
}

fn hwnd_walk(st: &mut UiaState, root: HWND, max_nodes: usize) {
    unsafe extern "system" fn cb(h: HWND, l: LPARAM) -> BOOL {
        let v = &mut *(l as *mut Vec<HWND>);
        if IsWindowVisible(h) != 0 {
            v.push(h);
        }
        (v.len() < 2000) as BOOL
    }
    let mut kids: Vec<HWND> = vec![];
    unsafe { EnumChildWindows(root, Some(cb), &mut kids as *mut _ as LPARAM) };
    let push = |st: &mut UiaState, h: HWND, d: usize| {
        let r = rect_of(h);
        let cls = class_of(h);
        let ctype = match cls.to_lowercase().as_str() {
            "button" => "Button", "edit" | "richedit20w" | "richedit50w" | "richeditd2dpt" => "Edit", "static" => "Text",
            "combobox" => "ComboBox", "listbox" | "syslistview32" => "List", "systreeview32" => "Tree", _ => "Window",
        }.to_string();
        let enabled = unsafe { IsWindowEnabled(h) } != 0;
        st.refs.push((Elem::Hwnd(h), TreeNode { depth: d, ctype: format!("{ctype}/{cls}"), name: text_of(h), aid: String::new(),
            rect: (r.left, r.top, r.right - r.left, r.bottom - r.top), enabled, value: None }));
    };
    push(st, root, 0);
    for h in kids {
        if st.refs.len() >= max_nodes {
            break;
        }
        let mut d = 1;
        let mut p = unsafe { GetParent(h) };
        while !p.is_null() && p != root && d < 20 {
            d += 1;
            p = unsafe { GetParent(p) };
        }
        push(st, h, d);
    }
}

/// Build the tree for a window (or the whole desktop) and remember the refs.
pub fn tree(window: Option<HWND>, all: bool, depth: usize, max_nodes: usize) -> Result<(bool, String, Vec<String>), String> {
    let win = window.map(|h| h as usize);
    on_uia(move |st| {
        st.refs.clear();
        let mut uia = false;
        let mut note = String::new();
        if let Some(auto) = st.auto.clone() {
            let root = unsafe { if all { auto.GetRootElement() } else { auto.ElementFromHandle(windows::Win32::Foundation::HWND(win.unwrap_or(0) as *mut _)) } };
            match root.map_err(|e| e.to_string()).and_then(|r| uia_walk(st, r, depth, max_nodes)) {
                Ok(()) => uia = true,
                Err(e) => note = format!("UI Automation failed ({e}); fell back to the Win32 window tree"),
            }
        } else {
            note = format!("{}; fell back to the Win32 window tree (classic controls only)", st.err);
        }
        if !uia {
            st.refs.clear();
            let root = if all { unsafe { GetDesktopWindow() } } else { win.unwrap_or(0) as HWND };
            hwnd_walk(st, root, max_nodes);
        }
        let lines = st.refs.iter().enumerate().map(|(i, (_, n))| desktop::tree_line(n.depth, i + 1, &n.ctype, &n.name, &n.aid, n.rect, n.enabled, n.value.as_deref())).collect();
        (uia, note, lines)
    })
}

/// Rects of the last tree's refs (for Set-of-Marks).
pub fn last_rects() -> Vec<(usize, (i32, i32, i32, i32))> {
    on_uia(|st| st.refs.iter().enumerate().filter(|(_, (_, n))| n.rect.2 > 4 && n.rect.3 > 4).map(|(i, (_, n))| (i + 1, n.rect)).collect()).unwrap_or_default()
}

pub fn ref_info(r: usize) -> Result<(String, String, (i32, i32, i32, i32)), String> {
    on_uia(move |st| st.refs.get(r.wrapping_sub(1)).map(|(_, n)| (n.ctype.clone(), n.name.clone(), n.rect))
        .ok_or_else(|| format!("ref {r} not found; call desktop_tree first")))?
}

/// Pattern-based action on a ref; Ok(None) means "no pattern, use the mouse/keyboard fallback".
pub fn element_action(r: usize, action: String, text: Option<String>) -> Result<Option<Value>, String> {
    on_uia(move |st| -> Result<Option<Value>, String> {
        use windows::Win32::UI::Accessibility::*;
        let (e, _) = st.refs.get(r.wrapping_sub(1)).ok_or_else(|| format!("ref {r} not found; call desktop_tree first"))?;
        match e {
            Elem::Uia(e) => unsafe {
                let out = match action.as_str() {
                    "click" => e.GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId).ok().map(|p| p.Invoke().map(|_| json!({"via": "InvokePattern"}))),
                    "set_value" => e.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId).ok().map(|p| {
                        p.SetValue(&windows::core::BSTR::from(text.clone().unwrap_or_default())).map(|_| json!({"via": "ValuePattern"}))
                    }),
                    "value" => Some(e.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
                        .and_then(|p| p.CurrentValue()).map(|v| json!({"value": v.to_string(), "via": "ValuePattern"}))
                        .or_else(|_| e.GetCurrentPatternAs::<IUIAutomationTogglePattern>(UIA_TogglePatternId)
                            .and_then(|p| p.CurrentToggleState()).map(|t| json!({"value": match t.0 { 0 => "off", 1 => "on", _ => "indeterminate" }, "via": "TogglePattern"})))
                        .or_else(|_| e.CurrentName().map(|n| json!({"value": n.to_string(), "via": "Name"})))),
                    "focus" => Some(e.SetFocus().map(|_| json!({"via": "SetFocus"}))),
                    "toggle" => e.GetCurrentPatternAs::<IUIAutomationTogglePattern>(UIA_TogglePatternId).ok().map(|p| p.Toggle().map(|_| json!({"via": "TogglePattern"}))),
                    "expand" => e.GetCurrentPatternAs::<IUIAutomationExpandCollapsePattern>(UIA_ExpandCollapsePatternId).ok().map(|p| p.Expand().map(|_| json!({"via": "ExpandCollapsePattern"}))),
                    "collapse" => e.GetCurrentPatternAs::<IUIAutomationExpandCollapsePattern>(UIA_ExpandCollapsePatternId).ok().map(|p| p.Collapse().map(|_| json!({"via": "ExpandCollapsePattern"}))),
                    "select" => e.GetCurrentPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId).ok().map(|p| p.Select().map(|_| json!({"via": "SelectionItemPattern"}))),
                    _ => None,
                };
                match out {
                    Some(Ok(v)) => Ok(Some(v)),
                    Some(Err(err)) => Err(format!("{action} failed: {err}")),
                    None => {
                        if action == "set_value" {
                            let _ = e.SetFocus();
                        }
                        Ok(None)
                    }
                }
            },
            Elem::Hwnd(h) => {
                let h = *h;
                match action.as_str() {
                    "click" if class_of(h).eq_ignore_ascii_case("button") => unsafe {
                        PostMessageW(h, 0x00F5 /* BM_CLICK */, 0, 0);
                        Ok(Some(json!({"via": "BM_CLICK"})))
                    },
                    "set_value" => unsafe {
                        let w = wide(&text.clone().unwrap_or_default());
                        SendMessageW(h, WM_SETTEXT, 0, w.as_ptr() as LPARAM);
                        Ok(Some(json!({"via": "WM_SETTEXT"})))
                    },
                    "value" => {
                        let mut buf = vec![0u16; 65536];
                        let n = unsafe { SendMessageW(h, WM_GETTEXT, buf.len(), buf.as_mut_ptr() as LPARAM) };
                        Ok(Some(json!({"value": String::from_utf16_lossy(&buf[..(n.max(0) as usize).min(buf.len())]), "via": "WM_GETTEXT"})))
                    }
                    "focus" => unsafe {
                        SetForegroundWindow(GetAncestor(h, GA_ROOT));
                        Ok(Some(json!({"via": "SetForegroundWindow"})))
                    },
                    _ => Ok(None),
                }
            }
        }
    })?
}
