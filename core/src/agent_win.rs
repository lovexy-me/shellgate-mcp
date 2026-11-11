//! Win32 parts of the helper agents: session ids, starting a copy of ShellGate in the logged-on
//! user's session (from a service), starting an elevated copy (one UAC prompt), pid liveness.

#![cfg(windows)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevation, TokenPrimary, TOKEN_ALL_ACCESS,
    TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::platform::wide;

pub fn current_session() -> u32 {
    let mut s = u32::MAX;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut s) };
    s
}

/// Running in session 0 (a service), where there is no interactive desktop.
pub fn in_service_session() -> bool {
    current_session() == 0
}

pub fn pid_alive(pid: u32) -> bool {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32;
        CloseHandle(h);
        ok
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut tok: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, &mut e as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len) != 0;
        CloseHandle(tok);
        ok && e.TokenIsElevated != 0
    }
}

fn quote(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    format!("\"{}\"", a.replace('"', "\\\""))
}

/// Start `exe args` in the active console session as the logged-on user (needs SYSTEM).
pub fn spawn_in_user_session(exe: &str, args: &[String]) -> Result<u32, String> {
    unsafe {
        let session = WTSGetActiveConsoleSessionId();
        if session == u32::MAX {
            return Err("no user is logged on at the console".into());
        }
        let mut user: HANDLE = null_mut();
        if WTSQueryUserToken(session, &mut user) == 0 {
            return Err(format!("WTSQueryUserToken failed ({}); the service must run as LocalSystem", std::io::Error::last_os_error()));
        }
        let mut primary: HANDLE = null_mut();
        let dup = DuplicateTokenEx(user, TOKEN_ALL_ACCESS, null(), SecurityImpersonation, TokenPrimary, &mut primary);
        CloseHandle(user);
        if dup == 0 {
            return Err(format!("DuplicateTokenEx failed ({})", std::io::Error::last_os_error()));
        }
        let mut env: *mut core::ffi::c_void = null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, primary, 0) != 0;
        let mut cmd = wide(&std::iter::once(quote(exe)).chain(args.iter().map(|a| quote(a))).collect::<Vec<_>>().join(" "));
        let mut desktop = wide("winsta0\\default");
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desktop.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessAsUserW(primary, null(), cmd.as_mut_ptr(), null(), null(), 0,
                                      CREATE_NO_WINDOW | if have_env { CREATE_UNICODE_ENVIRONMENT } else { 0 },
                                      if have_env { env } else { null_mut() }, null(), &si, &mut pi);
        let err = std::io::Error::last_os_error();
        if have_env {
            DestroyEnvironmentBlock(env);
        }
        CloseHandle(primary);
        if ok == 0 {
            return Err(format!("CreateProcessAsUserW failed ({err})"));
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Ok(pi.dwProcessId)
    }
}

/// Start `exe args` elevated: Windows shows the UAC prompt on the user's screen.
pub fn spawn_elevated(exe: &str, args: &[String]) -> Result<(), String> {
    unsafe {
        let verb = wide("runas");
        let file = wide(exe);
        let params = wide(&args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "));
        let mut sei: SHELLEXECUTEINFOW = std::mem::zeroed();
        sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = file.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.nShow = 0; // SW_HIDE
        if ShellExecuteExW(&mut sei) == 0 {
            return Err(format!("elevation was not granted ({})", std::io::Error::last_os_error()));
        }
        if !sei.hProcess.is_null() {
            CloseHandle(sei.hProcess);
        }
        Ok(())
    }
}
