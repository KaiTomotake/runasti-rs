use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, FALSE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID},
        Security::{
            AdjustTokenPrivileges,
            DuplicateTokenEx,
            ImpersonateLoggedOnUser,
            LUID_AND_ATTRIBUTES,
            LookupPrivilegeValueW,
            SE_DEBUG_NAME,
            SE_IMPERSONATE_NAME,
            SE_PRIVILEGE_ENABLED,
            SECURITY_ATTRIBUTES,
            SecurityImpersonation,
            TOKEN_ADJUST_PRIVILEGES,
            TOKEN_ALL_ACCESS,
            TOKEN_DUPLICATE,
            TOKEN_PRIVILEGES,
            TOKEN_QUERY,
            TokenImpersonation,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot,
                PROCESSENTRY32W,
                Process32FirstW,
                Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Services::{
                CloseServiceHandle,
                OpenSCManagerW,
                OpenServiceW,
                QueryServiceStatusEx,
                SC_MANAGER_CONNECT,
                SC_STATUS_PROCESS_INFO,
                SERVICE_QUERY_STATUS,
                SERVICE_RUNNING,
                SERVICE_START,
                SERVICE_START_PENDING,
                SERVICE_STATUS_PROCESS,
                SERVICE_STOP_PENDING,
                SERVICE_STOPPED,
                SERVICES_ACTIVE_DATABASE,
                StartServiceW,
            },
            Threading::{
                CREATE_UNICODE_ENVIRONMENT,
                CreateProcessWithTokenW,
                GetCurrentProcess,
                GetStartupInfoW,
                LOGON_WITH_PROFILE,
                OpenProcess,
                OpenProcessToken,
                PROCESS_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION,
                STARTUPINFOW,
                Sleep,
            },
        },
    },
    core::{PCWSTR, PWSTR, w},
};

unsafe fn enable_privilege(privilege_name: PCWSTR) -> Result<(), String> {
    let mut token_handle = HANDLE::default();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        )
    } == FALSE
    {
        return Err(format!("OpenProcessToken failed: {}", unsafe {
            GetLastError()
        }));
    };
    let mut luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), privilege_name, &mut luid) } == FALSE {
        unsafe {
            CloseHandle(token_handle);
        }
        return Err(format!("LookupPrivilegeValue failed: {}", unsafe {
            GetLastError()
        }));
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    if unsafe {
        AdjustTokenPrivileges(
            token_handle,
            FALSE,
            &tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == FALSE
    {
        unsafe {
            CloseHandle(token_handle);
        }
        return Err(format!("AdjustTokenPrivilege failed: {}", unsafe {
            GetLastError()
        }));
    }
    unsafe {
        CloseHandle(token_handle);
    }
    Ok(())
}

unsafe fn get_processid(process_name: [u16; 260]) -> Result<u32, String> {
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot_handle == INVALID_HANDLE_VALUE {
        return Err(format!("CreateToolhelp32Snapshot failed: {}", unsafe {
            GetLastError()
        }));
    }
    let mut pid = 0;
    let mut pe = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snapshot_handle, &mut pe) } != FALSE {
        while unsafe { Process32NextW(snapshot_handle, &mut pe) } != FALSE {
            if pe.szExeFile == process_name {
                pid = pe.th32ProcessID;
                break;
            }
        }
    } else {
        unsafe {
            CloseHandle(snapshot_handle);
        }
        return Err(format!("Process32First failed: {}", unsafe {
            GetLastError()
        }));
    }
    if pid == u32::MAX {
        unsafe {
            CloseHandle(snapshot_handle);
        }
        return Err(format!("process not found: {}", unsafe { GetLastError() }));
    }
    unsafe {
        CloseHandle(snapshot_handle);
    }
    Ok(pid)
}

unsafe fn impersonate_system() -> Result<(), String> {
    let system_pid = unsafe { get_processid(to_wide_array("winlogon.exe")) }?;
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, system_pid) };
    if process_handle.is_null() {
        return Err(format!("OpenProcess failed (winlogon.exe): {}", unsafe {
            GetLastError()
        }));
    }
    let mut token_handle = HANDLE::default();
    if unsafe { OpenProcessToken(process_handle, TOKEN_DUPLICATE, &mut token_handle) } == FALSE {
        unsafe {
            CloseHandle(process_handle);
        }
        return Err(format!(
            "OpenProcessToken failed (winlogon.exe): {}",
            unsafe { GetLastError() }
        ));
    }
    unsafe {
        CloseHandle(process_handle);
    }
    let mut dup_token_handle = HANDLE::default();
    let token_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: FALSE,
    };
    if unsafe {
        DuplicateTokenEx(
            token_handle,
            TOKEN_ALL_ACCESS,
            &token_attributes as *const _,
            SecurityImpersonation,
            TokenImpersonation,
            &mut dup_token_handle,
        )
    } == FALSE
    {
        unsafe {
            CloseHandle(token_handle);
        }
        return Err(format!(
            "DuplicateTokenEx failed (winlogon.exe): {}",
            unsafe { GetLastError() }
        ));
    }
    unsafe {
        CloseHandle(token_handle);
    }
    if unsafe { ImpersonateLoggedOnUser(dup_token_handle) } == FALSE {
        unsafe {
            CloseHandle(dup_token_handle);
        }
        return Err(format!("ImpersonateLoggedOnUser failed: {}", unsafe {
            GetLastError()
        }));
    }
    unsafe {
        CloseHandle(dup_token_handle);
    }
    Ok(())
}

fn to_wide_array(s: &str) -> [u16; 260] {
    let mut buf = [0u16; 260];
    let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let len = utf16.len().min(260);
    buf[..len].copy_from_slice(&utf16[..len]);
    buf
}

unsafe fn start_ti() -> Result<u32, String> {
    let sc_manager_handle = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            SERVICES_ACTIVE_DATABASE,
            SC_MANAGER_CONNECT,
        )
    };
    if sc_manager_handle.is_null() {
        return Err(format!("OpenSCManager failed: {}", unsafe {
            GetLastError()
        }));
    }
    let service_handle = unsafe {
        OpenServiceW(
            sc_manager_handle,
            w!("TrustedInstaller"),
            SERVICE_QUERY_STATUS | SERVICE_START,
        )
    };
    if service_handle.is_null() {
        unsafe {
            CloseServiceHandle(sc_manager_handle);
        }
        return Err(format!("OpenService failed: {}", unsafe { GetLastError() }));
    }
    unsafe {
        CloseServiceHandle(sc_manager_handle);
    }
    let mut status_buffer = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0u32;
    while unsafe {
        QueryServiceStatusEx(
            service_handle,
            SC_STATUS_PROCESS_INFO,
            &mut status_buffer as *mut _ as *mut _,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    } != FALSE
    {
        if status_buffer.dwCurrentState == SERVICE_STOPPED
            && unsafe { StartServiceW(service_handle, 0, std::ptr::null()) } == FALSE
        {
            unsafe {
                CloseHandle(service_handle);
            }
            return Err(format!("StartService failed: {}", unsafe {
                GetLastError()
            }));
        }
        if status_buffer.dwCurrentState == SERVICE_START_PENDING
            || status_buffer.dwCurrentState == SERVICE_STOP_PENDING
        {
            unsafe {
                Sleep(status_buffer.dwWaitHint);
            }
            continue;
        }
        if status_buffer.dwCurrentState == SERVICE_RUNNING {
            unsafe {
                CloseServiceHandle(service_handle);
            }
            return Ok(status_buffer.dwProcessId);
        }
    }
    unsafe {
        CloseServiceHandle(service_handle);
    }
    Err(format!("QueryServiceStatusEx failed: {}", unsafe {
        GetLastError()
    }))
}

unsafe fn create_process(pid: u32, command_line: PWSTR) -> Result<(), String> {
    unsafe {
        enable_privilege(SE_DEBUG_NAME)?;
        enable_privilege(SE_IMPERSONATE_NAME)?;
        impersonate_system()?;
    }
    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if process_handle.is_null() {
        return Err(format!(
            "OpenProcess failed (TrustedInstaller.exe): {}",
            unsafe { GetLastError() }
        ));
    }
    let mut token_handle = HANDLE::default();
    if unsafe { OpenProcessToken(process_handle, TOKEN_DUPLICATE, &mut token_handle) } == FALSE {
        unsafe {
            CloseHandle(process_handle);
        }
        return Err(format!(
            "OpenProcessToken failed (TrustedInstaller.exe): {}",
            unsafe { GetLastError() }
        ));
    }
    unsafe {
        CloseHandle(process_handle);
    }
    let mut dup_token_handle = HANDLE::default();
    let token_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: FALSE,
    };
    if unsafe {
        DuplicateTokenEx(
            token_handle,
            TOKEN_ALL_ACCESS,
            &token_attributes as *const _,
            SecurityImpersonation,
            TokenImpersonation,
            &mut dup_token_handle,
        )
    } == FALSE
    {
        unsafe {
            CloseHandle(token_handle);
        }
        return Err(format!(
            "DuplicateTokenEx failed (TrustedInstaller.exe): {}",
            unsafe { GetLastError() }
        ));
    }
    unsafe {
        CloseHandle(token_handle);
    }
    let mut startup_info = STARTUPINFOW::default();
    unsafe { GetStartupInfoW(&mut startup_info) }
    let mut process_info = PROCESS_INFORMATION::default();
    if unsafe {
        CreateProcessWithTokenW(
            dup_token_handle,
            LOGON_WITH_PROFILE,
            std::ptr::null(),
            command_line,
            CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(),
            std::ptr::null(),
            &startup_info,
            &mut process_info,
        )
    } == FALSE
    {
        unsafe {
            CloseHandle(dup_token_handle);
        }
        return Err(format!("CreateProcessWithTokenW failed: {}", unsafe {
            GetLastError()
        }));
    }
    unsafe {
        CloseHandle(dup_token_handle);
    }
    Ok(())
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn runasti<T: ToString>(command_line: T) -> Result<(), String> {
    let mut process_name_wide: Vec<u16> = command_line.to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let process_name = process_name_wide.as_mut_ptr();
    let pid = unsafe { start_ti() }?;
    unsafe { create_process(pid, process_name) }
}
