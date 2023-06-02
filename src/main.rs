use std::{mem::size_of, time::Duration, thread};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE, LUID, WIN32_ERROR},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, SE_SHUTDOWN_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            TOKEN_QUERY,
        },
        System::{ProcessStatus::*, Shutdown::*, Threading::*},
    },
};

fn enum_procs_names() -> Vec<(u32, String)> {
    unsafe {
        let mut arr_process_ids: [u32; 1024] = [0; 1024]; // 4096 bytes
        let mut bytes_needed: u32 = 0;

        EnumProcesses(
            arr_process_ids.as_mut_ptr(),
            size_of::<[u32; 1024]>() as u32,
            &mut bytes_needed,
        );

        let process_ids: Vec<u32> = arr_process_ids
            .iter()
            .take(bytes_needed as usize / size_of::<u32>())
            .map(|pid: &u32| *pid)
            .collect::<Vec<u32>>();

        process_ids
            .iter()
            .map(|pid: &u32| {
                let process_handle: HANDLE =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, *pid)
                        .unwrap_or_default();
                if process_handle == HANDLE(0) {
                    // println!(
                    //     "OpenProcess failed: {}",
                    //     if GetLastError() == WIN32_ERROR(5) {
                    //         "Access Denied"
                    //     } else {
                    //         "Unknown Error"
                    //     }
                    // );
                    return (0, String::new());
                }

                let mut process_module: HMODULE = HMODULE(0);
                let mut bytes_needed: u32 = 0;

                EnumProcessModules(
                    process_handle,
                    &mut process_module,
                    size_of::<HMODULE>() as u32,
                    &mut bytes_needed,
                );

                let mut process_name: [u16; 1024] = [0; 1024];
                GetModuleBaseNameW(process_handle, process_module, &mut process_name);
                CloseHandle(process_handle);
                (*pid, String::from_utf16_lossy(&process_name).trim_end_matches('\0').to_string())
            })
            .filter(|(pid, _)| *pid != 0)
            .collect::<Vec<(u32, String)>>()
    }
}
fn wait_for_process(pid: u32) {
    unsafe {
        let process_handle: HANDLE =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .unwrap_or_default();
        if process_handle == HANDLE(0) {
            println!(
                "OpenProcess failed: {}",
                if GetLastError() == WIN32_ERROR(5) {
                    "Access Denied"
                } else {
                    "Unknown Error"
                }
            );
            ExitProcess(1);
        }

        let mut process_exit_code: u32 = 0;

        loop {
            GetExitCodeProcess(process_handle, &mut process_exit_code);
            if process_exit_code != 259 {
                break;
            }
            thread::sleep(Duration::from_millis(1000));
        }

        CloseHandle(process_handle);
    }
}
fn shutdown_windows() {
    unsafe {
        let mut tokenhandle: HANDLE = HANDLE(0);
        let mut states: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: LUID {
                    LowPart: 0,
                    HighPart: 0,
                },
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut tokenhandle,
        );

        LookupPrivilegeValueW(
            PCWSTR(std::ptr::null()),
            SE_SHUTDOWN_NAME,
            &mut states.Privileges[0].Luid,
        );

        AdjustTokenPrivileges(
            tokenhandle,
            false,
            Some(&mut states),
            size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            Some(&mut 0),
        );

        ExitWindowsEx(
            EWX_SHUTDOWN,
            SHTDN_REASON_MAJOR_APPLICATION
                | SHTDN_REASON_MINOR_MAINTENANCE
                | SHTDN_REASON_FLAG_PLANNED,
        );
    }
}

fn main() {
    let processes: Vec<(u32, String)> = enum_procs_names();

    println!("Processes:");
    for (pid, name) in processes {
        println!("{}: {}", pid, name);
    }

    loop {
        print!("Pid of process to wait for: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let pid: u32 = input.trim().parse().unwrap_or(0);
        if pid == 0 {
            continue;
        }
        println!("Waiting for process to exit, use Ctrl+C to cancel shutdown...");
        wait_for_process(pid);
        println!("Process exited, shutting down...");
        shutdown_windows();
    }
}
