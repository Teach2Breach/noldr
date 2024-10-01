//ignore irrefutable warning
#![allow(irrefutable_let_patterns)]

use std::ffi::{c_void, CString};
use noldr::{get_dll_address, get_function_address, list_all_dlls, load_dll};
use noldr::get_teb;
use noldr::HMODULE;

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

fn main() {
    // Get the Thread Environment Block (TEB)
    let teb = get_teb();
    println!("teb: {:?}", teb);

    // List all currently loaded DLLs
    let dlls = list_all_dlls(teb);
    println!("Loaded DLLs:");
    for dll in dlls {
        if let (name, _) = dll {
            // Filter and print only valid DLL names
            if !name.is_empty() && name != "\0" && name.to_lowercase().ends_with(".dll") {
                println!("  {}", name);
            }
        }
    }

    // Locate kernel32.dll as an example
    println!("locating kernel32.dll as an example");
    let dll_base_address = get_dll_address("kERnel32.DLL".to_string(), teb).unwrap();
    println!("kernel32.dll base address: {:?}", dll_base_address);

    // Load user32.dll manually
    println!("loading user32.dll");
    let user32_handle = load_dll("user32.dll", dll_base_address);
    println!("user32.dll handle: {:?}", user32_handle);

    // Get the base address of user32.dll
    let user32_base_address = user32_handle.0 as usize;
    println!("user32.dll base address: 0x{:x}", user32_base_address);

    // List all loaded DLLs again to confirm user32.dll is now loaded
    let dlls = list_all_dlls(teb);
    println!("New loaded DLLs:");
    for dll in dlls {
        if let (name, _) = dll {
            if !name.is_empty() && name != "\0" && name.to_lowercase().ends_with(".dll") {
                println!("  {}", name);
            }
        }
    }

    // Check if user32.dll was successfully loaded
    if user32_handle != HMODULE::default() {
        println!("{}", &lc!("locating MessageBoxA in user32.dll as an example"));
        
        // Get the address of MessageBoxA function
        let message_box_a = unsafe {
            let function_address = get_function_address(user32_handle.0 as *mut _, &lc!("MessageBoxA")).unwrap();
            // Convert the function address to a callable function pointer
            std::mem::transmute::<_, extern "system" fn(*mut c_void, *const i8, *const i8, u32) -> i32>(function_address)
        };

        print!("{}", &lc!("MessageBoxA address: "));
        println!("{:?}", message_box_a as *const ());

        // Call MessageBoxA to display a message
        let title = CString::new("Example").unwrap();
        let message = CString::new("Hello from no-LDR technique!").unwrap();
        message_box_a(std::ptr::null_mut(), message.as_ptr(), title.as_ptr(), 0);
    } else {
        println!("Failed to load user32.dll");
    }
}