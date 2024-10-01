#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::arch::asm;
use std::ffi::c_void;

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}
impl Copy for IMAGE_DATA_DIRECTORY {}
impl Clone for IMAGE_DATA_DIRECTORY {
    fn clone(&self) -> Self {
        *self
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IMAGE_DLL_CHARACTERISTICS(pub u16);

#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct IMAGE_OPTIONAL_HEADER_MAGIC(pub u16);
impl TypeKind for IMAGE_OPTIONAL_HEADER_MAGIC {
    type TypeKind = CopyType;
}
impl core::fmt::Debug for IMAGE_OPTIONAL_HEADER_MAGIC {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IMAGE_OPTIONAL_HEADER_MAGIC")
            .field(&self.0)
            .finish()
    }
}

#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct IMAGE_SUBSYSTEM(pub u16);
impl TypeKind for IMAGE_SUBSYSTEM {
    type TypeKind = CopyType;
}
impl core::fmt::Debug for IMAGE_SUBSYSTEM {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IMAGE_SUBSYSTEM").field(&self.0).finish()
    }
}

#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}
impl Copy for IMAGE_OPTIONAL_HEADER64 {}
impl Clone for IMAGE_OPTIONAL_HEADER64 {
    fn clone(&self) -> Self {
        *self
    }
}
impl TypeKind for IMAGE_OPTIONAL_HEADER64 {
    type TypeKind = CopyType;
}
impl Default for IMAGE_OPTIONAL_HEADER64 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

impl Copy for IMAGE_NT_HEADERS64 {}

impl Clone for IMAGE_NT_HEADERS64 {
    fn clone(&self) -> Self {
        *self
    }
}

impl TypeKind for IMAGE_NT_HEADERS64 {
    type TypeKind = CopyType;
}

impl Default for IMAGE_NT_HEADERS64 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct IMAGE_FILE_MACHINE(pub u16);
impl TypeKind for IMAGE_FILE_MACHINE {
    type TypeKind = CopyType;
}
impl std::fmt::Debug for IMAGE_FILE_MACHINE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IMAGE_FILE_MACHINE({})", self.0)
    }
}

#[repr(transparent)]
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct IMAGE_FILE_CHARACTERISTICS(pub u16);
impl TypeKind for IMAGE_FILE_CHARACTERISTICS {
    type TypeKind = CopyType;
}
impl std::fmt::Debug for IMAGE_FILE_CHARACTERISTICS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IMAGE_FILE_CHARACTERISTICS({})", self.0)
    }
}

impl Copy for IMAGE_FILE_HEADER {}

impl Clone for IMAGE_FILE_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}

impl core::fmt::Debug for IMAGE_FILE_HEADER {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IMAGE_FILE_HEADER")
            .field("Machine", &self.Machine)
            .field("NumberOfSections", &self.NumberOfSections)
            .field("TimeDateStamp", &self.TimeDateStamp)
            .field("PointerToSymbolTable", &self.PointerToSymbolTable)
            .field("NumberOfSymbols", &self.NumberOfSymbols)
            .field("SizeOfOptionalHeader", &self.SizeOfOptionalHeader)
            .field("Characteristics", &self.Characteristics)
            .finish()
    }
}

impl TypeKind for IMAGE_FILE_HEADER {
    type TypeKind = CopyType;
}

impl PartialEq for IMAGE_FILE_HEADER {
    fn eq(&self, other: &Self) -> bool {
        self.Machine == other.Machine
            && self.NumberOfSections == other.NumberOfSections
            && self.TimeDateStamp == other.TimeDateStamp
            && self.PointerToSymbolTable == other.PointerToSymbolTable
            && self.NumberOfSymbols == other.NumberOfSymbols
            && self.SizeOfOptionalHeader == other.SizeOfOptionalHeader
            && self.Characteristics == other.Characteristics
    }
}

impl Eq for IMAGE_FILE_HEADER {}

impl Default for IMAGE_FILE_HEADER {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(transparent)]
#[derive(PartialEq, Eq)]
pub struct HMODULE(pub isize);
impl HMODULE {
    pub fn is_invalid(&self) -> bool {
        self.0 == 0
    }
}
impl Default for HMODULE {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
impl Clone for HMODULE {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for HMODULE {}
impl core::fmt::Debug for HMODULE {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("HMODULE").field(&self.0).finish()
    }
}
impl TypeKind for HMODULE {
    type TypeKind = CopyType;
}
/*
impl windows_core::CanInto<HINSTANCE> for HMODULE {}
impl From<HMODULE> for HINSTANCE {
    fn from(value: HMODULE) -> Self {
        Self(value.0)
    }
}
*/
pub type TYPEKIND = i32;

#[doc(hidden)]
pub trait TypeKind {
    type TypeKind;
}

#[doc(hidden)]
pub struct InterfaceType;

#[doc(hidden)]
pub struct CloneType;

#[doc(hidden)]
pub struct CopyType;

#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}
impl Copy for IMAGE_DOS_HEADER {}
impl Clone for IMAGE_DOS_HEADER {
    fn clone(&self) -> Self {
        *self
    }
}
impl TypeKind for IMAGE_DOS_HEADER {
    type TypeKind = CopyType;
}
impl Default for IMAGE_DOS_HEADER {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [*mut core::ffi::c_void; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [*mut core::ffi::c_void; 2],
    pub DllBase: *mut core::ffi::c_void,
    pub Reserved3: [*mut core::ffi::c_void; 2],
    pub FullDllName: UNICODE_STRING,
    pub Reserved4: [u8; 8],
    pub Reserved5: [*mut core::ffi::c_void; 3],
    pub Anonymous: LDR_DATA_TABLE_ENTRY_0,
    pub TimeDateStamp: u32,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}

pub type PWSTR = *mut u16;

#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut c_void,
}

#[repr(C)]
pub struct TEB {
    pub Reserved1: [*mut c_void; 12],
    pub ProcessEnvironmentBlock: *mut PEB,
    pub Reserved2: [*mut c_void; 399],
    pub Reserved3: [u8; 1952],
    pub TlsSlots: [*mut c_void; 64],
    pub Reserved4: [u8; 8],
    pub Reserved5: [*mut c_void; 26],
    pub ReservedForOle: *mut c_void,
    pub Reserved6: [*mut c_void; 4],
    pub TlsExpansionSlots: *mut c_void,
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [*mut c_void; 3],
    pub AtlThunkSListPtr: *mut c_void,
    pub Reserved5: *mut c_void,
    pub Reserved6: u32,
    pub Reserved7: *mut c_void,
    pub Reserved8: u32,
    pub AtlThunkSListPtr32: u32,
    pub Reserved9: [*mut c_void; 45],
    pub Reserved10: [u8; 96],
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub Reserved11: [u8; 128],
    pub Reserved12: [*mut c_void; 1],
    pub SessionId: u32,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*mut c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*mut c_void; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}



//use windows::Win32::System::Diagnostics::Debug;

#[macro_use]
extern crate memoffset;

macro_rules! container_of {
    ($ptr:expr, $type:ty, $field:ident) => {{
        (($ptr as usize) - offset_of!($type, $field)) as *const $type
    }};
}

// Add this type definition
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;

#[inline]
pub fn get_teb() -> *const TEB {
    let teb: *const TEB;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("mov {}, gs:[0x30]", out(reg) teb);
        #[cfg(target_arch = "x86")]
        asm!("mov {}, fs:[0x18]", out(reg) teb);
    }
    teb
}

type HANDLE = *mut c_void;
//get the base address of an already loaded dll
pub fn get_dll_address(dll_name: String, teb: *const TEB) -> Option<*const c_void> {
    let mut peb_address: *const PEB = std::ptr::null();
    let dll_name_lower = dll_name.to_lowercase(); // Convert the input dll_name to lowercase
    unsafe {
        if !teb.is_null() {
            peb_address = (*teb).ProcessEnvironmentBlock;
            let ldr_data = (*peb_address).Ldr;
            if !ldr_data.is_null() {
                let list_entry = (*ldr_data).InMemoryOrderModuleList.Flink;
                if !list_entry.is_null() {
                    let mut current_entry =
                        container_of!(list_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    loop {
                        let dll_base = (*current_entry).DllBase;
                        let dll_name_in_memory = std::slice::from_raw_parts(
                            (*current_entry).FullDllName.Buffer,
                            (*current_entry).FullDllName.Length as usize / 2,
                        )
                        .as_ptr();
                        let dll_name_len = (*current_entry).FullDllName.Length as usize / 2;

                        // Convert the DLL name to a Rust string and make it lowercase for case-insensitive comparison
                        let dll_name_in_memory = String::from_utf16_lossy(
                            std::slice::from_raw_parts(dll_name_in_memory, dll_name_len),
                        )
                        .to_lowercase();

                        if dll_name_in_memory.ends_with(&dll_name_lower) {
                            return Some(dll_base);
                        }

                        // Move to the next entry
                        let next_entry = (*current_entry).InMemoryOrderLinks.Flink;
                        if next_entry == list_entry {
                            // We've looped back to the start of the list, so the DLL was not found
                            break;
                        }
                        current_entry =
                            container_of!(next_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    }
                }
            }
        }
    }
    None
}

//get the address of a function in a dll
pub fn get_function_address(dll_base: *const c_void, function_name: &str) -> Option<*const c_void> {
    unsafe {
        let dos_header = &*(dll_base as *const IMAGE_DOS_HEADER);
        let nt_headers =
            &*((dll_base as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
        let export_directory_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
        let export_directory = &*((dll_base as usize + export_directory_rva as usize)
            as *const IMAGE_EXPORT_DIRECTORY);

        let names_rva = export_directory.AddressOfNames;
        let functions_rva = export_directory.AddressOfFunctions;
        let ordinals_rva = export_directory.AddressOfNameOrdinals;

        let names = std::slice::from_raw_parts(
            (dll_base as usize + names_rva as usize) as *const u32,
            export_directory.NumberOfNames as usize,
        );
        let ordinals = std::slice::from_raw_parts(
            (dll_base as usize + ordinals_rva as usize) as *const u16,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let name_ptr = (dll_base as usize + names[i] as usize) as *const u8;
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8)
                .to_str()
                .unwrap_or_default();
            if name == function_name {
                let ordinal = ordinals[i] as usize;
                let function_rva =
                    *((dll_base as usize + functions_rva as usize) as *const u32).add(ordinal);
                return Some((dll_base as usize + function_rva as usize) as *const c_void);
            }
        }
    }
    None
}

// Function to get the current process handle
pub fn get_current_process_handle(_peb: *const PEB) -> HANDLE {
    // NtCurrentProcess is a pseudo-handle that always represents the current process.
    // It's a special constant that doesn't need to be closed.
    const NT_CURRENT_PROCESS: HANDLE = -1isize as HANDLE;

    // Return the pseudo-handle for the current process
    NT_CURRENT_PROCESS
}

//use std::ffi::c_void;

pub fn list_all_dlls(teb: *const TEB) -> Vec<(String, *mut c_void)> {
    let mut dll_list = Vec::new();
    let mut peb_address: *const PEB = std::ptr::null();
    unsafe {
        if !teb.is_null() {
            peb_address = (*teb).ProcessEnvironmentBlock;
            let ldr_data = (*peb_address).Ldr;
            if !ldr_data.is_null() {
                let list_entry = (*ldr_data).InMemoryOrderModuleList.Flink;
                if !list_entry.is_null() {
                    let mut current_entry =
                        container_of!(list_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    loop {
                        let dll_base = (*current_entry).DllBase;
                        let dll_name_in_memory = std::slice::from_raw_parts(
                            (*current_entry).FullDllName.Buffer,
                            (*current_entry).FullDllName.Length as usize / 2,
                        )
                        .as_ptr();
                        let dll_name_len = (*current_entry).FullDllName.Length as usize / 2;

                        // Convert the DLL name to a Rust string
                        let dll_name_in_memory = String::from_utf16_lossy(
                            std::slice::from_raw_parts(dll_name_in_memory, dll_name_len),
                        );

                        // Add the DLL name and base address to the list
                        dll_list.push((dll_name_in_memory, dll_base));

                        // Move to the next entry
                        let next_entry = (*current_entry).InMemoryOrderLinks.Flink;
                        if next_entry == list_entry {
                            // We've looped back to the start of the list
                            break;
                        }
                        current_entry =
                            container_of!(next_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    }
                }
            }
        }
    }
    dll_list
}


//for loading the dll and getting a handle to it
pub fn load_dll(dll_name: &str, kernel32_base: *const c_void) -> HMODULE {
    unsafe {
        // Get the base address of kernel32.dll
        //let kernel32_base = get_dll_address("kernel32.dll".to_string(), get_teb()).unwrap();

        // Get the address of LoadLibraryA function
        let load_library_a = get_function_address(kernel32_base, &lc!("LoadLibraryA")).unwrap();
        let load_library_a: extern "system" fn(*const i8) -> HMODULE =
            std::mem::transmute(load_library_a);

        // Convert dll_name to a C-style string
        let c_dll_name = std::ffi::CString::new(dll_name).unwrap();

        // Call LoadLibraryA to get the handle
        load_library_a(c_dll_name.as_ptr())
    }
}
