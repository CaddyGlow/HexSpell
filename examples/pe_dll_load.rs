//! Load a generated DLL with a matching-architecture Windows process.
//! Usage: pe_dll_load DLL [--force-relocation]
#[cfg(not(windows))]
fn main() {
    eprintln!("pe_dll_load must run on Windows with the DLL's architecture");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows::run()
}

#[cfg(windows)]
mod windows {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr};
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(path: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            kind: u32,
            protection: u32,
        ) -> *mut c_void;
        fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
    }
    struct Reservation(*mut c_void);
    impl Drop for Reservation {
        fn drop(&mut self) {
            // SAFETY: this object owns a reservation obtained from VirtualAlloc.
            unsafe {
                VirtualFree(self.0, 0, 0x8000);
            }
        }
    }
    struct Module(*mut c_void);
    impl Drop for Module {
        fn drop(&mut self) {
            // SAFETY: this object owns a successful LoadLibraryW reference.
            if !self.0.is_null() {
                unsafe {
                    FreeLibrary(self.0);
                }
            }
        }
    }
    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = std::env::args_os().skip(1);
        let first = args
            .next()
            .ok_or("usage: pe_dll_load DLL [--force-relocation] | --unwind-check EXE")?;
        if first == "--unwind-check" {
            let path = std::fs::canonicalize(args.next().ok_or("missing EXE path")?)?;
            if args.next().is_some() {
                return Err("too many arguments".into());
            }
            return unwind_check(&path);
        }
        let path = std::fs::canonicalize(first)?;
        let force = match args.next() {
            None => false,
            Some(arg) if arg == "--force-relocation" => true,
            Some(_) => return Err("unknown argument".into()),
        };
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let image = hexspell::pe::PE::from_buffer(std::fs::read(&path)?)?;
        let preferred = match image.optional_header.image_base.value {
            hexspell::pe::header::ImageBase::Base32(value) => value as usize,
            hexspell::pe::header::ImageBase::Base64(value) => usize::try_from(value)?,
        };
        let size = image.optional_header.size_of_image.value as usize;
        let _reservation = if force {
            // Reserve the exact preferred range in this process, before loading.
            // SAFETY: MEM_RESERVE/PAGE_NOACCESS allocates no accessible memory.
            let address = unsafe { VirtualAlloc(preferred as *mut c_void, size, 0x2000, 1) };
            if address != preferred as *mut c_void {
                return Err(format!(
                    "cannot reserve preferred base {preferred:#x}: {}",
                    std::io::Error::last_os_error()
                )
                .into());
            }
            Some(Reservation(address))
        } else {
            None
        };
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: wide is NUL-terminated and lives throughout the call.
        let mut module = Module(unsafe { LoadLibraryW(wide.as_ptr()) });
        if module.0.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        if force && module.0 as usize == preferred {
            return Err("DLL did not relocate".into());
        }
        // SAFETY: the generated DLL's documented exports have these exact system ABIs.
        unsafe {
            let add = GetProcAddress(module.0, c"Add".as_ptr().cast());
            let greeting = GetProcAddress(module.0, c"GetGreeting".as_ptr().cast());
            let version = GetProcAddress(module.0, 3usize as *const u8);
            if add.is_null() || greeting.is_null() || version.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let add: unsafe extern "system" fn(u32, u32) -> u32 = std::mem::transmute(add);
            let greeting: unsafe extern "system" fn() -> *const u16 = std::mem::transmute(greeting);
            let version: unsafe extern "system" fn() -> u32 = std::mem::transmute(version);
            if add(2, 3) != 5 || add(u32::MAX, 2) != 1 || version() != 1 {
                return Err("export result mismatch".into());
            }
            let text = greeting();
            if text.is_null() {
                return Err("NULL greeting".into());
            }
            let expected: Vec<u16> = "Hello".encode_utf16().chain(Some(0)).collect();
            if std::slice::from_raw_parts(text, expected.len()) != expected {
                return Err("greeting mismatch".into());
            }
            println!(
                "preferred={preferred:#x} actual={:#x}; exports and greeting passed",
                module.0 as usize
            );
            if FreeLibrary(module.0) == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            module.0 = ptr::null_mut();
        }
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn unwind_check(_: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        Err("unwind check requires an x64 loader".into())
    }
    #[cfg(target_arch = "x86_64")]
    fn unwind_check(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        }
        #[link(name = "ntdll")]
        extern "system" {
            fn RtlLookupFunctionEntry(pc: u64, base: *mut u64, history: *mut c_void)
                -> *mut c_void;
            fn RtlVirtualUnwind(
                kind: u32,
                base: u64,
                pc: u64,
                function: *mut c_void,
                context: *mut c_void,
                handler: *mut *mut c_void,
                frame: *mut u64,
                pointers: *mut c_void,
            ) -> *mut c_void;
        }
        // AMD64 CONTEXT has 16-byte alignment; offsets below follow winnt.h.
        #[repr(C, align(16))]
        struct Context([u8; 1232]);
        let image = hexspell::pe::PE::from_buffer(std::fs::read(path)?)?;
        let preferred = match image.optional_header.image_base.value {
            hexspell::pe::header::ImageBase::Base64(value) => usize::try_from(value)?,
            _ => return Err("unwind check requires PE32+".into()),
        };
        // Force a different mapping even for this metadata-only executable load.
        // SAFETY: reserve inaccessible address space owned by the RAII object.
        let address = unsafe {
            VirtualAlloc(
                preferred as *mut c_void,
                image.optional_header.size_of_image.value as usize,
                0x2000,
                1,
            )
        };
        if address != preferred as *mut c_void {
            return Err("cannot reserve EXE preferred base".into());
        }
        let _reservation = Reservation(address);
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // DONT_RESOLVE_DLL_REFERENCES maps headers/sections without executing entry/TLS.
        // SAFETY: valid NUL-terminated absolute path; module owns the mapping.
        let module = Module(unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), 1) });
        if module.0.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        if module.0 as usize == preferred {
            return Err("EXE metadata mapping did not relocate".into());
        }
        let pc = module.0 as u64 + u64::from(image.optional_header.entry_point.value) + 4;
        let mut base = 0u64;
        // SAFETY: pointers refer to live local storage; pc refers to the mapped image.
        let function = unsafe { RtlLookupFunctionEntry(pc, &mut base, ptr::null_mut()) };
        if function.is_null() || base != module.0 as u64 {
            return Err("runtime function lookup failed".into());
        }
        let mut stack = [0u64; 16];
        let sentinel = 0x1234567812345678u64;
        stack[5] = sentinel; // entry's sub rsp,40 leaves return address at RSP+40.
        let rsp = stack.as_mut_ptr() as u64;
        let mut context = Context([0; 1232]);
        context.0[48..52].copy_from_slice(&0x00100001u32.to_le_bytes()); // CONTEXT_CONTROL
        context.0[152..160].copy_from_slice(&rsp.to_le_bytes());
        context.0[248..256].copy_from_slice(&pc.to_le_bytes());
        let mut handler = ptr::null_mut();
        let mut frame = 0u64;
        // SAFETY: aligned CONTEXT buffer, valid function metadata, and a synthetic
        // stack large enough for the reviewed ALLOC_SMALL(40) unwind operation.
        unsafe {
            RtlVirtualUnwind(
                0,
                base,
                pc,
                function,
                context.0.as_mut_ptr().cast(),
                &mut handler,
                &mut frame,
                ptr::null_mut(),
            );
        }
        let actual_rsp = u64::from_le_bytes(context.0[152..160].try_into()?);
        let actual_rip = u64::from_le_bytes(context.0[248..256].try_into()?);
        if actual_rsp != rsp + 48 || actual_rip != sentinel {
            return Err(format!("unwind mismatch: rsp={actual_rsp:#x} rip={actual_rip:#x}").into());
        }
        println!("preferred={preferred:#x} actual={:#x}; RtlLookupFunctionEntry and RtlVirtualUnwind passed",module.0 as usize);
        Ok(())
    }
}
