# noldr Library

This Rust library provides low-level functionality for working with Windows Portable Executable (PE) files and dynamic-link libraries (DLLs). It offers a set of tools for interacting with the Windows process environment, loading DLLs, and retrieving function addresses.

It was written to be used in a C2 server for hiding API calls and limiting the number of dependencies in a DLL. There are no Windows API crates imported, not even for types.

This library was written for a very specific use case in mind. If you want something more robust, check out Kudaes [DInvoke_rs](https://github.com/Kudaes/DInvoke_rs).

## Features

- Retrieve the Thread Environment Block (TEB) and Process Environment Block (PEB)
- Get the base address of loaded DLLs
- Retrieve function addresses from DLLs
- List all loaded DLLs in the current process
- Load DLLs dynamically
- Various Windows PE-related structures and types

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
noldr = "client = { git = "https://github.com/Teach2Breach/noldr.git", branch = "main" }"
```

There is an example of how to use the library in the `src/main.rs` file. 

Please note that litcrypt is used to encrypt specific strings, so you will need to add that to your project as well and set a `LITCRYPT_ENCRYPT_KEY` environment variable. The value is arbitrary, but it must be set. If you encrypt the API names which you want to call, in the same way as shown in main.rs, then those strings will not be visible in the compiled program. It is highly recommended to use litcrypt.

