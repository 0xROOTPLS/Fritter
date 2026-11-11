# Fritter

The evasive cousin of [Donut](https://github.com/TheWover/donut).

Fritter is a heavily modified fork of TheWover and Odzhan's Donut shellcode generator. It generates position-independent shellcode for in-memory execution of VBScript, JScript, EXE, DLL, and .NET assemblies, with a focus on evasion and signature resistance. The codebase is x64-only.

## What's different

**Lots.** Fritter strips out features that aren't commonly needed and replaces internals that have become well-signatured over the years. The crypto, compression, hashing, and API resolution layers have all been reworked among many other areas.

Polymorphism and evasion is the design goal. Every output is unique, and every build of the tool is itself unique. There are two distinct layers:

**Per-output randomization**: applied each time `fritter` is invoked. The entry stub, the polymorphic decoder, the encryption keys, the mask stub, the stubs written into the payload image and many structural elements within the generated shellcode are regenerated from new entropy on every PIC build.

**Per-build randomization**: applied each time `fritter` itself is compiled. Cipher and hash rotation constants, API resolution table layout, shim-side string scrambling, PEB-walk directions, post-execution wipe patterns, and several structural axes inside the loader and shim are baked at compile time.

At runtime, Fritter minimizes what of itself can be seen:

- **While the loader churns**, it is partitioned into individually encrypted functions, each with its own PE section, keystream seed, and dispatcher. Only one function's bytes are in plaintext at any given moment. **The earlier VEH sliding-window model has been retired in favor of this dispatch model.**
- **While the payload runs**, the whole loader is masked: encrypted, read/write, with a single generated stub page left executable.
- **Afterwards**, everything is wiped and nothing of the shellcode stays executable.

## !! Build from source is strongly recommended !!

**This matters.** The pre-built binaries available for testing in *`releases`* share their per-build constants across all users of the binary.

**Build your own copy.** The per-build axes are re-randomized on every `make` invocation:

```bash
# Linux, static-musl ELF, no runtime libc dependency
# Requires: build-essential, mingw-w64, musl-tools
make -f Makefile.linux release

# Windows (MSVC), recommended on Windows
nmake -f Makefile.msvc
```

Both toolchains lay each protected loader function into its own PE section, which is what the N>1 per-function dispatch model needs, so MSVC and Linux builds produce equivalent output. If you don't have Visual Studio, build under WSL with `Makefile.linux`; it cross-compiles the Windows loader via mingw-w64.

## Usage

The shellcode decodes itself in place, so the memory it runs from must be set as **RWX**. You should start it on a page boundary *(what `VirtualAlloc` returns)* to get the loader mask; at any other address it still runs, unmasked.

A `/test` folder is included with `calc.exe` and `inject_local64.exe` to test Fritter.
```
fritter [options] -i <EXE/DLL/VBS/JS>

  INPUT
    -i, --input  <path>       Input file to execute in-memory
    -p, --args   <args>       Parameters / command line for target
    -c, --class  <name>       Class name (required for .NET DLL)
    -m, --method <name>       Method or function for DLL
    -r, --runtime <ver>       CLR runtime version
    -w, --unicode             Pass command line as UNICODE
    -t, --thread              Run unmanaged EXE entrypoint as thread
    -b, --imagebase           EXE is the process image while it runs (resources; use with -k 2)
    -l, --tls-donor <dll>     Static TLS for the payload, borrowed from this DLL on the target
    -a, --allow-tls           Accept a payload that uses static TLS without a slot (at your own risk)

  OUTPUT
    -o, --output <path>       Output file (default: loader.bin)
    -f, --format <1-9>        1=Bin 2=B64 3=C 4=Ruby 5=Py 6=PS 7=C# 8=Hex 9=UUID
    -x, --exit   <1-3>        1=Thread (default) 2=Process 3=Block
    -y, --fork   <offset>     Fork thread, continue at RVA offset

  LOADER
    -e, --entropy <1-3>       1=None 2=Random names 3=Names+Crypto (default)
    -k, --headers <1-2>       1=Overwrite (default) 2=Keep all
    -d, --domain  <name>      AppDomain name for .NET
    -j, --decoy   <path>      Decoy module for Module Overloading

  KEY
    --key-brute <bits>        Key bits the loader finds by trial; default 22, 0 = none (key stored whole)
    --key-host <name>         Runs only where COMPUTERNAME is <name>
    --key-domain <name>       Runs only where USERDNSDOMAIN is <name>
    --key-user <name>         Runs only where USERNAME is <name>
    --key-env <NAME=VALUE>    Runs only where that environment variable has that value
```

### Examples

```
fritter -i payload.exe
fritter -i implant.dll -m RunMain -p "arg1 arg2"
fritter -i payload.exe -k 2 -o out.bin
fritter -i tool.exe -p "-v --all" -x 2
fritter -i Assembly.dll -c Namespace.Class -m Run -p "a b"
fritter -i script.js -f 7 -o loader.cs
fritter -i payload.exe --key-host WS-0142 --key-domain corp.example.com
fritter -i payload.exe -j C:\Windows\System32\wininet.dll
fritter -i payload.exe -l scesrv.dll
```

## Architecture

Nested layers, each decrypting or staging the next. Technical detail is in the [CHANGELOG](CHANGELOG.md).

1. **Entry stub**: junk prefix, stack alignment and trampoline, generated per output.
2. **Decoder**: polymorphic, 32-bit xorshift keystream compiled into the code; no stored key.
3. **Dispatch shim**: routes each loader call through a per-function dispatcher that decrypts, runs, and wipes.
4. **Loader**: decrypts and verifies the instance in place, resolves APIs by hash, runs the payload (PE mapper, CLR host, or script engine).
5. **Mask stub**: one generated page; keeps the shim, loader and instance encrypted and read/write while the payload runs.
6. **Cleanup**: wipes everything and leaves no page of the shellcode executable.

## Known limits

- Memory given to the shellcode must be RWX.
- `/MD` payloads cannot catch MSVC C++ exceptions (`/MT` can).
- Static-TLS payloads need `-l <dll>` (or `-a`).
- `-j`: the loader thread's return address is in private memory.
- Scripts: calling the host from a second thread while under the mask is not supported; `WScript.Echo` and `WScript.CreateObject` are not implemented.
- `-e 1` outputs share about 20 KB (instance unencrypted by design).
- `-x 2` ends the host even if the output is damaged; a `--key-*` mismatch returns quietly.

## Credits

Fritter is built on the work of [TheWover](https://github.com/TheWover) and [Odzhan](https://github.com/odzhan), whose original [Donut](https://github.com/TheWover/donut) project made position-independent shellcode generation accessible and practical. Their architecture, loader design, and PIC framework are the foundation everything here is built on. The PE mapping, .NET hosting, and script execution paths are largely their work, retained and respected.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
