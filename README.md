# Fritter

The evasive cousin of [Donut](https://github.com/TheWover/donut).

Fritter is a heavily modified fork of TheWover and Odzhan's Donut shellcode generator. It generates position-independent shellcode for in-memory execution of VBScript, JScript, EXE, DLL, and .NET assemblies, but with a heavy focus on evasion and signature resistance.

## What's different

Fritter strips out features that aren't needed and replaces internals that have become well-signatured over the years. The crypto, compression, and API resolution layers have all been reworked. The codebase has been simplified to x64-only.

Every generation produces fully unique output. The entry stub, encoding layer, and loader blob are all randomized per run. Different instructions, different keys, different layout, different sizes. Nothing is static between two runs of the same input.

At runtime, Fritter manages memory permissions to minimize the executable footprint of the loader in memory. By default, only a small window of code is executable at any given time during loader execution. This can be configured with the `-g` flag.

## Usage

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

  OUTPUT
    -o, --output <path>       Output file (default: loader.bin)
    -f, --format <1-8>        1=Bin 2=B64 3=C 4=Ruby 5=Py 6=PS 7=C# 8=Hex
    -x, --exit   <1-3>        1=Thread (default) 2=Process 3=Block
    -y, --fork   <offset>     Fork thread, continue at RVA offset

  LOADER
    -e, --entropy <1-3>       1=None 2=Random names 3=Names+Crypto (default)
    -k, --headers <1-2>       1=Overwrite (default) 2=Keep all
    -g, --chunked <0-1>       0=RW->RX  1=VEH sliding window (default)
    -d, --domain  <name>      AppDomain name for .NET
    -j, --decoy   <path>      Decoy module for Module Overloading

  STAGING
    -n, --modname <name>      Module name for HTTP staging
    -s, --server  <url>       Server URL (supports basic auth)
```

### Examples

```
fritter -i payload.exe
fritter -i implant.dll -m RunMain -p "arg1 arg2"
fritter -i payload.exe -g 0 -o out.bin
```

## Credits

Fritter is built on the work of [TheWover](https://github.com/TheWover) and [Odzhan](https://github.com/odzhan), whose original [Donut](https://github.com/TheWover/donut) project made position-independent shellcode generation accessible and practical. Their architecture, loader design, and PIC framework are the foundation everything here is built on.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
