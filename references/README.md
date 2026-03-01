# References Directory

This directory holds local reference materials for CERF development. Contents are gitignored — each contributor sets up their own.

## Expected Structure

```
references/
  pb_sources/          - Platform Builder
    ...
  wince_build/         - WinCE debug build output (EXEs, DLLs, PDBs)
    coredll.dll
    coredll.pdb
    ...
```

## What to Put Here

- **Platform Builder** 
- **WinCE debug build** (ARMv4/ARMv4I): Debug EXEs and PDBs useful for reverse engineering with IDA/Ghidra when thunking new APIs.
- **WinCE test apps**: ARM PE executables for testing the emulator.
