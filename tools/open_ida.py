"""open_ida.py -- Open PE files in IDA with autonomous mode + ida_server.

Opens new PE files (no existing .i64) in IDA with -A (autonomous mode) which
auto-accepts all dialogs (PE format, PDB loading). After analysis completes,
saves the DB and starts the ida_server.py HTTP API.

Usage:
    python open_ida.py file.dll                 Open a single file
    python open_ida.py path/to/directory/       Open all new PEs in directory
    python open_ida.py --all path/to/directory/  Open ALL PEs (even with existing .i64)
    python open_ida.py --wait file.dll          Wait for analysis + server registration
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
IDA_EXE = Path(r"C:\Program Files\IDA Professional 9.0\ida.exe")
IDA_INIT_SCRIPT = SCRIPT_DIR / "ida_init_and_serve.py"
REGISTRY_DIR = Path.home() / ".ida-mcp" / "instances"

PE_EXTENSIONS = {".dll", ".exe"}


def find_pe_files(directory, include_existing=False):
    """Find PE files in directory. Skip those with existing .i64 unless forced."""
    directory = Path(directory)
    files = []
    for f in sorted(directory.iterdir()):
        if f.suffix.lower() not in PE_EXTENSIONS:
            continue
        i64 = f.parent / (f.name + ".i64")
        if i64.exists() and not include_existing:
            continue
        files.append(f)
    return files


def open_in_ida(pe_path):
    """Launch IDA in autonomous mode with the init+serve script."""
    pe_path = Path(pe_path).resolve()
    print(f"  Opening: {pe_path.name}")
    subprocess.Popen([
        str(IDA_EXE),
        "-A",                           # autonomous mode — no dialogs
        f"-S{IDA_INIT_SCRIPT}",         # wait for analysis, save, start server
        str(pe_path),
    ])


def wait_for_registration(pe_path, timeout=120):
    """Wait until the IDA instance registers in ~/.ida-mcp/instances/."""
    pe_name = Path(pe_path).name.lower()
    start = time.time()
    while time.time() - start < timeout:
        if REGISTRY_DIR.is_dir():
            for f in REGISTRY_DIR.glob("*.json"):
                try:
                    data = json.loads(f.read_text())
                    if pe_name in data.get("instance_id", "").lower():
                        return data.get("port")
                except (json.JSONDecodeError, OSError):
                    pass
        time.sleep(2)
    return None


def main():
    parser = argparse.ArgumentParser(description="Open PE files in IDA (autonomous mode)")
    parser.add_argument("path", help="PE file or directory of PE files")
    parser.add_argument("--all", action="store_true",
                        help="Open ALL PEs, even those with existing .i64 databases")
    parser.add_argument("--wait", action="store_true",
                        help="Wait for analysis completion and server registration")
    parser.add_argument("--stagger", type=float, default=3.0,
                        help="Seconds between launching IDA instances (default: 3)")
    args = parser.parse_args()

    if not IDA_EXE.exists():
        print(f"ERROR: IDA not found at {IDA_EXE}")
        sys.exit(1)

    target = Path(args.path)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = find_pe_files(target, include_existing=args.all)
        if not files:
            print(f"No new PE files in {target}" +
                  (" (use --all to re-open existing)" if not args.all else ""))
            return
    else:
        print(f"ERROR: {target} not found")
        sys.exit(1)

    print(f"Opening {len(files)} file(s) in IDA (autonomous mode)...")
    for i, f in enumerate(files):
        open_in_ida(f)
        if i < len(files) - 1:
            time.sleep(args.stagger)

    if args.wait:
        print(f"\nWaiting for IDA analysis and server registration...")
        for f in files:
            port = wait_for_registration(f)
            if port:
                print(f"  {f.name} → port {port}")
            else:
                print(f"  {f.name} — timed out waiting for registration")

    print("\nDone.")


if __name__ == "__main__":
    main()
