#!/usr/bin/env python3
"""GDB Remote Serial Protocol client for CERF ARM debugging.
Connects to cerf.exe --gdb-port and provides register/memory/breakpoint control.

Usage:
    python3 tools/debug.py [--port PORT] <command> [args...]

Commands:
    regs                     Read all ARM registers
    reg <n>                  Read register n (0-15, or 25 for cpsr)
    setreg <n> <value>       Write register n
    mem <addr> [len]         Read memory (default 64 bytes)
    writemem <addr> <hex>    Write hex bytes to memory
    break <addr>             Set breakpoint
    unbreak <addr>           Remove breakpoint
    step                     Single-step one instruction
    cont                     Continue execution
    stop                     Send Ctrl+C interrupt
    threads                  List all threads with PC/SP/LR
    thread <tid>             Select thread and show registers
    detach                   Detach from target
"""
import socket
import sys
import struct
import time

DEFAULT_PORT = 1234

REG_NAMES = [
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
    "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC", "CPSR"
]


class GdbClient:
    def __init__(self, host="localhost", port=DEFAULT_PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.sock.settimeout(10.0)
        self.no_ack = False
        # GDB protocol handshake: query stop reason to sync state
        stop = self.command("?")
        # stop is something like "S05" (SIGTRAP)

    def close(self):
        self.sock.close()

    def send_packet(self, data: str):
        cksum = sum(ord(c) for c in data) & 0xFF
        pkt = f"${data}#{cksum:02x}"
        self.sock.sendall(pkt.encode())
        if not self.no_ack:
            self.sock.recv(1)  # consume ACK

    def recv_packet(self) -> str:
        buf = b""
        # Skip to '$'
        while True:
            ch = self.sock.recv(1)
            if not ch:
                return ""
            if ch == b"$":
                break
        # Read until '#'
        while True:
            ch = self.sock.recv(1)
            if not ch:
                return ""
            if ch == b"#":
                break
            buf += ch
        self.sock.recv(2)  # consume checksum
        if not self.no_ack:
            self.sock.sendall(b"+")  # send ACK
        return buf.decode()

    def command(self, data: str) -> str:
        self.send_packet(data)
        return self.recv_packet()

    def read_regs(self) -> list:
        hex_data = self.command("g")
        regs = []
        for i in range(17):
            h = hex_data[i * 8:(i + 1) * 8]
            b = bytes.fromhex(h)
            regs.append(struct.unpack("<I", b)[0])
        return regs

    def read_mem(self, addr: int, length: int) -> bytes:
        hex_data = self.command(f"m{addr:x},{length:x}")
        return bytes.fromhex(hex_data)

    def set_break(self, addr: int):
        return self.command(f"Z0,{addr:x},4")

    def remove_break(self, addr: int):
        return self.command(f"z0,{addr:x},4")

    def step(self) -> str:
        return self.command("s")

    def cont(self):
        self.send_packet("c")

    def wait_stop(self, timeout=30.0) -> str:
        self.sock.settimeout(timeout)
        try:
            return self.recv_packet()
        except socket.timeout:
            return ""

    def interrupt(self):
        self.sock.sendall(b"\x03")

    def detach(self):
        return self.command("D")

    def list_threads(self) -> list:
        """Query thread IDs from the GDB stub."""
        resp = self.command("qfThreadInfo")
        if not resp or resp[0] != 'm':
            return []
        tids = []
        for t in resp[1:].split(","):
            t = t.strip()
            if t:
                tids.append(int(t, 16))
        return tids

    def select_thread(self, tid: int):
        """Select thread for register reads (Hg command)."""
        return self.command(f"Hg{tid:x}")


def print_regs(regs):
    for i in range(0, 16, 4):
        parts = []
        for j in range(4):
            if i + j < 16:
                parts.append(f"{REG_NAMES[i+j]:>3}=0x{regs[i+j]:08X}")
        print("  ".join(parts))
    cpsr = regs[16]
    flags = ""
    flags += "N" if cpsr & (1 << 31) else "-"
    flags += "Z" if cpsr & (1 << 30) else "-"
    flags += "C" if cpsr & (1 << 29) else "-"
    flags += "V" if cpsr & (1 << 28) else "-"
    mode = "Thumb" if cpsr & (1 << 5) else "ARM"
    print(f" CPSR=0x{cpsr:08X} [{flags} {mode}]")


def hex_dump(data: bytes, base_addr: int):
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in row)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print(f"  {base_addr + off:08X}: {hexs:<48s} {ascii_str}")


def main():
    port = DEFAULT_PORT
    args = sys.argv[1:]

    if len(args) >= 2 and args[0] == "--port":
        port = int(args[1])
        args = args[2:]

    if not args:
        print(__doc__)
        return

    cmd = args[0]
    gdb = GdbClient(port=port)

    try:
        if cmd == "regs":
            regs = gdb.read_regs()
            print_regs(regs)
        elif cmd == "reg":
            n = int(args[1])
            regs = gdb.read_regs()
            idx = n if n < 17 else 16
            print(f"{REG_NAMES[idx]}=0x{regs[idx]:08X}")
        elif cmd == "setreg":
            n = int(args[1])
            val = int(args[2], 0)
            b = struct.pack("<I", val).hex()
            print(gdb.command(f"P{n:x}={b}"))
        elif cmd == "mem":
            addr = int(args[1], 0)
            length = int(args[2], 0) if len(args) > 2 else 64
            data = gdb.read_mem(addr, length)
            hex_dump(data, addr)
        elif cmd == "writemem":
            addr = int(args[1], 0)
            hex_data = args[2]
            print(gdb.command(f"M{addr:x},{len(hex_data)//2:x}:{hex_data}"))
        elif cmd == "break":
            addr = int(args[1], 0)
            print(gdb.set_break(addr))
        elif cmd == "unbreak":
            addr = int(args[1], 0)
            print(gdb.remove_break(addr))
        elif cmd == "step":
            reply = gdb.step()
            print(f"Stop: {reply}")
            regs = gdb.read_regs()
            print_regs(regs)
        elif cmd == "cont":
            gdb.cont()
            print("Continuing... (Ctrl+C or 'stop' to interrupt)")
            reply = gdb.wait_stop(timeout=60)
            if reply:
                print(f"Stop: {reply}")
                regs = gdb.read_regs()
                print_regs(regs)
            else:
                print("(timed out waiting for stop)")
        elif cmd == "stop":
            gdb.interrupt()
            reply = gdb.wait_stop(timeout=5)
            if reply:
                print(f"Stop: {reply}")
                regs = gdb.read_regs()
                print_regs(regs)
        elif cmd == "threads":
            tids = gdb.list_threads()
            print(f"Threads ({len(tids)}):")
            for tid in tids:
                gdb.select_thread(tid)
                regs = gdb.read_regs()
                print(f"  tid={tid} PC=0x{regs[15]:08X} SP=0x{regs[13]:08X} LR=0x{regs[14]:08X}")
        elif cmd == "thread":
            tid = int(args[1], 0)
            print(gdb.select_thread(tid))
            regs = gdb.read_regs()
            print_regs(regs)
        elif cmd == "detach":
            print(gdb.detach())
        else:
            print(f"Unknown command: {cmd}")
            print(__doc__)
    finally:
        gdb.close()


if __name__ == "__main__":
    main()
