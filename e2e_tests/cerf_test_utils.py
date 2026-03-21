"""Shared utilities for CERF e2e tests.
Log-driven testing: poll the log file for expected patterns with timeouts."""
import subprocess, time, os, sys, re

CERF = r"Z:\build\Release\x64\cerf.exe"
REGISTRY = "Z:/build/Release/x64/devices/wince5/registry.reg"
INTERACT = "python3 Z:/tools/interact.py"
DEFAULT_TIMEOUT = 30  # seconds


class CerfTestRunner:
    """Manages cerf.exe lifecycle and log-driven assertions."""

    def __init__(self, log_path, log_categories="API"):
        self.log_path = log_path
        self.log_categories = log_categories
        self.proc = None
        self.log_file = None
        self._last_check_pos = 0

    def start(self):
        """Kill existing cerf, delete stale registry, start fresh."""
        subprocess.run(["taskkill", "/f", "/im", "cerf.exe"], capture_output=True)
        time.sleep(1)
        if os.path.exists(REGISTRY):
            os.remove(REGISTRY)
        self.log_file = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [CERF, "--flush-outputs", f"--log={self.log_categories}"],
            stdout=self.log_file, stderr=self.log_file, cwd="Z:/")
        print(f"  cerf started PID={self.proc.pid}")

    def stop(self):
        """Kill cerf."""
        if self.proc:
            self.proc.kill()
            self.proc = None
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def click(self, x, y):
        os.system(f"{INTERACT} click {x} {y}")

    def dclick(self, x, y):
        os.system(f"{INTERACT} dclick {x} {y}")

    def rclick(self, x, y):
        os.system(f"{INTERACT} rclick {x} {y}")

    def move(self, x, y):
        os.system(f"{INTERACT} move {x} {y}")

    def type_text(self, text):
        os.system(f"{INTERACT} type {text}")

    def key(self, k):
        os.system(f"{INTERACT} key {k}")

    def screenshot(self, path=None):
        if path:
            os.system(f"{INTERACT} screenshot --file {path}")
        else:
            os.system(f"{INTERACT} screenshot")

    def mark(self):
        """Mark current log position. Subsequent wait_for_log searches from here."""
        try:
            self._last_check_pos = os.path.getsize(self.log_path)
        except:
            self._last_check_pos = 0

    def _match(self, line, pattern, use_regex):
        if use_regex:
            return re.search(pattern, line) is not None
        return pattern in line

    def wait_for_log(self, pattern, timeout=DEFAULT_TIMEOUT, since_mark=True, regex=False):
        """Wait until `pattern` appears in the log. Returns the matching line.
        If since_mark=True, only searches lines added after the last mark().
        If regex=True, uses re.search instead of plain string match.
        Raises TimeoutError if not found within timeout seconds."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                with open(self.log_path, "r", errors="replace") as f:
                    if since_mark:
                        f.seek(self._last_check_pos)
                    for line in f:
                        if self._match(line, pattern, regex):
                            return line.strip()
            except:
                pass
            time.sleep(0.3)
        raise TimeoutError(f"Timed out waiting for '{pattern}' in log ({timeout}s)")

    def check_log(self, pattern, since_mark=True, regex=False):
        """Check if pattern exists in log (non-blocking). Returns bool."""
        try:
            with open(self.log_path, "r", errors="replace") as f:
                if since_mark:
                    f.seek(self._last_check_pos)
                for line in f:
                    if self._match(line, pattern, regex):
                        return True
        except:
            pass
        return False


def step(msg):
    """Print a test step."""
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}")


def passed(msg=""):
    print(f"  PASS {msg}")


def failed(msg=""):
    print(f"  FAIL {msg}")
    sys.exit(1)
