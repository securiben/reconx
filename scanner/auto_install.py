"""
Auto-installer for external tools used by ReconX scanners.
Attempts to install missing tools automatically before scanning.
Designed for Kali Linux (apt-first strategy).
"""

import os
import sys
import shutil
import subprocess
import platform
import threading
import time


# ─── Progress Bar ─────────────────────────────────────────────────────────────

class _ProgressBar:
    """Animated progress bar that runs in a background thread."""

    def __init__(self, label: str):
        self.label = label
        self._stop = threading.Event()
        self._thread = None
        self._success = None

    def start(self):
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    @staticmethod
    def _read_net_bytes():
        """Read total rx+tx bytes from /proc/net/dev (Linux only)."""
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            total = 0
            for line in lines[2:]:  # skip header
                parts = line.split()
                iface = parts[0].rstrip(":")
                if iface == "lo":
                    continue
                rx = int(parts[1])
                tx = int(parts[9])
                total += rx + tx
            return total
        except Exception:
            return 0

    @staticmethod
    def _fmt_speed(bps: float) -> str:
        """Human-readable speed string."""
        if bps <= 0:
            return ""
        kbps = bps / 1024
        if kbps >= 1024:
            return f"{kbps / 1024:.1f} MB/s"
        if kbps >= 1:
            return f"{kbps:.0f} KB/s"
        return f"{bps:.0f} B/s"

    def _animate(self):
        bar_width = 30
        progress = 0.0
        last_net = self._read_net_bytes()
        last_time = time.time()
        speed = 0.0
        while not self._stop.is_set():
            remaining = 92.0 - progress
            if remaining > 0:
                step = max(0.3, remaining * 0.06)
                progress = min(progress + step, 92.0)

            # Calculate network speed from /proc/net/dev
            now = time.time()
            dt = now - last_time
            if dt >= 0.8:
                cur_net = self._read_net_bytes()
                if cur_net > 0 and last_net > 0:
                    speed = (cur_net - last_net) / dt
                last_net = cur_net
                last_time = now

            speed_str = self._fmt_speed(speed)
            speed_display = f" \033[36m↓ {speed_str}\033[0m" if speed_str else ""

            filled = int(bar_width * progress / 100)
            bar = "\033[92m━\033[0m" * filled + "\033[90m━\033[0m" * (bar_width - filled)
            sys.stdout.write(
                f"\r\033[96m[*]\033[0m {self.label} [{bar}] \033[93m{progress:5.1f}%\033[0m{speed_display}   "
            )
            sys.stdout.flush()
            self._stop.wait(0.15)

        # Final state — use \033[K (erase to end of line) to clear leftover chars
        if self._success:
            bar = "\033[92m━\033[0m" * bar_width
            sys.stdout.write(
                f"\r\033[92m[✓]\033[0m {self.label} [{bar}] \033[92m100.0%\033[0m\033[K\n"
            )
        else:
            filled = int(bar_width * 0.92)
            bar = "\033[91m━\033[0m" * filled + "\033[90m━\033[0m" * (bar_width - filled)
            sys.stdout.write(
                f"\r\033[91m[✗]\033[0m {self.label} [{bar}] \033[91mGAGAL\033[0m\033[K\n"
            )
        sys.stdout.flush()

    def finish(self, success: bool):
        self._success = success
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


def _run(cmd: str, label: str = "", shell: bool = True, timeout: int = 300) -> bool:
    """Run an install command with animated progress bar and live speed."""
    display = label or cmd
    bar = _ProgressBar(display)
    bar.start()
    try:
        proc = subprocess.Popen(
            cmd, shell=shell,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        output_lines: list = []

        def _reader():
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                try:
                    output_lines.append(chunk.decode("utf-8", errors="replace"))
                except Exception:
                    pass

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        proc.wait(timeout=timeout)
        reader_thread.join(timeout=5)

        success = proc.returncode == 0
        bar.finish(success)
        if not success and output_lines:
            full = "".join(output_lines)
            for line in full.strip().splitlines()[-3:]:
                print(f"\033[90m    {line}\033[0m")
        if success:
            _rehash_path()
        return success
    except subprocess.TimeoutExpired:
        proc.kill()
        bar.finish(False)
        print(f"\033[90m    Install timed out after {timeout}s\033[0m")
        return False
    except Exception as e:
        bar.finish(False)
        print(f"\033[90m    {e}\033[0m")
        return False


# Directories where Go / pdtm / PD tools may live
_EXTRA_BIN_DIRS = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.pdtm/go/bin"),
    os.path.expanduser("~/.local/bin"),
]


def _rehash_path():
    """Refresh PATH lookup cache after installing a new binary."""
    for extra in _EXTRA_BIN_DIRS:
        if os.path.isdir(extra) and extra not in os.environ.get("PATH", ""):
            os.environ["PATH"] = extra + os.pathsep + os.environ.get("PATH", "")


def _persist_path():
    """Append extra bin dirs to ~/.bashrc and ~/.zshrc if not already there."""
    export_line_tpl = 'export PATH="{}:$PATH"'
    for rc in [os.path.expanduser("~/.bashrc"), os.path.expanduser("~/.zshrc")]:
        if not os.path.isfile(rc):
            continue
        try:
            content = open(rc, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        lines_to_add = []
        for d in _EXTRA_BIN_DIRS:
            if not os.path.isdir(d):
                continue
            if d in content:
                continue
            lines_to_add.append(export_line_tpl.format(d))
        if lines_to_add:
            try:
                with open(rc, "a", encoding="utf-8") as f:
                    f.write("\n# ReconX — auto-added PD tool paths\n")
                    for ln in lines_to_add:
                        f.write(ln + "\n")
            except Exception:
                pass


def _has_go() -> bool:
    _rehash_path()
    return shutil.which("go") is not None


def _has_pip() -> bool:
    return shutil.which("pip3") is not None or shutil.which("pip") is not None


def _pip_cmd() -> str:
    return "pip3" if shutil.which("pip3") else "pip"


# ─── ProjectDiscovery tools via pdtm ─────────────────────────────────────────

_pdtm_ran = False  # Only run pdtm -ia once per session

PD_TOOLS = {"httpx", "nuclei", "katana", "subfinder", "naabu", "dnsx", "uncover", "notify", "pdtm"}


def _ensure_golang() -> bool:
    """Install golang if not present."""
    if _has_go():
        return True
    return _run("sudo apt-get install -y golang", label="golang (apt)")


def _ensure_pdtm() -> bool:
    """Install pdtm via go install if not present."""
    _rehash_path()
    if shutil.which("pdtm"):
        return True
    if not _ensure_golang():
        return False
    success = _run(
        "go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest",
        label="pdtm (go install)",
        timeout=300,
    )
    if success:
        _rehash_path()
        _persist_path()
    return success


def _run_pdtm_install_all() -> bool:
    """Run pdtm -ia to install all ProjectDiscovery tools at once."""
    global _pdtm_ran
    if _pdtm_ran:
        return True
    if not _ensure_pdtm():
        return False
    _rehash_path()
    pdtm = shutil.which("pdtm")
    if not pdtm:
        return False
    success = _run(
        f"{pdtm} -ia",
        label="pdtm -ia (install all PD tools)",
        timeout=600,
    )
    if success:
        _pdtm_ran = True
        _rehash_path()
        _persist_path()
    return success


def _install_pd_tool(tool_name: str) -> bool:
    """Install a ProjectDiscovery tool — only runs pdtm -ia if tool is missing."""
    _rehash_path()
    if shutil.which(tool_name):
        return True
    # Tool not found — install via pdtm
    _run_pdtm_install_all()
    _rehash_path()
    return shutil.which(tool_name) is not None


# ─── Tool-specific installers (Kali Linux) ───────────────────────────────────

def install_httpx() -> bool:
    """Install ProjectDiscovery httpx via pdtm."""
    return _install_pd_tool("httpx")


def install_nuclei() -> bool:
    """Install ProjectDiscovery nuclei via pdtm."""
    return _install_pd_tool("nuclei")


def install_katana() -> bool:
    """Install ProjectDiscovery katana via pdtm."""
    return _install_pd_tool("katana")


def install_nmap() -> bool:
    """Install nmap."""
    return _run("sudo apt-get install -y nmap", label="nmap (apt)")


def install_enum4linux() -> bool:
    """Install enum4linux."""
    return _run("apt-get install -y enum4linux", label="enum4linux (apt)")


def install_smbclient() -> bool:
    """Install smbclient."""
    return _run("sudo apt-get install -y smbclient", label="smbclient (apt)")


def install_netexec() -> bool:
    """Install NetExec (nxc)."""
    if _run("sudo apt-get install -y netexec", label="netexec (apt)"):
        return True
    if _has_pip():
        return _run(f"{_pip_cmd()} install netexec", label="netexec (pip)")
    return False


def install_crackmapexec() -> bool:
    """Install CrackMapExec."""
    if _run("sudo apt-get install -y crackmapexec", label="crackmapexec (apt)"):
        return True
    if _has_pip():
        return _run(f"{_pip_cmd()} install crackmapexec", label="crackmapexec (pip)")
    return False


def install_wpscan() -> bool:
    """Install WPScan."""
    if _run("sudo apt-get install -y wpscan", label="wpscan (apt)"):
        return True
    if shutil.which("gem"):
        return _run("gem install wpscan", label="wpscan (gem)")
    return False


def install_metasploit() -> bool:
    """Install Metasploit Framework."""
    if _run(
        "sudo apt-get install -y metasploit-framework",
        label="metasploit-framework (apt)",
        timeout=600,
    ):
        return True
    return _run(
        "curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/"
        "master/config/templates/metasploit-framework-wrappers/msfupdate.erb "
        "> /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall",
        label="metasploit (installer)",
        timeout=600,
    )


def install_dirsearch() -> bool:
    """Install dirsearch directory brute-force tool."""
    if _run("sudo apt-get install -y dirsearch", label="dirsearch (apt)"):
        return True
    return _run("pip3 install dirsearch", label="dirsearch (pip3)")


# ─── Unified auto-install dispatcher ─────────────────────────────────────────

# Map of binary name → installer function
TOOL_INSTALLERS = {
    "httpx": install_httpx,
    "nuclei": install_nuclei,
    "katana": install_katana,
    "nmap": install_nmap,
    "enum4linux": install_enum4linux,
    "enum4linux-ng": install_enum4linux,
    "smbclient": install_smbclient,
    "nxc": install_netexec,
    "netexec": install_netexec,
    "crackmapexec": install_crackmapexec,
    "cme": install_crackmapexec,
    "wpscan": install_wpscan,
    "msfconsole": install_metasploit,
    "dirsearch": install_dirsearch,
}


def ensure_tool(tool_name: str) -> bool:
    """
    Check if a tool is installed; if not, attempt auto-install.
    Returns True if tool is available after check/install.
    """
    if shutil.which(tool_name):
        return True

    installer = TOOL_INSTALLERS.get(tool_name)
    if installer is None:
        return False

    success = installer()
    if success:
        _rehash_path()
        return shutil.which(tool_name) is not None
    return False
