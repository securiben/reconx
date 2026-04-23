"""
AI Analyst for ReconX — Powered by Gemini 2.5 Flash.

Consumes the full scan result and produces an autonomous pentest analysis:
  • Executive Summary
  • Critical & High Findings (prioritised)
  • Lateral-movement / attack paths
  • Exploitation recommendations (with PoC commands)
  • Remediation checklist

API: Google Generative AI (Gemini 2.5 Flash)
Endpoint: https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent
"""

import json
import ssl
import time
import textwrap
from typing import Optional, Dict, Any

try:
    import urllib.request
    import urllib.error
    _HTTP_OK = True
except ImportError:
    _HTTP_OK = False

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2;37m"
PURPLE = "\033[95m"
WHITE  = "\033[1;97m"

GEMINI_MODEL   = "gemini-2.5-flash-preview-04-17"
GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

_SYSTEM_PROMPT = """You are a senior penetration tester conducting an authorized on-site network security assessment.
You have just received automated reconnaissance output from ReconX.
Your job is NOT just to report — you must ACT as an on-site consultant and tell the operator EXACTLY what to do next.

RULES:
- Write in Indonesian (Bahasa Indonesia) for narrative sections, but keep tool commands and technical terms in English.
- Every command must be copy-paste ready. Use real IPs from the scan data.
- Prioritise by impact: domain compromise > credential access > data exposure > info disclosure.
- If credentials were found, show the full lateral movement chain.
- If nothing critical was found, still recommend the next manual steps.
- Always think like an attacker: what would YOU do next with this data?

FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS (do not skip any section):

═══════════════════════════════════════════════════════════════
 [1] RINGKASAN EKSEKUTIF
═══════════════════════════════════════════════════════════════
<3-5 kalimat: postur keamanan, temuan paling kritis, risiko bisnis>
Jumlah host: X | Port terbuka: X | Kredensial ditemukan: X | Vuln kritis: X

═══════════════════════════════════════════════════════════════
 [2] TEMUAN KRITIS & TINGGI
═══════════════════════════════════════════════════════════════
Untuk setiap temuan kritis/tinggi gunakan format:

[KRITIS/TINGGI] NAMA TEMUAN
  Host        : <IP> (<hostname jika ada>)
  Bukti       : <apa yang ditemukan oleh scanner>
  CVE/Ref     : <CVE jika ada>
  Dampak      : <apa yang bisa dilakukan attacker>
  Verifikasi  :
      <command untuk konfirmasi manual>
  Eksploitasi :
      <command eksploitasi — nxc/netexec/impacket/msf/python>
  Langkah lanjut setelah exploit:
      <apa yang harus dilakukan setelah berhasil masuk>

═══════════════════════════════════════════════════════════════
 [3] JALUR SERANGAN (ATTACK PATH)
═══════════════════════════════════════════════════════════════
Gambarkan 1-3 rantai serangan realistis dari awal sampai domain compromise.
Setiap step harus ada command-nya.

CONTOH FORMAT:
  Step 1: [akses awal] → nxc smb 10.x.x.x -u guest -p '' --shares
  Step 2: [eskalasi]   → impacket-secretsdump ...
  Step 3: [lateral]    → nxc smb 10.x.x.x -u admin -H <hash> --sam
  Step 4: [DA]         → impacket-psexec domain/admin@10.x.x.x

═══════════════════════════════════════════════════════════════
 [4] REKOMENDASI MANUAL TESTING SELANJUTNYA
═══════════════════════════════════════════════════════════════
Berikan daftar hal yang HARUS dilakukan pentest manual setelah scan otomatis ini.
Urutkan dari yang paling penting. Sertakan command siap pakai.

Contoh kategori:
  [AD/Domain]    → BloodHound collection, Kerberoasting, AS-REP Roasting
  [Web]          → SQLi manual, auth bypass, file upload, SSRF
  [Network]      → MITM/responder, NTLM relay, ARP poisoning
  [Credential]   → Password spray, credential stuffing dengan user yang ditemukan
  [Post-Exploit] → Persistence, data exfil, screenshot, keylogger
  [Compliance]   → Cek password policy, patching status, backup keamanan

Format per item:
  [PRIORITAS] Nama aksi
    Kenapa: <alasan berdasarkan temuan>
    Command: <command siap pakai dengan IP asli dari scan>

═══════════════════════════════════════════════════════════════
 [5] TOOLS YANG DIREKOMENDASIKAN
═══════════════════════════════════════════════════════════════
Berikan daftar tools tambahan yang relevan dengan temuan di jaringan ini.
Format:
  [TOOL] nama-tool
    Fungsi  : <untuk apa>
    Install : <cara install>
    Command : <command langsung untuk target ini>

Pertimbangkan: BloodHound, Impacket suite, Responder, CrackMapExec modules,
Certipy (ADCS), ldapdomaindump, kerbrute, hashcat, mimikatz, ligolo, chisel,
evil-winrm, PowerView, ADExplorer, dll.

═══════════════════════════════════════════════════════════════
 [6] TEMUAN MEDIUM & INFORMASIONAL
═══════════════════════════════════════════════════════════════
Daftar temuan medium/low/info yang tetap perlu diperhatikan.

═══════════════════════════════════════════════════════════════
 [7] CHECKLIST REMEDIASI
═══════════════════════════════════════════════════════════════
Daftar bernomor tindakan perbaikan, urut dari prioritas tertinggi.
Sertakan referensi patch/KB jika ada.

Gunakan data IP asli dari scan. Jadilah spesifik dan teknikal.
"""


def _build_context(result_dict: Dict[str, Any], target: str) -> str:
    """Convert ScanResult dict into a compact, LLM-friendly context string."""
    lines = [
        f"TARGET: {target}",
        f"SCAN DATE: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
        "",
    ]

    # ── Nmap results ──────────────────────────────────────────────────────
    nmap = result_dict.get("nmap_results") or {}
    if nmap:
        lines.append("=== OPEN PORTS / SERVICES (nmap) ===")
        for ip, host in nmap.items():
            if isinstance(host, dict):
                ports = host.get("ports", [])
                hostname = host.get("hostname", "")
                os_info = host.get("os_info", "")
                host_label = f"{ip}"
                if hostname:
                    host_label += f" ({hostname})"
                if os_info:
                    host_label += f" [{os_info}]"
                open_ports = [
                    f"{p.get('port','?')}/{p.get('protocol','tcp')} {p.get('service','')}"
                    for p in ports if p.get("state") == "open"
                ]
                if open_ports:
                    lines.append(f"  {host_label}: {', '.join(open_ports)}")
        lines.append("")

    # ── Enum4linux ─────────────────────────────────────────────────────────
    e4l = result_dict.get("enum4linux_results") or {}
    if e4l:
        lines.append("=== ENUM4LINUX (SMB/AD ENUMERATION) ===")
        for ip, data in e4l.items():
            if isinstance(data, dict):
                users = data.get("users", [])
                shares = data.get("shares", [])
                null_sess = data.get("null_session", False)
                domain = data.get("domain", "")
                pw_policy = data.get("password_policy", {})
                parts = []
                if null_sess:
                    parts.append("NULL SESSION ALLOWED")
                if domain:
                    parts.append(f"domain={domain}")
                if users:
                    parts.append(f"users={users[:20]}")
                if shares:
                    parts.append(f"shares={[s.get('name','') for s in shares[:10]]}")
                if pw_policy:
                    parts.append(f"pw_policy={pw_policy}")
                if parts:
                    lines.append(f"  {ip}: {'; '.join(str(p) for p in parts)}")
        lines.append("")

    # ── CME results ────────────────────────────────────────────────────────
    cme = result_dict.get("cme_results") or {}
    if cme:
        lines.append("=== CME / NETEXEC PROTOCOL ENUMERATION ===")
        for proto, pdata in cme.items():
            if isinstance(pdata, dict):
                hosts = pdata.get("host_results", [])
                for h in hosts:
                    if isinstance(h, dict):
                        ip = h.get("ip", "?")
                        hostname = h.get("hostname", "")
                        os_info = h.get("os_info", "")
                        signing = h.get("signing", "")
                        domain = h.get("domain", "")
                        label = f"{ip}"
                        if hostname:
                            label += f" ({hostname})"
                        if os_info:
                            label += f" [{os_info}]"
                        extras = []
                        if signing:
                            extras.append(f"signing={signing}")
                        if domain:
                            extras.append(f"domain={domain}")
                        ext_str = f" — {', '.join(extras)}" if extras else ""
                        lines.append(f"  [{proto.upper()}] {label}{ext_str}")
        lines.append("")

    # ── NetExec Module findings ────────────────────────────────────────────
    nxcmod = result_dict.get("netexec_module_results") or {}
    if nxcmod:
        lines.append("=== NETEXEC MODULE SCAN (VULN CHECKS) ===")
        for proto, mdata in nxcmod.items():
            if isinstance(mdata, dict):
                findings = mdata.get("findings", [])
                for f in findings:
                    if isinstance(f, dict) and f.get("status") in ("VULNERABLE", "INFO"):
                        lines.append(
                            f"  [{f.get('status')}] {proto.upper()}/{f.get('module')} "
                            f"on {f.get('ip')} — {f.get('detail','')}"
                        )
        lines.append("")

    # ── SMB Brute credentials ──────────────────────────────────────────────
    smb_brute = result_dict.get("smb_brute_results") or {}
    if smb_brute:
        lines.append("=== SMB CREDENTIALS FOUND ===")
        for ip, bdata in smb_brute.items():
            if isinstance(bdata, dict):
                creds = bdata.get("credentials", [])
                for c in creds:
                    if isinstance(c, dict):
                        dom = f"{c.get('domain','')}\\\\".lstrip("\\\\") if c.get("domain") else ""
                        pwn = " [Pwn3d!]" if c.get("pwned") else ""
                        lines.append(
                            f"  {ip} → {dom}{c.get('username','')}:{c.get('password','')}{pwn}"
                        )
        lines.append("")

    # ── SSH/FTP/MongoDB/Postgres credentials ──────────────────────────────
    for section, key in [
        ("SSH", "ssh_login_results"),
        ("FTP", "ftp_login_results"),
        ("MONGODB", "mongodb_login_results"),
        ("POSTGRESQL", "postgres_login_results"),
    ]:
        res = result_dict.get(key) or {}
        if res:
            cred_lines = []
            for ip, data in res.items():
                if isinstance(data, dict):
                    for c in data.get("credentials", []):
                        if isinstance(c, dict):
                            anon = " [ANON]" if c.get("anonymous") else ""
                            cred_lines.append(
                                f"  {ip}:{c.get('port','')} → "
                                f"{c.get('username','')}:{c.get('password','')}{anon}"
                            )
            if cred_lines:
                lines.append(f"=== {section} CREDENTIALS ===")
                lines.extend(cred_lines)
                lines.append("")

    # ── SNMP community strings ─────────────────────────────────────────────
    snmp_login = result_dict.get("snmp_login_results") or {}
    if snmp_login:
        lines.append("=== SNMP COMMUNITY STRINGS ===")
        for ip, data in snmp_login.items():
            if isinstance(data, dict):
                for c in data.get("credentials", []):
                    if isinstance(c, dict):
                        rw = " [READ-WRITE!]" if "write" in c.get("access_level","").lower() else ""
                        lines.append(
                            f"  {ip} community={c.get('community','')} "
                            f"({c.get('access_level','')}){rw}"
                        )
        lines.append("")

    # ── Nuclei vulnerabilities ─────────────────────────────────────────────
    nuclei = result_dict.get("nuclei_results") or []
    if nuclei:
        lines.append("=== NUCLEI VULNERABILITY FINDINGS ===")
        for finding in nuclei[:50]:  # cap to 50 to avoid token overflow
            if isinstance(finding, dict):
                sev = finding.get("severity", "info").upper()
                name = finding.get("name") or finding.get("template_id", "?")
                host = finding.get("host") or finding.get("url", "?")
                matched = finding.get("matched_at") or finding.get("matched", "")
                desc = finding.get("description") or finding.get("info", {}).get("description", "")
                lines.append(
                    f"  [{sev}] {name} on {host}"
                    + (f" — {matched}" if matched else "")
                    + (f" | {desc[:100]}" if desc else "")
                )
        lines.append("")

    # ── SMBClient accessible shares ────────────────────────────────────────
    smbclient = result_dict.get("smbclient_results") or {}
    if smbclient:
        lines.append("=== SMBCLIENT ACCESSIBLE SHARES ===")
        for ip, data in smbclient.items():
            if isinstance(data, dict):
                for share in data.get("shares", []):
                    if isinstance(share, dict) and share.get("accessible"):
                        perms = share.get("permissions", "?")
                        lines.append(
                            f"  {ip}: \\\\{ip}\\{share.get('name','')} [{perms}]"
                            + (f" — {share.get('files_count',0)} files" if share.get("files_count") else "")
                        )
        lines.append("")

    # ── Subdomains summary ─────────────────────────────────────────────────
    subdomains = result_dict.get("subdomains") or []
    if subdomains:
        alive = [s for s in subdomains if isinstance(s, dict) and s.get("is_alive")]
        lines.append(f"=== SUBDOMAINS ({len(subdomains)} total, {len(alive)} alive) ===")
        # List alive with interesting first
        interesting = [s for s in alive if s.get("interesting")]
        if interesting:
            lines.append("  Interesting subdomains:")
            for s in interesting[:20]:
                reason = s.get("interesting_reason", "")
                lines.append(
                    f"    {s.get('hostname','')} [{s.get('http_status','')}] "
                    f"{f'— {reason}' if reason else ''}"
                )
        lines.append("")

    # ── Takeover results ───────────────────────────────────────────────────
    takeover = result_dict.get("takeover_results") or []
    vuln_takeovers = [t for t in takeover if isinstance(t, dict) and t.get("status") == "VULNERABLE"]
    if vuln_takeovers:
        lines.append("=== SUBDOMAIN TAKEOVER CANDIDATES ===")
        for t in vuln_takeovers:
            lines.append(
                f"  {t.get('subdomain','')} → {t.get('provider','')} "
                f"(CNAME: {t.get('cname','')})"
            )
        lines.append("")

    # ── Tech stack ─────────────────────────────────────────────────────────
    tech = result_dict.get("tech_matches") or []
    if tech:
        high_sev = [t for t in tech if isinstance(t, dict) and
                    t.get("severity", "").lower() in ("critical", "high")]
        if high_sev:
            lines.append("=== HIGH-SEVERITY TECH DETECTIONS ===")
            for t in high_sev[:20]:
                lines.append(
                    f"  [{t.get('severity','').upper()}] {t.get('name','')} "
                    f"on {t.get('hostname','?')} — {t.get('description','')[:80]}"
                )
            lines.append("")

    return "\n".join(lines)


class AIAnalyst:
    """
    Autonomous pentest analyst powered by Gemini 2.5 Flash.

    Usage:
        analyst = AIAnalyst(api_key="YOUR_GEMINI_KEY")
        report = analyst.analyse(scan_result_dict, target="10.10.0.0/24")
        print(report)
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.available = bool(api_key and _HTTP_OK)
        self.last_report: str = ""
        self.last_prompt_tokens: int = 0
        self.last_output_tokens: int = 0

    def analyse(self, result_dict: Dict[str, Any], target: str = "") -> Optional[str]:
        """
        Build context from scan results, send to Gemini, return formatted report.

        Returns the report string, or None on failure.
        """
        if not self.available:
            return None

        # Skip if there is nothing meaningful to analyse
        nmap = result_dict.get("nmap_results") or {}
        subdomains = result_dict.get("subdomains") or []
        nuclei = result_dict.get("nuclei_results") or []
        if not nmap and not subdomains and not nuclei:
            print(
                f"{YELLOW}[!]{RESET} {PURPLE}AI Analyst{RESET}: "
                f"no scan data found — skipping analysis"
            )
            return None

        context = _build_context(result_dict, target)

        prompt = (
            f"{_SYSTEM_PROMPT}\n\n"
            f"=== SCAN DATA ===\n"
            f"{context}\n\n"
            f"Now produce the pentest report."
        )

        print(f"\n{CYAN}[>]{RESET} {PURPLE}AI Analyst{RESET}: sending results to Gemini 2.5 Flash ...")

        report = self._call_gemini(prompt)
        if report:
            self.last_report = report
            print(
                f"{GREEN}[+]{RESET} {PURPLE}AI Analyst{RESET}: "
                f"report generated "
                f"{DIM}({self.last_output_tokens} output tokens){RESET}"
            )
        return report

    def _http_post(self, url: str, payload_dict: dict) -> Optional[str]:
        """
        POST JSON payload to url.
        Strategy:
          1. requests verify=True
          2. requests verify=False  (SSL inspection / self-signed proxy)
          3. urllib CERT_NONE       (last resort)
        """
        payload_bytes = json.dumps(payload_dict).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        # ── 1. requests with cert verification ────────────────────────────
        if _HAS_REQUESTS:
            try:
                resp = _requests.post(
                    url, data=payload_bytes, headers=headers,
                    timeout=180, verify=True,
                )
                if resp.status_code == 200:
                    return resp.text
                print(f"{YELLOW}[!]{RESET} Gemini API error {resp.status_code}: {resp.text[:200]}")
                return None
            except Exception as exc:
                _is_ssl = "SSL" in str(exc) or "ssl" in str(exc).lower() or "EOF" in str(exc)
                if _is_ssl:
                    print(
                        f"{YELLOW}[!]{RESET} SSL error detected — "
                        f"retrying without cert verification..."
                    )
                else:
                    print(f"{YELLOW}[!]{RESET} Gemini (requests) failed: {type(exc).__name__}: {str(exc)[:120]}")

            # ── 2. requests without cert verification ─────────────────────
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    resp = _requests.post(
                        url, data=payload_bytes, headers=headers,
                        timeout=180, verify=False,
                    )
                if resp.status_code == 200:
                    return resp.text
                print(f"{YELLOW}[!]{RESET} Gemini API error {resp.status_code}: {resp.text[:200]}")
                return None
            except Exception as exc:
                print(f"{YELLOW}[!]{RESET} Gemini (requests no-verify) failed: {type(exc).__name__}: {str(exc)[:120]}")

        # ── 3. urllib CERT_NONE (final fallback) ──────────────────────────
        import urllib.request
        import urllib.error

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url, data=payload_bytes, headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=180, context=ctx) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            print(f"{YELLOW}[!]{RESET} Gemini API error {exc.code}: {err_body[:200]}")
            return None
        except Exception as exc:
            print(f"{YELLOW}[!]{RESET} Gemini API request failed: {type(exc).__name__}: {str(exc)[:180]}")
            return None

    def _call_gemini(self, prompt: str) -> Optional[str]:
        """Send prompt to Gemini 2.5 Flash API and return response text."""
        payload_dict = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": 8192,
                "topP": 0.9,
            },
        }
        url = f"{GEMINI_API_URL}?key={self.api_key}"

        body = self._http_post(url, payload_dict)
        if body is None:
            return None

        try:
            data = json.loads(body)
        except Exception:
            print(f"{YELLOW}[!]{RESET} Gemini: could not parse response JSON")
            return None

        # Extract token usage
        usage = data.get("usageMetadata", {})
        self.last_prompt_tokens  = usage.get("promptTokenCount", 0)
        self.last_output_tokens  = usage.get("candidatesTokenCount", 0)

        # Extract text content
        candidates = data.get("candidates", [])
        if not candidates:
            # Check for error block
            if "error" in data:
                print(
                    f"{YELLOW}[!]{RESET} Gemini error: "
                    f"{data['error'].get('message', str(data['error']))}"
                )
            return None

        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return None

        return parts[0].get("text", "")

    def print_report(self, report: str, output_file: Optional[str] = None):
        """Pretty-print the AI report to terminal and optionally save to file."""
        separator = f"{PURPLE}{'═' * 64}{RESET}"
        header    = f"{PURPLE}{BOLD}  AI PENTEST ANALYSIS — Gemini 2.5 Flash  {RESET}"

        print(f"\n{separator}")
        print(header)
        print(separator)

        # Command prefixes that should be coloured cyan
        CMD_PREFIXES = (
            "nxc ", "netexec ", "python ", "python3 ",
            "impacket", "msf", "msfconsole", "crackmapexec ",
            "hashcat", "kerbrute", "bloodhound", "certipy",
            "evil-winrm", "responder", "ldapdomaindump",
            "Step 1:", "Step 2:", "Step 3:", "Step 4:", "Step 5:",
        )

        for line in report.splitlines():
            stripped = line.strip()

            # ── Section dividers ─────────────────────────────────────────
            if stripped.startswith("═" * 3):
                print(f"{PURPLE}{line}{RESET}")

            # ── Section titles [1]..[7] ───────────────────────────────────
            elif stripped.startswith("[1]") or stripped.startswith("[2]") \
                    or stripped.startswith("[3]") or stripped.startswith("[4]") \
                    or stripped.startswith("[5]") or stripped.startswith("[6]") \
                    or stripped.startswith("[7]"):
                print(f"{PURPLE}{BOLD}{line}{RESET}")

            # ── Severity tags ─────────────────────────────────────────────
            elif stripped.startswith("[KRITIS]") or stripped.startswith("[CRITICAL]"):
                print(f"  {RED}{BOLD}{stripped}{RESET}")
            elif stripped.startswith("[TINGGI]") or stripped.startswith("[HIGH]"):
                print(f"  {RED}{stripped}{RESET}")
            elif stripped.startswith("[MEDIUM]") or stripped.startswith("[SEDANG]"):
                print(f"  {YELLOW}{stripped}{RESET}")
            elif stripped.startswith("[LOW]") or stripped.startswith("[RENDAH]") \
                    or stripped.startswith("[INFO]"):
                print(f"  {DIM}{stripped}{RESET}")

            # ── Priority labels ───────────────────────────────────────────
            elif stripped.startswith("[PRIORITAS TINGGI]") or stripped.startswith("[P1]"):
                print(f"  {RED}{BOLD}{stripped}{RESET}")
            elif stripped.startswith("[PRIORITAS SEDANG]") or stripped.startswith("[P2]"):
                print(f"  {YELLOW}{stripped}{RESET}")
            elif stripped.startswith("[PRIORITAS RENDAH]") or stripped.startswith("[P3]"):
                print(f"  {DIM}{stripped}{RESET}")

            # ── Field labels (Host:, Bukti:, Command:, etc.) ──────────────
            elif any(stripped.startswith(lbl) for lbl in (
                "Host ", "Host:", "Bukti", "CVE", "Dampak", "Verifikasi",
                "Eksploitasi", "Langkah lanjut", "Fungsi", "Install",
                "Command", "Kenapa",
            )):
                # label bold white, rest normal
                colon_idx = stripped.find(":")
                if colon_idx > 0:
                    label = stripped[:colon_idx + 1]
                    rest  = stripped[colon_idx + 1:]
                    indent = len(line) - len(line.lstrip())
                    print(f"{' ' * indent}{WHITE}{label}{RESET}{rest}")
                else:
                    print(f"  {WHITE}{stripped}{RESET}")

            # ── Commands / tool lines ─────────────────────────────────────
            elif any(stripped.startswith(p) for p in CMD_PREFIXES):
                print(f"    {CYAN}{stripped}{RESET}")

            # ── [TOOL] blocks ─────────────────────────────────────────────
            elif stripped.startswith("[TOOL]") or stripped.startswith("[AD/") \
                    or stripped.startswith("[Web]") or stripped.startswith("[Network]") \
                    or stripped.startswith("[Credential]") or stripped.startswith("[Post-") \
                    or stripped.startswith("[Compliance]"):
                print(f"  {YELLOW}{BOLD}{stripped}{RESET}")

            # ── Bullet / numbered list items ──────────────────────────────
            elif stripped.startswith("•") or stripped.startswith("→"):
                print(f"  {WHITE}{stripped}{RESET}")
            elif stripped and stripped[0].isdigit() and len(stripped) > 2 and stripped[1] in ".):":
                print(f"  {WHITE}{stripped}{RESET}")

            # ── Default ───────────────────────────────────────────────────
            else:
                print(line)

        print(separator + "\n")

        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as fh:
                    fh.write(report)
                print(
                    f"{GREEN}[+]{RESET} AI report saved → "
                    f"{CYAN}{output_file}{RESET}"
                )
            except Exception as exc:
                print(f"{YELLOW}[!]{RESET} Could not save AI report: {exc}")
