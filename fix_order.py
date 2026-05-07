"""
Reorder direct mode pipeline:
  BEFORE: CME → nuclei → wpscan → katana → feroxbuster → stats → netexec → service-misconfig → _output
  AFTER:  CME → service-misconfig → nuclei → wpscan → katana → feroxbuster → stats → netexec → _output
"""

with open('engine.py', encoding='utf-8') as f:
    content = f.read()

# ── Marker strings ──────────────────────────────────────────────────────────

AFTER_CME = (
    "        elif not self.cme_scanner.available and self.result.nmap_available:\n"
    "            print(\n"
    "                f\"\\033[93m[!]\\033[0m crackmapexec/nxc not found \u2013 skipping protocol enumeration\"\n"
    "            )\n"
    "            print(\n"
    "                f\"\\033[90m    Install: pip install crackmapexec | or: https://github.com/byt3bl33d3r/CrackMapExec\\033[0m\\n\"\n"
    "            )\n"
    "\n"
    "        # \u2500\u2500 Nuclei vulnerability scanning (direct mode) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
)

MISCONFIG_START = "        # \u2500\u2500 Service misconfiguration checks (direct mode) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
MISCONFIG_END   = "            elif service_results is None:\n                print(f\"\\033[93m[!]\\033[0m service-misconfig: skipped by user\\n\")\n\n        self._output()"

AFTER_NETEXEC = (
    "        elif not self.netexec_module_scanner.available and self.result.nmap_available:\n"
    "            print(\n"
    "                f\"\\033[93m[!]\\033[0m nxc/netexec not found \u2013 skipping module scan\"\n"
    "            )\n"
    "            print(\n"
    "                f\"\\033[90m    Install: pip install netexec\\033[0m\\n\"\n"
    "            )\n"
)

# ── Find service-misconfig block ────────────────────────────────────────────

start_idx = content.find('\n' + MISCONFIG_START)
if start_idx == -1:
    raise ValueError("Cannot find service-misconfig block start")

end_marker = MISCONFIG_END
end_idx = content.find(end_marker, start_idx)
if end_idx == -1:
    raise ValueError("Cannot find service-misconfig block end")

# The block ends AFTER the elif/print lines but BEFORE \n\n        self._output()
# end_idx points to the start of the end_marker; we want to include up to "\n\n"
end_idx_full = end_idx + len(end_marker)
# end_idx_full now points past "self._output()" part of MISCONFIG_END

# Extract the block (with its leading newline)
misconfig_block = content[start_idx : end_idx_full - len("\n\n        self._output()")]
# misconfig_block starts with '\n        # ── Service misconfiguration...' and ends with the elif/print

print(f"Extracted misconfig block: {len(misconfig_block)} chars")
print(f"  First 80 chars: {repr(misconfig_block[:80])}")
print(f"  Last  80 chars: {repr(misconfig_block[-80:])}")

# ── Remove service-misconfig block from current location ───────────────────
# Replace the block (including trailing blank line before self._output) with nothing
content_without = content[:start_idx] + content[end_idx_full - len("\n\n        self._output()"):]

# Verify removal
if MISCONFIG_START in content_without:
    raise ValueError("Removal failed - block still present")
print("Removal verified OK")

# ── Insert after CME ────────────────────────────────────────────────────────
insert_after = (
    "        elif not self.cme_scanner.available and self.result.nmap_available:\n"
    "            print(\n"
    "                f\"\\033[93m[!]\\033[0m crackmapexec/nxc not found \u2013 skipping protocol enumeration\"\n"
    "            )\n"
    "            print(\n"
    "                f\"\\033[90m    Install: pip install crackmapexec | or: https://github.com/byt3bl33d3r/CrackMapExec\\033[0m\\n\"\n"
    "            )\n"
    "\n"
    "        # \u2500\u2500 Nuclei vulnerability scanning (direct mode) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
)

idx = content_without.find(insert_after)
if idx == -1:
    raise ValueError("Cannot find CME→nuclei anchor in modified content")

# Insert the misconfig block between CME and nuclei
insert_point = idx + len(insert_after) - len("        # \u2500\u2500 Nuclei vulnerability scanning (direct mode) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")

# misconfig_block starts with \n so we get a blank line separator naturally
content_final = content_without[:insert_point] + misconfig_block + "\n\n" + content_without[insert_point:]

# ── Verify ──────────────────────────────────────────────────────────────────
# Check service-misconfig appears once
count = content_final.count(MISCONFIG_START)
if count != 1:
    raise ValueError(f"Expected 1 occurrence of misconfig block, found {count}")

# Check order: CME before service-misconfig before nuclei
idx_cme = content_final.find("Install: pip install crackmapexec")
idx_svc = content_final.find(MISCONFIG_START)
idx_nuc = content_final.find("# \u2500\u2500 Nuclei vulnerability scanning (direct mode)")
print(f"Order check: CME at {idx_cme}, service-misconfig at {idx_svc}, nuclei at {idx_nuc}")
assert idx_cme < idx_svc < idx_nuc, "Order is wrong!"
print("Order verified: CME → service-misconfig → nuclei ✓")

# ── Write ───────────────────────────────────────────────────────────────────
with open('engine.py', 'w', encoding='utf-8') as f:
    f.write(content_final)
print(f"Written {len(content_final)} chars to engine.py")
