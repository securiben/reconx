"""
Service misconfiguration scanner for SMTP, POP3, MongoDB, Docker,
Elasticsearch, etcd, Grafana, IMAP, Jenkins, Kafka, Kerberos,
Kubernetes, LDAP, Memcached, MSSQL, NetBIOS, NFS, NTP, Oracle,
PostgreSQL, RabbitMQ, RDP, Redis, TFTP, Tomcat, VNC, WebDAV, and WinRM.

Uses discovered nmap services as input and performs small read-only checks.
The scanner avoids sending SMTP DATA, avoids modifying Docker containers, and
uses MongoDB metadata commands only.
"""

import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..config import ScannerConfig


SMTP_PORTS = {25, 465, 587, 2525}
POP3_PORTS = {110, 995}
MONGODB_PORTS = {27017, 27018, 27019, 28017}
DOCKER_PORTS = {2375, 2376, 4243}
ELASTICSEARCH_PORTS = {9200, 9300}
ETCD_PORTS = {2379, 2380}
GRAFANA_PORTS = {3000}
IMAP_PORTS = {143, 993}
JENKINS_PORTS = {8080, 8081, 8082, 8443}
KAFKA_PORTS = {9092, 9093, 9094, 2181}
KERBEROS_PORTS = {88, 464, 749}
KUBERNETES_PORTS = {6443, 10250, 10255, 8001}
LDAP_PORTS = {389, 636, 3268, 3269}
MEMCACHED_PORTS = {11211}
MSSQL_PORTS = {1433, 1434}
NETBIOS_PORTS = {137, 138, 139, 445}
NFS_PORTS = {111, 2049, 20048}
NTP_PORTS = {123}
ORACLE_PORTS = {1521, 1522, 2483, 2484}
POSTGRESQL_PORTS = {5432, 5433}
RABBITMQ_PORTS = {4369, 5671, 5672, 15671, 15672, 25672}
RDP_PORTS = {3389}
REDIS_PORTS = {6379}
TFTP_PORTS = {69}
TOMCAT_PORTS = {8009, 8080, 8081, 8443}
VNC_PORTS = set(range(5900, 5911)) | {5800, 5801}
WEBDAV_PORTS = {80, 443, 8080, 8443}
WINRM_PORTS = {5985, 5986}


@dataclass
class ServiceFinding:
    service: str = ""
    ip: str = ""
    port: int = 0
    check: str = ""
    severity: str = "info"
    evidence: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "ip": self.ip,
            "port": self.port,
            "check": self.check,
            "severity": self.severity,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class ServiceHostResult:
    service: str = ""
    ip: str = ""
    port: int = 0
    banner: str = ""
    metadata: Dict = field(default_factory=dict)
    findings: List[ServiceFinding] = field(default_factory=list)
    scan_time: float = 0.0
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "ip": self.ip,
            "port": self.port,
            "banner": self.banner,
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
            "scan_time": round(self.scan_time, 2),
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


@dataclass
class ServiceMisconfigStats:
    total_hosts: int = 0
    smtp_hosts: int = 0
    pop3_hosts: int = 0
    mongodb_hosts: int = 0
    docker_hosts: int = 0
    elasticsearch_hosts: int = 0
    etcd_hosts: int = 0
    grafana_hosts: int = 0
    imap_hosts: int = 0
    jenkins_hosts: int = 0
    kafka_hosts: int = 0
    kerberos_hosts: int = 0
    kubernetes_hosts: int = 0
    ldap_hosts: int = 0
    memcached_hosts: int = 0
    mssql_hosts: int = 0
    netbios_hosts: int = 0
    nfs_hosts: int = 0
    ntp_hosts: int = 0
    oracle_hosts: int = 0
    postgresql_hosts: int = 0
    rabbitmq_hosts: int = 0
    rdp_hosts: int = 0
    redis_hosts: int = 0
    tftp_hosts: int = 0
    tomcat_hosts: int = 0
    vnc_hosts: int = 0
    webdav_hosts: int = 0
    winrm_hosts: int = 0
    service_summary: Dict[str, int] = field(default_factory=dict)
    findings_total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    checks_not_verified: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_hosts": self.total_hosts,
            "smtp_hosts": self.smtp_hosts,
            "pop3_hosts": self.pop3_hosts,
            "mongodb_hosts": self.mongodb_hosts,
            "docker_hosts": self.docker_hosts,
            "elasticsearch_hosts": self.elasticsearch_hosts,
            "etcd_hosts": self.etcd_hosts,
            "grafana_hosts": self.grafana_hosts,
            "imap_hosts": self.imap_hosts,
            "jenkins_hosts": self.jenkins_hosts,
            "kafka_hosts": self.kafka_hosts,
            "kerberos_hosts": self.kerberos_hosts,
            "kubernetes_hosts": self.kubernetes_hosts,
            "ldap_hosts": self.ldap_hosts,
            "memcached_hosts": self.memcached_hosts,
            "mssql_hosts": self.mssql_hosts,
            "netbios_hosts": self.netbios_hosts,
            "nfs_hosts": self.nfs_hosts,
            "ntp_hosts": self.ntp_hosts,
            "oracle_hosts": self.oracle_hosts,
            "postgresql_hosts": self.postgresql_hosts,
            "rabbitmq_hosts": self.rabbitmq_hosts,
            "rdp_hosts": self.rdp_hosts,
            "redis_hosts": self.redis_hosts,
            "tftp_hosts": self.tftp_hosts,
            "tomcat_hosts": self.tomcat_hosts,
            "vnc_hosts": self.vnc_hosts,
            "webdav_hosts": self.webdav_hosts,
            "winrm_hosts": self.winrm_hosts,
            "service_summary": self.service_summary,
            "findings_total": self.findings_total,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "checks_not_verified": self.checks_not_verified,
            "scan_time": round(self.scan_time, 2),
        }


class ServiceMisconfigScanner:
    """Read-only checks for common service weaknesses."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.available = True
        self.stats = ServiceMisconfigStats()
        self.results: Dict[str, ServiceHostResult] = {}
        self._request_id = 1000

    def scan(self, nmap_results: Dict, target_domain: str = "", output_dir: str = "") -> Dict[str, ServiceHostResult]:
        start = time.time()
        self.results = {}
        self.stats = ServiceMisconfigStats()
        targets = self._get_service_targets(nmap_results)
        self.stats.total_hosts = len(targets)
        self.stats.smtp_hosts = sum(1 for _, port, svc in targets if svc == "smtp")
        self.stats.pop3_hosts = sum(1 for _, port, svc in targets if svc == "pop3")
        self.stats.mongodb_hosts = sum(1 for _, port, svc in targets if svc == "mongodb")
        self.stats.docker_hosts = sum(1 for _, port, svc in targets if svc == "docker")
        self.stats.elasticsearch_hosts = sum(1 for _, port, svc in targets if svc == "elasticsearch")
        self.stats.etcd_hosts = sum(1 for _, port, svc in targets if svc == "etcd")
        self.stats.grafana_hosts = sum(1 for _, port, svc in targets if svc == "grafana")
        self.stats.imap_hosts = sum(1 for _, port, svc in targets if svc == "imap")
        self.stats.jenkins_hosts = sum(1 for _, port, svc in targets if svc == "jenkins")
        self.stats.kafka_hosts = sum(1 for _, port, svc in targets if svc == "kafka")
        self.stats.kerberos_hosts = sum(1 for _, port, svc in targets if svc == "kerberos")
        self.stats.kubernetes_hosts = sum(1 for _, port, svc in targets if svc == "kubernetes")
        self.stats.ldap_hosts = sum(1 for _, port, svc in targets if svc == "ldap")
        self.stats.memcached_hosts = sum(1 for _, port, svc in targets if svc == "memcached")
        self.stats.mssql_hosts = sum(1 for _, port, svc in targets if svc == "mssql")
        self.stats.netbios_hosts = sum(1 for _, port, svc in targets if svc == "netbios")
        self.stats.nfs_hosts = sum(1 for _, port, svc in targets if svc == "nfs")
        self.stats.ntp_hosts = sum(1 for _, port, svc in targets if svc == "ntp")
        self.stats.oracle_hosts = sum(1 for _, port, svc in targets if svc == "oracle")
        self.stats.postgresql_hosts = sum(1 for _, port, svc in targets if svc == "postgresql")
        self.stats.rabbitmq_hosts = sum(1 for _, port, svc in targets if svc == "rabbitmq")
        self.stats.rdp_hosts = sum(1 for _, port, svc in targets if svc == "rdp")
        self.stats.redis_hosts = sum(1 for _, port, svc in targets if svc == "redis")
        self.stats.tftp_hosts = sum(1 for _, port, svc in targets if svc == "tftp")
        self.stats.tomcat_hosts = sum(1 for _, port, svc in targets if svc == "tomcat")
        self.stats.vnc_hosts = sum(1 for _, port, svc in targets if svc == "vnc")
        self.stats.webdav_hosts = sum(1 for _, port, svc in targets if svc == "webdav")
        self.stats.winrm_hosts = sum(1 for _, port, svc in targets if svc == "winrm")
        self.stats.service_summary = {
            service: sum(1 for _, _, svc in targets if svc == service)
            for service in sorted({svc for _, _, svc in targets})
        }

        for ip, port, service in sorted(targets):
            key = f"{service}:{ip}:{port}"
            if service == "smtp":
                result = self._scan_smtp(ip, port, target_domain)
            elif service == "pop3":
                result = self._scan_pop3(ip, port)
            elif service == "mongodb":
                result = self._scan_mongodb(ip, port)
            elif service == "docker":
                result = self._scan_docker(ip, port)
            elif service == "elasticsearch":
                result = self._scan_elasticsearch(ip, port)
            elif service == "etcd":
                result = self._scan_etcd(ip, port)
            elif service == "grafana":
                result = self._scan_grafana(ip, port)
            elif service == "imap":
                result = self._scan_imap(ip, port)
            elif service == "jenkins":
                result = self._scan_jenkins(ip, port)
            elif service == "kafka":
                result = self._scan_kafka(ip, port)
            elif service == "kerberos":
                result = self._scan_kerberos(ip, port)
            elif service == "kubernetes":
                result = self._scan_kubernetes(ip, port)
            elif service == "ldap":
                result = self._scan_ldap(ip, port)
            elif service == "memcached":
                result = self._scan_memcached(ip, port)
            elif service == "mssql":
                result = self._scan_mssql(ip, port)
            elif service == "netbios":
                result = self._scan_netbios(ip, port)
            elif service == "nfs":
                result = self._scan_nfs(ip, port)
            elif service == "ntp":
                result = self._scan_ntp(ip, port)
            elif service == "oracle":
                result = self._scan_oracle(ip, port)
            elif service == "postgresql":
                result = self._scan_postgresql(ip, port)
            elif service == "rabbitmq":
                result = self._scan_rabbitmq(ip, port)
            elif service == "rdp":
                result = self._scan_rdp(ip, port)
            elif service == "redis":
                result = self._scan_redis(ip, port)
            elif service == "tftp":
                result = self._scan_tftp(ip, port)
            elif service == "tomcat":
                result = self._scan_tomcat(ip, port)
            elif service == "vnc":
                result = self._scan_vnc(ip, port)
            elif service == "webdav":
                result = self._scan_webdav(ip, port)
            elif service == "winrm":
                result = self._scan_winrm(ip, port)
            else:
                continue
            self.results[key] = result

        self.stats.scan_time = time.time() - start
        self._compute_stats()
        return self.results

    def _get_service_targets(self, nmap_results: Dict) -> Set[Tuple[str, int, str]]:
        targets = set()
        for ip, host_result in (nmap_results or {}).items():
            ports = host_result.ports if hasattr(host_result, "ports") else host_result.get("ports", [])
            for port_obj in ports:
                port = port_obj.port if hasattr(port_obj, "port") else port_obj.get("port", 0)
                state = port_obj.state if hasattr(port_obj, "state") else port_obj.get("state", "")
                service = port_obj.service if hasattr(port_obj, "service") else port_obj.get("service", "")
                version = port_obj.version if hasattr(port_obj, "version") else port_obj.get("version", "")
                extra_info = port_obj.extra_info if hasattr(port_obj, "extra_info") else port_obj.get("extra_info", "")
                service = (service or "").lower()
                service_text = f"{service} {version or ''} {extra_info or ''}".lower()
                if state and state != "open":
                    continue
                if port in SMTP_PORTS or "smtp" in service_text:
                    targets.add((ip, int(port), "smtp"))
                elif port in POP3_PORTS or "pop3" in service_text:
                    targets.add((ip, int(port), "pop3"))
                elif port in MONGODB_PORTS or "mongo" in service_text:
                    targets.add((ip, int(port), "mongodb"))
                elif port in DOCKER_PORTS or "docker" in service_text:
                    targets.add((ip, int(port), "docker"))
                elif port in ELASTICSEARCH_PORTS or "elastic" in service_text:
                    targets.add((ip, int(port), "elasticsearch"))
                elif port in ETCD_PORTS or "etcd" in service_text:
                    targets.add((ip, int(port), "etcd"))
                elif port in GRAFANA_PORTS or "grafana" in service_text:
                    targets.add((ip, int(port), "grafana"))
                elif port in IMAP_PORTS or "imap" in service_text:
                    targets.add((ip, int(port), "imap"))
                elif port in TOMCAT_PORTS and (port == 8009 or "tomcat" in service_text or "ajp" in service_text):
                    targets.add((ip, int(port), "tomcat"))
                elif port in JENKINS_PORTS or "jenkins" in service_text:
                    targets.add((ip, int(port), "jenkins"))
                elif port in KAFKA_PORTS or "kafka" in service_text or "zookeeper" in service_text:
                    targets.add((ip, int(port), "kafka"))
                elif port in KERBEROS_PORTS or "kerberos" in service_text or "kpasswd" in service_text:
                    targets.add((ip, int(port), "kerberos"))
                elif port in KUBERNETES_PORTS or "kubernetes" in service_text or "kubelet" in service_text:
                    targets.add((ip, int(port), "kubernetes"))
                elif port in LDAP_PORTS or service in {"ldap", "ldaps", "ldapssl"} or "ldap" in service_text:
                    targets.add((ip, int(port), "ldap"))
                elif port in MEMCACHED_PORTS or "memcache" in service_text:
                    targets.add((ip, int(port), "memcached"))
                elif port in MSSQL_PORTS or "ms-sql" in service_text or "mssql" in service_text or "sql server" in service_text:
                    targets.add((ip, int(port), "mssql"))
                elif port in NETBIOS_PORTS or "netbios" in service_text or "microsoft-ds" in service_text or service == "smb":
                    targets.add((ip, int(port), "netbios"))
                elif port in NFS_PORTS or "nfs" in service_text or "mountd" in service_text or "rpcbind" in service_text or "sunrpc" in service_text:
                    targets.add((ip, int(port), "nfs"))
                elif port in NTP_PORTS or service == "ntp" or "ntp" in service_text:
                    targets.add((ip, int(port), "ntp"))
                elif port in ORACLE_PORTS or "oracle" in service_text or "tns" in service_text:
                    targets.add((ip, int(port), "oracle"))
                elif port in POSTGRESQL_PORTS or "postgres" in service_text or "pgsql" in service_text:
                    targets.add((ip, int(port), "postgresql"))
                elif port in RABBITMQ_PORTS or "rabbitmq" in service_text or "amqp" in service_text or "epmd" in service_text:
                    targets.add((ip, int(port), "rabbitmq"))
                elif port in RDP_PORTS or service == "ms-wbt-server" or "rdp" in service_text:
                    targets.add((ip, int(port), "rdp"))
                elif port in REDIS_PORTS or "redis" in service_text:
                    targets.add((ip, int(port), "redis"))
                elif port in TFTP_PORTS or service == "tftp" or "tftp" in service_text:
                    targets.add((ip, int(port), "tftp"))
                elif port in VNC_PORTS or "vnc" in service_text or "rfb" in service_text:
                    targets.add((ip, int(port), "vnc"))
                elif "webdav" in service_text or "http-dav" in service_text:
                    targets.add((ip, int(port), "webdav"))
                elif port in WINRM_PORTS or "winrm" in service_text or "wsman" in service_text:
                    targets.add((ip, int(port), "winrm"))
        return targets

    def _finding(self, service: str, ip: str, port: int, check: str, severity: str, evidence: str, recommendation: str) -> ServiceFinding:
        return ServiceFinding(service, ip, port, check, severity, evidence[:500], recommendation)

    # ─── SMTP ──────────────────────────────────────────────────────────────

    def _scan_smtp(self, ip: str, port: int, target_domain: str) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="smtp", ip=ip, port=port)
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        sock = None
        try:
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            if port == 465:
                context = ssl.create_default_context()
                sock = context.wrap_socket(raw_sock, server_hostname=ip)
                result.metadata["implicit_tls"] = True
            else:
                sock = raw_sock
                result.metadata["implicit_tls"] = False

            banner = self._smtp_read(sock)
            result.banner = banner.strip()
            ehlo = self._smtp_cmd(sock, f"EHLO reconx.{target_domain or 'local'}")
            capabilities = self._parse_smtp_capabilities(ehlo)
            result.metadata["capabilities"] = sorted(capabilities)

            if "STARTTLS" not in capabilities and port != 465:
                result.findings.append(self._finding(
                    "smtp", ip, port, "No TLS encryption", "high",
                    "STARTTLS is not advertised on a clear-text SMTP port.",
                    "Enable STARTTLS with a valid certificate and require TLS for authentication."
                ))

            auth_mechs = self._parse_auth_mechanisms(ehlo)
            result.metadata["auth_mechanisms"] = sorted(auth_mechs)
            weak_mechs = auth_mechs.intersection({"PLAIN", "LOGIN", "CRAM-MD5"})
            if weak_mechs and port != 465 and "STARTTLS" not in capabilities:
                result.findings.append(self._finding(
                    "smtp", ip, port, "Weak authentication", "high",
                    f"Weak SMTP AUTH mechanisms advertised without TLS: {', '.join(sorted(weak_mechs))}.",
                    "Disable weak mechanisms or only advertise them after TLS is active."
                ))
            if "NTLM" in auth_mechs:
                result.findings.append(self._finding(
                    "smtp", ip, port, "Information disclosure via NTLM", "medium",
                    "SMTP AUTH advertises NTLM, which can expose domain metadata or support relay-style attacks.",
                    "Disable NTLM on internet-facing SMTP services unless strictly required."
                ))

            vrfy_resp = self._smtp_cmd(sock, "VRFY root")
            result.metadata["vrfy_response"] = vrfy_resp.strip()[:200]
            if self._smtp_positive(vrfy_resp, include_ambiguous=True):
                result.findings.append(self._finding(
                    "smtp", ip, port, "VRFY/EXPN enabled", "medium",
                    f"VRFY returned: {vrfy_resp.strip()}",
                    "Disable VRFY and EXPN or restrict them to trusted networks."
                ))

            expn_resp = self._smtp_cmd(sock, "EXPN postmaster")
            result.metadata["expn_response"] = expn_resp.strip()[:200]
            if self._smtp_positive(expn_resp, include_ambiguous=True):
                result.findings.append(self._finding(
                    "smtp", ip, port, "VRFY/EXPN enabled", "medium",
                    f"EXPN returned: {expn_resp.strip()}",
                    "Disable VRFY and EXPN or restrict them to trusted networks."
                ))

            relay_resp = self._smtp_open_relay_probe(sock, target_domain)
            result.metadata["open_relay_probe"] = relay_resp.strip()[:300]
            if self._smtp_positive(relay_resp):
                result.findings.append(self._finding(
                    "smtp", ip, port, "Open relay configuration", "critical",
                    f"Unauthenticated RCPT TO for an external domain was accepted: {relay_resp.strip()}",
                    "Require authentication or trusted-source restrictions before accepting relay recipients."
                ))
                result.findings.append(self._finding(
                    "smtp", ip, port, "No authentication required", "critical",
                    "The server accepted an unauthenticated relay recipient during MAIL/RCPT probing.",
                    "Require SMTP AUTH for relay and reject unauthenticated external recipients."
                ))

            verbose = self._looks_verbose("\n".join([banner, ehlo, vrfy_resp, expn_resp, relay_resp]))
            if verbose:
                result.findings.append(self._finding(
                    "smtp", ip, port, "Verbose error messages", "low",
                    "SMTP responses disclose detailed product, host, or policy information.",
                    "Reduce banner/detail leakage on internet-facing SMTP services."
                ))

            if target_domain and "." in target_domain and not self._is_ip_address(target_domain):
                spf, dmarc = self._check_mail_dns(target_domain)
                result.metadata["spf_record"] = spf
                result.metadata["dmarc_record"] = dmarc
                if not spf:
                    result.findings.append(self._finding(
                        "smtp", ip, port, "No SPF/DMARC records", "medium",
                        f"No SPF TXT record found for {target_domain}.",
                        "Publish an SPF TXT record for authorized mail senders."
                    ))
                if not dmarc:
                    result.findings.append(self._finding(
                        "smtp", ip, port, "No SPF/DMARC records", "medium",
                        f"No DMARC TXT record found for _dmarc.{target_domain}.",
                        "Publish a DMARC policy and monitor enforcement reports."
                    ))

            outdated = self._smtp_outdated_banner(result.banner)
            if outdated:
                result.findings.append(self._finding(
                    "smtp", ip, port, "Outdated mail server software", "high",
                    outdated,
                    "Upgrade the SMTP server to a supported release and apply vendor security updates."
                ))

            result.metadata["not_fully_verified"] = ["No rate limiting"]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        finally:
            try:
                if sock:
                    self._smtp_cmd(sock, "QUIT")
                    sock.close()
            except Exception:
                pass
        result.scan_time = time.time() - start
        return result

    def _smtp_read(self, sock: socket.socket) -> str:
        lines = []
        while True:
            data = sock.recv(4096).decode("utf-8", errors="replace")
            if not data:
                break
            lines.append(data)
            split = data.splitlines()
            if split and len(split[-1]) >= 4 and split[-1][3:4] == " ":
                break
            if len("".join(lines)) > 8192:
                break
        return "".join(lines)

    def _smtp_cmd(self, sock: socket.socket, command: str) -> str:
        sock.sendall((command + "\r\n").encode("ascii", errors="ignore"))
        return self._smtp_read(sock)

    def _parse_smtp_capabilities(self, ehlo: str) -> Set[str]:
        caps = set()
        for line in ehlo.splitlines():
            match = re.match(r"^250[- ]([A-Za-z0-9_-]+)", line.strip())
            if match:
                caps.add(match.group(1).upper())
        return caps

    def _parse_auth_mechanisms(self, ehlo: str) -> Set[str]:
        mechs = set()
        for line in ehlo.splitlines():
            if "AUTH" not in line.upper():
                continue
            clean = re.sub(r"^250[- ]", "", line.strip(), flags=re.I)
            parts = clean.split()
            if parts and parts[0].upper() == "AUTH":
                mechs.update(p.upper() for p in parts[1:])
        return mechs

    def _smtp_positive(self, response: str, include_ambiguous: bool = False) -> bool:
        codes = [line[:3] for line in response.splitlines() if len(line) >= 3 and line[:3].isdigit()]
        positives = {"250", "251"}
        if include_ambiguous:
            positives.add("252")
        return any(code in positives for code in codes)

    def _smtp_open_relay_probe(self, sock: socket.socket, target_domain: str) -> str:
        sender_domain = target_domain or "reconx.local"
        self._smtp_cmd(sock, "RSET")
        self._smtp_cmd(sock, f"MAIL FROM:<relay-test@{sender_domain}>")
        response = self._smtp_cmd(sock, "RCPT TO:<relay-test@reconx.invalid>")
        self._smtp_cmd(sock, "RSET")
        return response

    def _check_mail_dns(self, domain: str) -> Tuple[str, str]:
        return self._query_txt(domain, "v=spf1"), self._query_txt(f"_dmarc.{domain}", "v=DMARC1")

    def _query_txt(self, name: str, needle: str) -> str:
        commands = [
            ["nslookup", "-type=TXT", name],
        ]
        for command in commands:
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=8)
                output = (proc.stdout or "") + (proc.stderr or "")
                for line in output.splitlines():
                    if needle.lower() in line.lower():
                        return line.strip().strip('"')
            except Exception:
                continue
        return ""

    def _looks_verbose(self, text: str) -> bool:
        patterns = [
            r"postfix|exim|sendmail|microsoft esmtp|exchange server",
            r"hostname|helo command rejected|relay access denied|recipient address rejected",
            r"\b\d+\.\d+(?:\.\d+){0,2}\b",
        ]
        return sum(1 for pattern in patterns if re.search(pattern, text, re.I)) >= 2

    def _smtp_outdated_banner(self, banner: str) -> str:
        checks = [
            (r"postfix[^\d]*(\d+)\.(\d+)", "Postfix", (3, 5)),
            (r"exim[^\d]*(\d+)\.(\d+)", "Exim", (4, 95)),
            (r"sendmail[^\d]*(\d+)\.(\d+)", "Sendmail", (8, 16)),
            (r"exchange server[^\d]*(\d+)\.(\d+)", "Exchange", (15, 2)),
        ]
        for pattern, name, minimum in checks:
            match = re.search(pattern, banner, re.I)
            if match:
                version = (int(match.group(1)), int(match.group(2)))
                if version < minimum:
                    return f"{name} banner appears old: {match.group(0)}"
        return ""

    # --- POP3 -------------------------------------------------------------

    def _scan_pop3(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="pop3", ip=ip, port=port)
        sock = None
        try:
            timeout = max(3, int(getattr(self.config, "timeout", 8)))
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            if port == 995:
                sock = ssl._create_unverified_context().wrap_socket(raw_sock, server_hostname=ip)
                result.metadata["implicit_tls"] = True
            else:
                sock = raw_sock
                result.metadata["implicit_tls"] = False

            banner = self._pop3_read(sock)
            result.banner = banner.strip()
            capa = self._pop3_cmd(sock, "CAPA", multiline=True)
            capabilities = self._parse_pop3_capabilities(capa)
            result.metadata["capabilities"] = sorted(capabilities)

            if port == 110:
                result.findings.append(self._finding(
                    "pop3", ip, port, "No encryption (port 110)", "high",
                    "POP3 cleartext port 110 is reachable.",
                    "Use POP3S on 995 or require STLS before authentication."
                ))
                result.findings.append(self._finding(
                    "pop3", ip, port, "Plaintext authentication", "high",
                    "POP3 USER/PASS authentication is exposed on a cleartext listener.",
                    "Disable plaintext login before TLS and require encrypted transport."
                ))
            if port == 110 and "STLS" not in capabilities:
                result.findings.append(self._finding(
                    "pop3", ip, port, "No TLS enforcement", "high",
                    "CAPA does not advertise STLS on the cleartext POP3 listener.",
                    "Enable STLS and require TLS for all POP3 authentication."
                ))

            disclosure = self._pop3_info_disclosure("\n".join([banner, capa]))
            if disclosure:
                result.findings.append(self._finding(
                    "pop3", ip, port, "Information disclosure", "low",
                    disclosure,
                    "Reduce POP3 banner and capability detail exposed to untrusted clients."
                ))
            outdated = self._pop3_outdated_evidence("\n".join([banner, capa]))
            if outdated:
                result.findings.append(self._finding(
                    "pop3", ip, port, "Outdated server software", "high",
                    outdated,
                    "Upgrade the POP3 server to a supported release."
                ))
            result.metadata["not_fully_verified"] = [
                "Weak passwords", "No rate limiting", "No account lockout",
            ]
            try:
                self._pop3_cmd(sock, "QUIT")
            except Exception:
                pass
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        result.scan_time = time.time() - start
        return result

    def _pop3_read(self, sock: socket.socket, multiline: bool = False) -> str:
        chunks = []
        while True:
            try:
                data = sock.recv(4096).decode("utf-8", errors="replace")
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            text = "".join(chunks)
            if multiline and "\r\n.\r\n" in text:
                break
            if not multiline and text.endswith("\r\n"):
                break
            if len(text) > 16384:
                break
        return "".join(chunks)

    def _pop3_cmd(self, sock: socket.socket, command: str, multiline: bool = False) -> str:
        sock.sendall((command + "\r\n").encode("ascii", errors="ignore"))
        return self._pop3_read(sock, multiline=multiline)

    def _parse_pop3_capabilities(self, response: str) -> Set[str]:
        capabilities = set()
        for line in response.splitlines():
            clean = line.strip()
            if not clean or clean.startswith(("+OK", ".", "-ERR")):
                continue
            capabilities.add(clean.split()[0].upper())
        return capabilities

    def _pop3_info_disclosure(self, text: str) -> str:
        patterns = [r"Dovecot[^\r\n]*", r"Cyrus[^\r\n]*", r"Courier[^\r\n]*", r"Exchange[^\r\n]*", r"Qpopper[^\r\n]*"]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)[:250]
        return ""

    def _pop3_outdated_evidence(self, text: str) -> str:
        checks = [
            (r"Dovecot\s+([01]\.\d+|2\.[0-2])", "Dovecot before 2.3"),
            (r"Cyrus[^\d]*(2\.[0-4])", "Cyrus POP3 before 2.5"),
            (r"Courier[^\d]*([0-4]\.\d+)", "Courier before 5.x"),
            (r"Qpopper[^\d]*([0-4]\.\d+)", "Qpopper legacy version"),
        ]
        for pattern, label in checks:
            if re.search(pattern, text, re.IGNORECASE):
                return label
        return ""

    # ─── MongoDB ───────────────────────────────────────────────────────────

    def _scan_mongodb(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="mongodb", ip=ip, port=port)
        try:
            hello = self._mongo_command(ip, port, {"hello": 1, "helloOk": True})
            if not hello:
                hello = self._mongo_command(ip, port, {"isMaster": 1})
            result.metadata["hello"] = self._clean_mongo_doc(hello)
            version = str(hello.get("maxWireVersion", ""))

            build_info = self._mongo_command(ip, port, {"buildInfo": 1})
            if build_info:
                result.metadata["build_info"] = self._clean_mongo_doc(build_info)
                if build_info.get("version"):
                    result.banner = f"MongoDB {build_info.get('version')}"
                    if self._is_old_mongodb(str(build_info.get("version"))):
                        result.findings.append(self._finding(
                            "mongodb", ip, port, "Outdated MongoDB version", "high",
                            f"MongoDB version reported as {build_info.get('version')}.",
                            "Upgrade MongoDB to a currently supported major release."
                        ))
            elif version:
                result.banner = f"MongoDB wireVersion {version}"

            if port == 27017:
                result.findings.append(self._finding(
                    "mongodb", ip, port, "Default port exposed", "medium",
                    "MongoDB default port 27017 is reachable.",
                    "Restrict MongoDB with firewall rules and expose it only to trusted clients."
                ))

            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "mongodb", ip, port, "Exposed to internet without firewall", "high",
                    f"MongoDB service is reachable on {ip}:{port}.",
                    "Bind MongoDB to private interfaces and enforce network ACLs/firewall rules."
                ))
            if not self._is_loopback_ip(ip):
                result.findings.append(self._finding(
                    "mongodb", ip, port, "Bind to 0.0.0.0 instead of localhost", "medium",
                    "Remote reachability indicates MongoDB is not limited to localhost.",
                    "Use bindIp to restrict MongoDB to localhost/private management networks."
                ))

            databases = self._mongo_command(ip, port, {"listDatabases": 1})
            if databases and databases.get("ok") == 1:
                result.metadata["databases"] = self._clean_mongo_doc(databases)
                result.findings.append(self._finding(
                    "mongodb", ip, port, "No authentication enabled", "critical",
                    "listDatabases succeeded without credentials.",
                    "Enable authorization, create least-privilege users, and disable anonymous access."
                ))
                db_names = [db.get("name") for db in databases.get("databases", []) if isinstance(db, dict)]
                if db_names:
                    result.findings.append(self._finding(
                        "mongodb", ip, port, "No role-based access control", "high",
                        f"Unauthenticated user can list databases: {', '.join(db_names[:10])}.",
                        "Enable RBAC and restrict database enumeration to authorized roles."
                    ))

            js_status = self._mongo_command(ip, port, {"getParameter": 1, "security.javascriptEnabled": 1})
            if js_status and js_status.get("security.javascriptEnabled") is True:
                result.findings.append(self._finding(
                    "mongodb", ip, port, "JavaScript execution enabled", "medium",
                    "MongoDB reports security.javascriptEnabled=true.",
                    "Disable server-side JavaScript unless explicitly required."
                ))

            log_status = self._mongo_command(ip, port, {"getLog": "global"})
            if log_status and log_status.get("ok") == 1:
                result.metadata["logging_readable_without_auth"] = True

            if hello:
                result.findings.append(self._finding(
                    "mongodb", ip, port, "No SSL/TLS encryption", "medium",
                    "MongoDB accepted a plaintext wire-protocol handshake.",
                    "Require TLS for MongoDB clients and disable plaintext access where possible."
                ))

            result.metadata["not_fully_verified"] = [
                "Default credentials", "Weak passwords", "Excessive user privileges",
                "Logging disabled", "No regular backups",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _mongo_command(self, ip: str, port: int, command: Dict) -> Dict:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        body = self._bson_encode(command)
        self._request_id += 1
        payload = struct.pack("<I", 0) + b"\x00" + body
        message_len = 16 + len(payload)
        header = struct.pack("<iiii", message_len, self._request_id, 0, 2013)
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(header + payload)
            response_header = self._recv_exact(sock, 16)
            if len(response_header) < 16:
                return {}
            length, _, _, opcode = struct.unpack("<iiii", response_header)
            response = self._recv_exact(sock, max(0, length - 16))
            if opcode == 2013 and len(response) > 5:
                return self._bson_decode(response[5:])
            if opcode == 1 and len(response) > 20:
                return self._bson_decode(response[20:])
        return {}

    def _recv_exact(self, sock: socket.socket, length: int) -> bytes:
        chunks = []
        remaining = length
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _bson_encode(self, doc: Dict) -> bytes:
        elements = b""
        for key, value in doc.items():
            encoded_key = key.encode("utf-8") + b"\x00"
            if isinstance(value, bool):
                elements += b"\x08" + encoded_key + (b"\x01" if value else b"\x00")
            elif isinstance(value, int):
                elements += b"\x10" + encoded_key + struct.pack("<i", value)
            elif isinstance(value, str):
                encoded = value.encode("utf-8") + b"\x00"
                elements += b"\x02" + encoded_key + struct.pack("<i", len(encoded)) + encoded
            elif isinstance(value, dict):
                elements += b"\x03" + encoded_key + self._bson_encode(value)
        return struct.pack("<i", len(elements) + 5) + elements + b"\x00"

    def _bson_decode(self, data: bytes) -> Dict:
        if len(data) < 5:
            return {}
        total_len = struct.unpack("<i", data[:4])[0]
        pos = 4
        out = {}
        while pos < min(total_len - 1, len(data)):
            element_type = data[pos]
            pos += 1
            end = data.find(b"\x00", pos)
            if end < 0:
                break
            key = data[pos:end].decode("utf-8", errors="replace")
            pos = end + 1
            if element_type == 0x01:
                out[key] = struct.unpack("<d", data[pos:pos + 8])[0]
                pos += 8
            elif element_type == 0x02:
                size = struct.unpack("<i", data[pos:pos + 4])[0]
                pos += 4
                out[key] = data[pos:pos + max(0, size - 1)].decode("utf-8", errors="replace")
                pos += size
            elif element_type in (0x03, 0x04):
                size = struct.unpack("<i", data[pos:pos + 4])[0]
                nested = self._bson_decode(data[pos:pos + size])
                if element_type == 0x04:
                    out[key] = [nested[k] for k in sorted(nested.keys(), key=lambda x: int(x) if x.isdigit() else x)]
                else:
                    out[key] = nested
                pos += size
            elif element_type == 0x08:
                out[key] = data[pos] != 0
                pos += 1
            elif element_type == 0x10:
                out[key] = struct.unpack("<i", data[pos:pos + 4])[0]
                pos += 4
            elif element_type == 0x12:
                out[key] = struct.unpack("<q", data[pos:pos + 8])[0]
                pos += 8
            elif element_type == 0x0A:
                out[key] = None
            else:
                break
        return out

    def _clean_mongo_doc(self, doc: Dict) -> Dict:
        raw = json.loads(json.dumps(doc, default=str)) if doc else {}
        return raw

    def _is_old_mongodb(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.(\d+)", version)
        if not match:
            return False
        major = int(match.group(1))
        return major < 6

    def _is_ip_address(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_loopback_ip(self, value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_loopback
        except ValueError:
            return value in {"localhost"}

    def _is_public_ip(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
        except ValueError:
            return False

    # ─── Docker ────────────────────────────────────────────────────────────

    def _scan_docker(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="docker", ip=ip, port=port)
        schemes = ["http"] if port != 2376 else ["https", "http"]
        try:
            base_url, version = self._docker_get_first(ip, port, schemes, "/version")
            if not version:
                raise RuntimeError("Docker API did not respond to /version")
            result.metadata["base_url"] = base_url
            result.metadata["version"] = version
            result.banner = f"Docker {version.get('Version', '')}".strip()

            result.findings.append(self._finding(
                "docker", ip, port, "Docker API exposed without authentication", "critical",
                f"Unauthenticated GET {base_url}/version returned Docker metadata.",
                "Do not expose Docker API publicly; require mutual TLS and restrict by firewall."
            ))
            if port == 2375 or base_url.startswith("http://"):
                result.findings.append(self._finding(
                    "docker", ip, port, "Using unencrypted port 2375", "critical",
                    f"Docker API is reachable over clear-text HTTP at {base_url}.",
                    "Disable tcp://0.0.0.0:2375 and use SSH or mutually authenticated TLS."
                ))

            containers = self._docker_get_json(base_url, "/containers/json?all=1") or []
            result.metadata["container_count"] = len(containers) if isinstance(containers, list) else 0
            for container in containers if isinstance(containers, list) else []:
                container_id = container.get("Id", "")
                inspect = self._docker_get_json(base_url, f"/containers/{container_id}/json") or {}
                self._docker_container_findings(result, container, inspect)

            result.metadata["not_fully_verified"] = ["No vulnerability scanning on images"]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _docker_get_first(self, ip: str, port: int, schemes: List[str], path: str) -> Tuple[str, Optional[Dict]]:
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            data = self._docker_get_json(base_url, path)
            if data:
                return base_url, data
        return "", None

    def _docker_get_json(self, base_url: str, path: str) -> Optional[object]:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        request = urllib.request.Request(base_url + path, headers={"User-Agent": "ReconX"})
        context = None
        if base_url.startswith("https://"):
            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                if response.status >= 400:
                    return None
                body = response.read(1024 * 1024).decode("utf-8", errors="replace")
                return json.loads(body) if body else None
        except (urllib.error.URLError, ValueError, TimeoutError):
            return None

    def _docker_container_findings(self, result: ServiceHostResult, container: Dict, inspect: Dict):
        name = (container.get("Names") or [container.get("Id", "")[:12]])[0].lstrip("/")
        image = container.get("Image") or inspect.get("Config", {}).get("Image", "")
        host_config = inspect.get("HostConfig", {}) if isinstance(inspect, dict) else {}
        config = inspect.get("Config", {}) if isinstance(inspect, dict) else {}
        mounts = inspect.get("Mounts", []) if isinstance(inspect, dict) else []
        network_settings = inspect.get("NetworkSettings", {}) if isinstance(inspect, dict) else {}

        if host_config.get("Privileged"):
            result.findings.append(self._finding(
                "docker", result.ip, result.port, "Privileged containers running", "critical",
                f"Container {name} is running with Privileged=true.",
                "Remove privileged mode and grant only specific capabilities required by the workload."
            ))

        for mount in mounts:
            source = mount.get("Source", "")
            destination = mount.get("Destination", "")
            if source in {"/", "/host", "C:\\"} or destination in {"/host", "/mnt/host", "/rootfs"}:
                result.findings.append(self._finding(
                    "docker", result.ip, result.port, "Host filesystem mounted in containers", "critical",
                    f"Container {name} mount {source} -> {destination}.",
                    "Avoid mounting host root filesystems into containers."
                ))
            if "docker.sock" in source or "docker.sock" in destination:
                result.findings.append(self._finding(
                    "docker", result.ip, result.port, "Docker socket mounted in containers", "critical",
                    f"Container {name} exposes Docker socket via {source} -> {destination}.",
                    "Never mount /var/run/docker.sock into untrusted containers."
                ))

        user = str(config.get("User", ""))
        if not user or user in {"0", "root"}:
            result.findings.append(self._finding(
                "docker", result.ip, result.port, "Containers running as root", "high",
                f"Container {name} runs as user '{user or 'root/default'}'.",
                "Set a non-root USER in the image or container runtime configuration."
            ))

        if not host_config.get("Memory") and not host_config.get("NanoCpus") and not host_config.get("CpuQuota"):
            result.findings.append(self._finding(
                "docker", result.ip, result.port, "No resource limits on containers", "medium",
                f"Container {name} has no memory or CPU runtime limits.",
                "Set memory and CPU limits for production containers."
            ))

        ports = network_settings.get("Ports", {}) if isinstance(network_settings, dict) else {}
        exposed = [port for port, bindings in ports.items() if bindings]
        if exposed:
            result.findings.append(self._finding(
                "docker", result.ip, result.port, "Exposed internal ports", "medium",
                f"Container {name} publishes ports: {', '.join(exposed[:10])}.",
                "Expose only required ports and bind them to trusted interfaces."
            ))

        if image.endswith(":latest") or ":" not in image:
            result.findings.append(self._finding(
                "docker", result.ip, result.port, "Using :latest tag for production", "medium",
                f"Container {name} image tag is not pinned: {image}.",
                "Pin immutable image tags or digests in production deployments."
            ))

        env_values = config.get("Env") or []
        secret_names = []
        for env in env_values:
            key = str(env).split("=", 1)[0].upper()
            if any(marker in key for marker in ["SECRET", "PASSWORD", "PASS", "TOKEN", "API_KEY", "PRIVATE_KEY"]):
                secret_names.append(key)
        if secret_names:
            result.findings.append(self._finding(
                "docker", result.ip, result.port, "Secrets stored in images or environment variables", "high",
                f"Container {name} has sensitive-looking environment keys: {', '.join(secret_names[:10])}.",
                "Move secrets to a dedicated secret manager and avoid image/env leakage."
            ))

        networks = network_settings.get("Networks", {}) if isinstance(network_settings, dict) else {}
        if "bridge" in networks and len(networks) <= 1:
            result.findings.append(self._finding(
                "docker", result.ip, result.port, "No network segmentation between containers", "medium",
                f"Container {name} is attached only to the default bridge network.",
                "Use purpose-specific Docker networks and isolate tiers by trust boundary."
            ))

    # ─── Elasticsearch ────────────────────────────────────────────────────

    def _scan_elasticsearch(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="elasticsearch", ip=ip, port=port)
        try:
            base_url, root = self._http_get_first_json(ip, port, ["http", "https"], "/")
            if not root or not isinstance(root.get("version"), dict):
                raise RuntimeError("Elasticsearch HTTP API did not respond")
            result.metadata["base_url"] = base_url
            result.metadata["root"] = root
            version = str((root.get("version") or {}).get("number", ""))
            result.banner = f"Elasticsearch {version}".strip()

            result.findings.append(self._finding(
                "elasticsearch", ip, port, "No authentication enabled", "critical",
                f"Unauthenticated GET {base_url}/ returned cluster metadata.",
                "Enable Elasticsearch security, authentication, and least-privilege roles."
            ))
            result.findings.append(self._finding(
                "elasticsearch", ip, port, "Anonymous access allowed", "critical",
                "Cluster metadata is readable without credentials.",
                "Disable anonymous access or restrict it to explicitly safe roles."
            ))
            if base_url.startswith("http://"):
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "No SSL/TLS encryption", "high",
                    f"Elasticsearch API is reachable over plaintext HTTP at {base_url}.",
                    "Enable TLS for HTTP and transport interfaces."
                ))
            if port == 9200:
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "Default port accessible", "medium",
                    "Default Elasticsearch HTTP port 9200 is reachable.",
                    "Restrict port 9200 to trusted clients only."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "Exposed to internet (0.0.0.0)", "high",
                    f"Elasticsearch is reachable on public IP {ip}:{port}.",
                    "Bind Elasticsearch to private interfaces and enforce network firewall rules."
                ))
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "No network firewall", "high",
                    "Elasticsearch API is reachable from the scan host on a public address.",
                    "Allow Elasticsearch access only from trusted application or admin networks."
                ))
            if self._is_old_elasticsearch(version):
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "Outdated Elasticsearch version", "high",
                    f"Elasticsearch version reported as {version}.",
                    "Upgrade Elasticsearch to a supported version with security patches."
                ))

            settings = self._http_get_json(f"{base_url}/_cluster/settings?include_defaults=true") or {}
            settings_text = json.dumps(settings, default=str).lower()
            if "script.allowed_types" in settings_text and "none" not in settings_text:
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "Dynamic scripting enabled", "medium",
                    "Cluster settings indicate scripting is allowed.",
                    "Restrict dynamic scripting to required contexts and script types."
                ))
            if settings:
                result.metadata["cluster_settings_readable"] = True

            nodes = self._http_get_json(f"{base_url}/_nodes/http,settings") or {}
            if nodes:
                result.metadata["nodes_api_readable"] = True
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "Unnecessary APIs exposed", "medium",
                    "_nodes API is readable without authentication.",
                    "Restrict administrative Elasticsearch APIs to authenticated operators."
                ))
                if "0.0.0.0" in json.dumps(nodes, default=str):
                    result.findings.append(self._finding(
                        "elasticsearch", ip, port, "Exposed to internet (0.0.0.0)", "high",
                        "Node settings include 0.0.0.0 binding evidence.",
                        "Bind HTTP and transport interfaces to specific private addresses."
                    ))

            error_text = self._http_get_text(f"{base_url}/_does_not_exist_reconx")
            if error_text and any(token in error_text.lower() for token in ["stack_trace", "root_cause", "exception", "caused_by"]):
                result.findings.append(self._finding(
                    "elasticsearch", ip, port, "Verbose error messages", "low",
                    "Error response exposes Elasticsearch exception details.",
                    "Avoid exposing detailed error bodies to untrusted clients."
                ))
            result.metadata["not_fully_verified"] = [
                "Default credentials", "Weak passwords", "No access logging",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _is_old_elasticsearch(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.(\d+)", version or "")
        if not match:
            return False
        major = int(match.group(1))
        return major < 8

    # ─── etcd ─────────────────────────────────────────────────────────────

    def _scan_etcd(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="etcd", ip=ip, port=port)
        try:
            base_url, version = self._http_get_first_json(ip, port, ["http", "https"], "/version")
            if not version or not any(key in version for key in ["etcdserver", "etcdcluster"]):
                raise RuntimeError("etcd API did not respond to /version")
            result.metadata["base_url"] = base_url
            result.metadata["version"] = version
            result.banner = f"etcd {version.get('etcdserver', '')}".strip()

            result.findings.append(self._finding(
                "etcd", ip, port, "Client certificate authentication not required", "high",
                "The client API answered without a client certificate.",
                "Require trusted client certificates for etcd client access."
            ))
            if base_url.startswith("http://"):
                result.findings.append(self._finding(
                    "etcd", ip, port, "No TLS encryption", "high",
                    f"etcd API is reachable over plaintext HTTP at {base_url}.",
                    "Enable TLS for client and peer endpoints."
                ))
            if port in {2379, 2380}:
                result.findings.append(self._finding(
                    "etcd", ip, port, "Default ports accessible", "medium",
                    f"Default etcd port {port} is reachable.",
                    "Restrict etcd ports to cluster members and trusted clients."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "etcd", ip, port, "Exposed to internet (0.0.0.0)", "critical",
                    f"etcd is reachable on public IP {ip}:{port}.",
                    "Bind etcd to private interfaces and enforce network firewall rules."
                ))
                result.findings.append(self._finding(
                    "etcd", ip, port, "No network segmentation", "high",
                    "etcd is reachable from the scan host on a public address.",
                    "Segment etcd from public and application-facing networks."
                ))

            members = self._http_get_json(f"{base_url}/v2/members") or {}
            if members:
                result.metadata["members_readable"] = True
                result.findings.append(self._finding(
                    "etcd", ip, port, "No authentication/authorization", "critical",
                    "Cluster member list is readable without credentials.",
                    "Enable etcd authentication, authorization, and least-privilege roles."
                ))
                result.findings.append(self._finding(
                    "etcd", ip, port, "Weak or no peer authentication", "medium",
                    "Cluster member list is readable without authentication.",
                    "Require peer TLS authentication and restrict member APIs."
                ))

            keys = self._http_get_json(f"{base_url}/v2/keys/?recursive=true") or {}
            if keys:
                result.metadata["keys_readable"] = True
                result.findings.append(self._finding(
                    "etcd", ip, port, "No authentication/authorization", "critical",
                    "Keyspace is readable without credentials.",
                    "Enable etcd authentication and authorization."
                ))
                result.findings.append(self._finding(
                    "etcd", ip, port, "No RBAC configured", "critical",
                    "v2 keys are readable without credentials.",
                    "Enable RBAC and restrict key reads to service-specific roles."
                ))
                key_text = json.dumps(keys, default=str).lower()
                if any(token in key_text for token in ["secret", "password", "token", "private_key", "kube"]):
                    result.findings.append(self._finding(
                        "etcd", ip, port, "Secrets not encrypted at rest", "high",
                        "Readable etcd keys contain secret-like names or values.",
                        "Enable encryption at rest for Kubernetes/etcd secrets and rotate exposed values."
                    ))

            metrics = self._http_get_text(f"{base_url}/metrics")
            if metrics:
                result.findings.append(self._finding(
                    "etcd", ip, port, "Debug mode enabled", "low",
                    "Metrics/debug-style endpoint is reachable without authentication.",
                    "Restrict operational endpoints to monitoring networks."
                ))
            result.metadata["not_fully_verified"] = [
                "No audit logging", "Backup files accessible",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    # ─── Grafana ──────────────────────────────────────────────────────────

    def _scan_grafana(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="grafana", ip=ip, port=port)
        try:
            base_url, health = self._http_get_first_json(ip, port, ["http", "https"], "/api/health")
            if not health or not any(key in health for key in ["database", "version", "commit"]):
                html_url, html = self._http_get_first_text(ip, port, ["http", "https"], "/login")
                if not html or "grafana" not in html.lower():
                    raise RuntimeError("Grafana did not respond to /api/health or /login")
                base_url = html_url
                health = {}
            result.metadata["base_url"] = base_url
            result.metadata["health"] = health
            version = str(health.get("version", ""))
            result.banner = f"Grafana {version}".strip()

            if base_url.startswith("http://"):
                result.findings.append(self._finding(
                    "grafana", ip, port, "No SSL/TLS encryption", "medium",
                    f"Grafana is reachable over plaintext HTTP at {base_url}.",
                    "Terminate Grafana behind HTTPS or enable TLS directly."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "grafana", ip, port, "Exposed to internet without firewall", "high",
                    f"Grafana is reachable on public IP {ip}:{port}.",
                    "Restrict Grafana to trusted users/networks or enforce SSO/MFA."
                ))
            if self._is_old_grafana(version):
                result.findings.append(self._finding(
                    "grafana", ip, port, "Outdated Grafana version", "high",
                    f"Grafana version reported as {version}.",
                    "Upgrade Grafana to a supported version with security patches."
                ))

            org = self._http_get_json(f"{base_url}/api/org")
            if org:
                result.findings.append(self._finding(
                    "grafana", ip, port, "Anonymous access enabled", "critical",
                    "Unauthenticated /api/org returned organization data.",
                    "Disable anonymous access or restrict anonymous role to minimum read-only dashboards."
                ))
                result.findings.append(self._finding(
                    "grafana", ip, port, "No authentication required", "critical",
                    "Grafana API returned data without a session.",
                    "Require authentication for Grafana API and dashboards."
                ))

            signup = self._http_get_text(f"{base_url}/signup")
            if signup and "grafana" in signup.lower() and not any(token in signup.lower() for token in ["not found", "disabled", "login"]):
                result.findings.append(self._finding(
                    "grafana", ip, port, "Signup enabled for anyone", "medium",
                    "Signup page appears reachable.",
                    "Disable public user signup unless explicitly required."
                ))

            default_login = self._grafana_default_login(base_url)
            if default_login:
                result.findings.append(self._finding(
                    "grafana", ip, port, "Default credentials (admin:admin)", "critical",
                    "Login with admin:admin succeeded.",
                    "Change the default admin password immediately and rotate any exposed tokens."
                ))
                result.findings.append(self._finding(
                    "grafana", ip, port, "Weak admin passwords", "critical",
                    "The default weak admin password is accepted.",
                    "Enforce strong admin passwords and MFA/SSO where possible."
                ))

            datasources = self._http_get_json(f"{base_url}/api/datasources")
            if datasources:
                result.findings.append(self._finding(
                    "grafana", ip, port, "Viewer role can access sensitive data", "high",
                    "Unauthenticated datasource API returned data.",
                    "Restrict datasource API access and review anonymous/viewer permissions."
                ))
                text = json.dumps(datasources, default=str).lower()
                if any(token in text for token in ["password", "basicAuthPassword".lower(), "securejsondata"]):
                    result.findings.append(self._finding(
                        "grafana", ip, port, "Datasource credentials in plaintext", "high",
                        "Datasource API response contains credential-like fields.",
                        "Store datasource credentials securely and avoid exposing datasource APIs."
                    ))

            plugins = self._http_get_json(f"{base_url}/api/plugins")
            if plugins:
                plugin_text = json.dumps(plugins, default=str).lower()
                if "unsigned" in plugin_text or "modified" in plugin_text:
                    result.findings.append(self._finding(
                        "grafana", ip, port, "Plugins from untrusted sources", "medium",
                        "Plugin API references unsigned or modified plugins.",
                        "Allow only trusted signed plugins in production."
                    ))

            login_text = self._http_get_text(f"{base_url}/login")
            if login_text and "secret_key" in login_text.lower():
                result.findings.append(self._finding(
                    "grafana", ip, port, "secret_key not changed from default", "medium",
                    "Login response exposes secret_key-related content.",
                    "Set a unique secret_key and avoid leaking configuration in responses."
                ))
            result.metadata["not_fully_verified"] = [
                "API keys with excessive permissions", "No rate limiting on login",
                "No audit logging", "secret_key not changed from default",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _grafana_default_login(self, base_url: str) -> bool:
        body = json.dumps({"user": "admin", "password": "admin"}).encode("utf-8")
        request = urllib.request.Request(
            base_url + "/login",
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "ReconX"},
            method="POST",
        )
        try:
            context = ssl._create_unverified_context() if base_url.startswith("https://") else None
            with urllib.request.urlopen(request, timeout=max(3, int(getattr(self.config, "timeout", 8))), context=context) as response:
                text = response.read(8192).decode("utf-8", errors="replace").lower()
                return response.status in {200, 302} and any(token in text for token in ["logged in", "redirect", "message"])
        except urllib.error.HTTPError as exc:
            if exc.code in {200, 302}:
                return True
        except Exception:
            return False
        return False

    def _is_old_grafana(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.(\d+)", version or "")
        if not match:
            return False
        major = int(match.group(1))
        return major < 10

    # ─── IMAP ─────────────────────────────────────────────────────────────

    def _scan_imap(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="imap", ip=ip, port=port)
        sock = None
        try:
            timeout = max(3, int(getattr(self.config, "timeout", 8)))
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            if port == 993:
                context = ssl._create_unverified_context()
                sock = context.wrap_socket(raw_sock, server_hostname=ip)
                result.metadata["implicit_tls"] = True
            else:
                sock = raw_sock
                result.metadata["implicit_tls"] = False

            banner = self._imap_read(sock)
            result.banner = banner.strip()
            cap_response = self._imap_cmd(sock, "A001", "CAPABILITY")
            capabilities = self._parse_imap_capabilities(cap_response)
            result.metadata["capabilities"] = sorted(capabilities)

            if port == 143:
                result.findings.append(self._finding(
                    "imap", ip, port, "No encryption (port 143)", "high",
                    "IMAP cleartext port 143 is reachable.",
                    "Use IMAPS on 993 or require STARTTLS before authentication."
                ))
            if port == 143 and "STARTTLS" not in capabilities:
                result.findings.append(self._finding(
                    "imap", ip, port, "No TLS required", "high",
                    "CAPABILITY does not advertise STARTTLS on port 143.",
                    "Enable STARTTLS and disable plaintext login before TLS."
                ))
            if port == 143 and "LOGINDISABLED" not in capabilities:
                result.findings.append(self._finding(
                    "imap", ip, port, "Plaintext authentication allowed", "high",
                    "CAPABILITY does not advertise LOGINDISABLED before TLS.",
                    "Set the IMAP server to reject LOGIN/AUTH until TLS is active."
                ))

            id_response = ""
            if "ID" in capabilities:
                id_response = self._imap_cmd(sock, "A002", "ID NIL")
                result.metadata["id_response"] = id_response.strip()[:300]
            disclosure = self._imap_info_disclosure("\n".join([banner, cap_response, id_response]))
            if disclosure:
                result.findings.append(self._finding(
                    "imap", ip, port, "Information disclosure", "low",
                    disclosure,
                    "Reduce banner, ID, and capability disclosure on public IMAP services."
                ))

            outdated = self._imap_outdated_evidence("\n".join([banner, id_response]))
            if outdated:
                result.findings.append(self._finding(
                    "imap", ip, port, "Outdated IMAP server", "high",
                    outdated,
                    "Upgrade the IMAP server to a supported release."
                ))

            result.metadata["not_fully_verified"] = [
                "Weak passwords", "VRFY/EXPN enabled", "No rate limiting", "No account lockout",
            ]
            self._imap_cmd(sock, "A999", "LOGOUT")
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        result.scan_time = time.time() - start
        return result

    def _imap_read(self, sock: socket.socket, tag: str = "") -> str:
        chunks = []
        while True:
            try:
                data = sock.recv(4096).decode("utf-8", errors="replace")
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            lines = "".join(chunks).splitlines()
            if tag and any(line.upper().startswith(tag.upper() + " ") for line in lines):
                break
            if not tag and lines:
                break
            if len("".join(chunks)) > 16384:
                break
        return "".join(chunks)

    def _imap_cmd(self, sock: socket.socket, tag: str, command: str) -> str:
        sock.sendall((f"{tag} {command}\r\n").encode("ascii", errors="ignore"))
        return self._imap_read(sock, tag)

    def _parse_imap_capabilities(self, response: str) -> Set[str]:
        capabilities = set()
        for line in response.splitlines():
            if "CAPABILITY" not in line.upper():
                continue
            parts = line.replace("*", "").split()
            for part in parts:
                if part.upper() != "CAPABILITY":
                    capabilities.add(part.upper())
        return capabilities

    def _imap_info_disclosure(self, text: str) -> str:
        patterns = [
            r"Dovecot[^\r\n]*", r"Cyrus[^\r\n]*", r"Courier[^\r\n]*",
            r"Microsoft Exchange[^\r\n]*", r"IMAP4rev1[^\r\n]*",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)[:250]
        return ""

    def _imap_outdated_evidence(self, text: str) -> str:
        checks = [
            (r"Dovecot\s+([01]\.\d+|2\.[0-2])", "Dovecot before 2.3"),
            (r"Cyrus[^\d]*(2\.[0-4])", "Cyrus IMAP before 2.5"),
            (r"Courier-IMAP\s+([0-4]\.\d+)", "Courier IMAP before 5.x"),
        ]
        for pattern, label in checks:
            if re.search(pattern, text, re.IGNORECASE):
                return label
        return ""

    # ─── Jenkins ──────────────────────────────────────────────────────────

    def _scan_jenkins(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="jenkins", ip=ip, port=port)
        try:
            base_url, status, headers, body = self._jenkins_find_base(ip, port)
            if not base_url:
                raise RuntimeError("Jenkins did not respond on HTTP/HTTPS")
            result.metadata["base_url"] = base_url
            version = headers.get("x-jenkins", "") or headers.get("x-hudson", "")
            result.banner = f"Jenkins {version}".strip()

            if base_url.startswith("http://"):
                result.findings.append(self._finding(
                    "jenkins", ip, port, "No HTTPS encryption", "medium",
                    f"Jenkins is reachable over plaintext HTTP at {base_url}.",
                    "Serve Jenkins only through HTTPS with secure cookies."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "jenkins", ip, port, "Exposed to internet without firewall", "high",
                    f"Jenkins is reachable on public IP {ip}:{port}.",
                    "Restrict Jenkins to trusted admin networks or VPN/SSO."
                ))
            if self._is_old_jenkins(version):
                result.findings.append(self._finding(
                    "jenkins", ip, port, "Outdated Jenkins version", "high",
                    f"Jenkins version reported as {version}.",
                    "Upgrade Jenkins core to a supported LTS release."
                ))

            api_status, _, api_body = self._http_request(
                f"{base_url}/api/json?tree=mode,nodeDescription,useSecurity,useCrumbs,jobs[name,url]"
            )
            api_json = self._json_from_text(api_body)
            if api_status == 200 and api_json:
                result.metadata["root_api_readable"] = True
                result.findings.append(self._finding(
                    "jenkins", ip, port, "No authentication required", "critical",
                    "Unauthenticated /api/json returned Jenkins instance data.",
                    "Require authentication and remove anonymous read permissions."
                ))
                result.findings.append(self._finding(
                    "jenkins", ip, port, "Anonymous read access enabled", "critical",
                    "Anonymous user can read Jenkins root API and job list.",
                    "Disable anonymous read or restrict it to explicitly public jobs."
                ))
                result.findings.append(self._finding(
                    "jenkins", ip, port, "Permissive authorization strategy", "high",
                    "Anonymous API access suggests permissive authorization.",
                    "Use matrix/role-based authorization with least privilege."
                ))
                if api_json.get("useSecurity") is False:
                    result.findings.append(self._finding(
                        "jenkins", ip, port, "No authentication required", "critical",
                        "Jenkins API reports useSecurity=false.",
                        "Enable Jenkins security and configure a secure realm."
                    ))

            script_status, _, script_body = self._http_request(f"{base_url}/script")
            if script_status == 200 and "script console" in script_body.lower() and "login" not in script_body.lower():
                result.findings.append(self._finding(
                    "jenkins", ip, port, "Script console accessible without authentication", "critical",
                    "GET /script returned the Jenkins script console without authentication.",
                    "Restrict script console to trusted administrators only."
                ))

            crumb_status, _, crumb_body = self._http_request(f"{base_url}/crumbIssuer/api/json")
            if crumb_status == 404 and (api_status == 200 or status == 200):
                result.findings.append(self._finding(
                    "jenkins", ip, port, "CSRF protection disabled", "medium",
                    "crumbIssuer endpoint returned 404 while Jenkins is reachable.",
                    "Enable Jenkins CSRF crumb issuer unless protected by a stronger control."
                ))

            signup_text = self._http_get_text(f"{base_url}/signup") + self._http_get_text(f"{base_url}/securityRealm/signup")
            if signup_text and any(token in signup_text.lower() for token in ["create an account", "sign up", "signup"]):
                result.findings.append(self._finding(
                    "jenkins", ip, port, "Signup enabled", "medium",
                    "Signup page appears reachable.",
                    "Disable public signup unless explicitly required."
                ))

            self._jenkins_plugin_checks(result, base_url)
            self._jenkins_job_config_checks(result, base_url, api_json)
            self._jenkins_agent_checks(result, base_url)

            result.metadata["not_fully_verified"] = [
                "Default or weak credentials", "Build agents with excessive permissions",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _jenkins_find_base(self, ip: str, port: int) -> Tuple[str, int, Dict[str, str], str]:
        schemes = ["https", "http"] if port == 8443 else ["http", "https"]
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            status, headers, body = self._http_request(base_url + "/")
            if self._looks_like_jenkins(headers, body):
                return base_url, status, headers, body
            login_status, login_headers, login_body = self._http_request(base_url + "/login")
            merged_headers = {**headers, **login_headers}
            if self._looks_like_jenkins(merged_headers, login_body):
                return base_url, login_status, merged_headers, login_body
        return "", 0, {}, ""

    def _looks_like_jenkins(self, headers: Dict[str, str], body: str) -> bool:
        text = body.lower()
        return bool(
            headers.get("x-jenkins") or headers.get("x-hudson")
            or "jenkins" in text or "x-jenkins" in text
        )

    def _is_old_jenkins(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.(\d+)", version or "")
        if not match:
            return False
        major, minor = int(match.group(1)), int(match.group(2))
        return major < 2 or (major == 2 and minor < 440)

    def _jenkins_plugin_checks(self, result: ServiceHostResult, base_url: str) -> None:
        plugin_status, _, plugin_body = self._http_request(
            f"{base_url}/pluginManager/api/json?depth=1&tree=plugins[shortName,version,hasUpdate,activeWarnings]"
        )
        plugin_json = self._json_from_text(plugin_body)
        if plugin_status != 200 or not plugin_json:
            return
        vulnerable = []
        for plugin in plugin_json.get("plugins", [])[:200]:
            warnings = plugin.get("activeWarnings") or []
            if warnings or plugin.get("hasUpdate"):
                vulnerable.append(f"{plugin.get('shortName', 'unknown')}:{plugin.get('version', '')}")
        if vulnerable:
            result.findings.append(self._finding(
                "jenkins", result.ip, result.port, "Vulnerable plugins installed", "high",
                f"Plugin API shows warnings/updates for: {', '.join(vulnerable[:10])}.",
                "Update vulnerable plugins and remove plugins that are not required."
            ))

    def _jenkins_job_config_checks(self, result: ServiceHostResult, base_url: str, api_json: Dict) -> None:
        jobs = (api_json or {}).get("jobs", [])[:10]
        exposed = []
        for job in jobs:
            name = job.get("name", "")
            url = job.get("url", "") or f"{base_url}/job/{urllib.parse.quote(name)}/"
            status, _, config_xml = self._http_request(url.rstrip("/") + "/config.xml")
            if status != 200 or not config_xml:
                continue
            if re.search(r"credentialsId|<password>|secret|token", config_xml, re.IGNORECASE):
                exposed.append(name or url)
        if exposed:
            result.findings.append(self._finding(
                "jenkins", result.ip, result.port, "Credentials stored in job configurations", "high",
                f"Readable job config contains credential-like fields: {', '.join(exposed[:5])}.",
                "Move secrets to Jenkins credentials store and restrict job config read access."
            ))

    def _jenkins_agent_checks(self, result: ServiceHostResult, base_url: str) -> None:
        status, _, body = self._http_request(f"{base_url}/computer/api/json?tree=computer%5BdisplayName,numExecutors,offline%5D")
        data = self._json_from_text(body)
        if status != 200 or not data:
            return
        agents = [c for c in data.get("computer", []) if c.get("displayName") != "Built-In Node"]
        executors = sum(int(c.get("numExecutors") or 0) for c in agents)
        if agents and executors > 0:
            result.findings.append(self._finding(
                "jenkins", result.ip, result.port, "Build agents with excessive permissions", "medium",
                f"Anonymous user can read {len(agents)} build agent(s) with {executors} executor(s).",
                "Restrict agent metadata and review agent permissions/workspace isolation."
            ))

    # ─── Kafka / ZooKeeper ────────────────────────────────────────────────

    def _scan_kafka(self, ip: str, port: int) -> ServiceHostResult:
        if port == 2181:
            return self._scan_zookeeper(ip, port)

        start = time.time()
        result = ServiceHostResult(service="kafka", ip=ip, port=port)
        try:
            api_versions = self._kafka_api_versions(ip, port)
            if not api_versions:
                raise RuntimeError("Kafka ApiVersions did not respond")
            result.metadata["api_versions"] = api_versions
            result.banner = "Kafka broker API"

            result.findings.append(self._finding(
                "kafka", ip, port, "No encryption (plaintext communication)", "high",
                "Kafka ApiVersions request succeeded over raw plaintext TCP.",
                "Require SSL/TLS listeners for Kafka clients and brokers."
            ))
            if port in {9092, 9093, 9094}:
                result.findings.append(self._finding(
                    "kafka", ip, port, "Default ports open", "medium",
                    f"Kafka default port {port} is reachable.",
                    "Expose Kafka only on trusted private listener addresses."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "kafka", ip, port, "Exposed to internet", "critical",
                    f"Kafka is reachable on public IP {ip}:{port}.",
                    "Restrict Kafka with network ACLs, private listeners, and authentication."
                ))

            metadata = self._kafka_metadata(ip, port)
            if metadata:
                result.metadata["metadata"] = metadata
                result.findings.append(self._finding(
                    "kafka", ip, port, "No authentication (SASL disabled)", "critical",
                    "Kafka metadata request succeeded without SASL authentication.",
                    "Enable SASL or mTLS authentication on exposed listeners."
                ))
                result.findings.append(self._finding(
                    "kafka", ip, port, "No authorization (ACLs not configured)", "critical",
                    f"Unauthenticated metadata request returned broker/topic metadata: {metadata}.",
                    "Enable Kafka ACLs and deny anonymous metadata reads."
                ))
                result.findings.append(self._finding(
                    "kafka", ip, port, "Overly permissive ACLs", "high",
                    "Broker metadata is readable without credentials.",
                    "Require authenticated principals and least-privilege ACLs."
                ))

            result.metadata["not_fully_verified"] = [
                "Zookeeper accessible without auth", "Auto-create topics enabled",
                "delete.topic.enable=true", "No message encryption at rest",
                "No audit logging", "Weak SASL credentials", "SSL certificate validation disabled",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _scan_zookeeper(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="kafka", ip=ip, port=port)
        try:
            ruok = self._zookeeper_cmd(ip, port, "ruok")
            if "imok" not in ruok.lower():
                raise RuntimeError("ZooKeeper four-letter commands did not respond")
            result.banner = "ZooKeeper"
            result.metadata["ruok"] = ruok.strip()
            result.findings.append(self._finding(
                "kafka", ip, port, "Zookeeper accessible without auth", "critical",
                "ZooKeeper ruok command returned imok without authentication.",
                "Restrict ZooKeeper to brokers/admin hosts and enable authentication."
            ))
            result.findings.append(self._finding(
                "kafka", ip, port, "No authentication (SASL disabled)", "high",
                "ZooKeeper four-letter command interface answered anonymously.",
                "Enable ZooKeeper authentication and restrict four-letter commands."
            ))
            if port == 2181:
                result.findings.append(self._finding(
                    "kafka", ip, port, "Default ports open", "medium",
                    "ZooKeeper default port 2181 is reachable.",
                    "Restrict ZooKeeper client port to Kafka cluster networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "kafka", ip, port, "Exposed to internet", "critical",
                    f"ZooKeeper is reachable on public IP {ip}:{port}.",
                    "Do not expose ZooKeeper to the internet."
                ))
            conf = self._zookeeper_cmd(ip, port, "conf")
            if conf:
                result.metadata["conf"] = conf[:1000]
                result.findings.append(self._finding(
                    "kafka", ip, port, "No audit logging", "info",
                    "ZooKeeper conf endpoint is readable; audit configuration should be reviewed.",
                    "Restrict operational four-letter commands and enable audit logging where supported."
                ))
            result.metadata["not_fully_verified"] = [
                "No authorization (ACLs not configured)", "Auto-create topics enabled",
                "delete.topic.enable=true", "No message encryption at rest",
                "Weak SASL credentials", "SSL certificate validation disabled",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _kafka_api_versions(self, ip: str, port: int) -> Dict:
        response = self._kafka_request(ip, port, 18, 0, 18001, b"")
        if len(response) < 10:
            return {}
        correlation_id = struct.unpack(">i", response[:4])[0]
        error_code = struct.unpack(">h", response[4:6])[0]
        api_count = struct.unpack(">i", response[6:10])[0]
        return {"correlation_id": correlation_id, "error_code": error_code, "api_count": api_count}

    def _kafka_metadata(self, ip: str, port: int) -> Dict:
        body = struct.pack(">i", 0)
        response = self._kafka_request(ip, port, 3, 0, 18002, body)
        if len(response) < 8:
            return {}
        pos = 4
        broker_count = struct.unpack(">i", response[pos:pos + 4])[0]
        pos += 4
        if broker_count < 0 or broker_count > 10000:
            return {}
        return {"broker_count": broker_count}

    def _kafka_request(self, ip: str, port: int, api_key: int, api_version: int, correlation_id: int, body: bytes) -> bytes:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        client_id = b"ReconX"
        header = (
            struct.pack(">hhi", api_key, api_version, correlation_id)
            + struct.pack(">h", len(client_id)) + client_id + body
        )
        request = struct.pack(">i", len(header)) + header
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            size_raw = self._recv_exact(sock, 4)
            if len(size_raw) != 4:
                return b""
            size = struct.unpack(">i", size_raw)[0]
            if size <= 0 or size > 10 * 1024 * 1024:
                return b""
            return self._recv_exact(sock, size)

    def _zookeeper_cmd(self, ip: str, port: int, command: str) -> str:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(command.encode("ascii", errors="ignore"))
            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                if sum(len(chunk) for chunk in chunks) > 65536:
                    break
            return b"".join(chunks).decode("utf-8", errors="replace")

    # ─── Kerberos ────────────────────────────────────────────────────────

    def _scan_kerberos(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="kerberos", ip=ip, port=port)
        try:
            if not self._tcp_connectable(ip, port):
                raise RuntimeError("Kerberos port did not accept a TCP connection")
            result.banner = "Kerberos KDC reachable"
            if port == 88:
                result.findings.append(self._finding(
                    "kerberos", ip, port, "Default Kerberos port accessible", "medium",
                    "Kerberos TCP/88 is reachable.",
                    "Restrict KDC exposure to domain clients and trusted networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "kerberos", ip, port, "KDC exposed to internet", "high",
                    f"Kerberos is reachable on public IP {ip}:{port}.",
                    "Do not expose Kerberos/KDC services directly to the internet."
                ))
            result.metadata["not_fully_verified"] = [
                "Pre-authentication not required", "Weak service account passwords",
                "RC4 encryption allowed", "Unconstrained delegation",
                "Excessive SPNs on accounts", "Long ticket lifetimes",
                "No monitoring of Kerberos events", "Weak krbtgt password",
                "Legacy encryption types enabled", "No PAC validation",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _tcp_connectable(self, ip: str, port: int) -> bool:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except Exception:
            return False

    # ─── Kubernetes ───────────────────────────────────────────────────────

    def _scan_kubernetes(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="kubernetes", ip=ip, port=port)
        try:
            base_url = self._kubernetes_base_url(ip, port)
            if not base_url:
                raise RuntimeError("Kubernetes API/Kubelet/Dashboard did not respond")
            result.metadata["base_url"] = base_url
            result.banner = "Kubernetes service"

            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "kubernetes", ip, port, "API server exposed to internet", "high",
                    f"Kubernetes-related API is reachable on public IP {ip}:{port}.",
                    "Expose Kubernetes APIs only through trusted admin networks or VPN."
                ))

            version = self._http_get_json(f"{base_url}/version") or {}
            if version:
                result.metadata["version"] = version
                result.banner = f"Kubernetes {version.get('gitVersion', '')}".strip()

            pods = self._kubernetes_get_json(base_url, "/pods")
            if not pods:
                pods = self._kubernetes_get_json(base_url, "/api/v1/pods")
            if pods and isinstance(pods.get("items"), list):
                result.metadata["pods_readable"] = True
                if port in {10250, 10255}:
                    result.findings.append(self._finding(
                        "kubernetes", ip, port, "Unauthenticated Kubelet API", "critical",
                        "Kubelet pods endpoint returned pod data without credentials.",
                        "Disable anonymous kubelet access and require client certificate/authentication."
                    ))
                else:
                    result.findings.append(self._finding(
                        "kubernetes", ip, port, "Anonymous auth enabled on API server", "critical",
                        "API server pods endpoint returned data without credentials.",
                        "Disable anonymous API access and require authenticated RBAC."
                    ))
                self._kubernetes_pod_findings(result, pods)

            secrets = self._kubernetes_get_json(base_url, "/api/v1/secrets")
            if secrets and isinstance(secrets.get("items"), list):
                result.findings.append(self._finding(
                    "kubernetes", ip, port, "Default service account tokens with excessive permissions", "critical",
                    "Secrets API is readable without credentials.",
                    "Restrict secret reads and use short-lived bound service account tokens."
                ))
                result.findings.append(self._finding(
                    "kubernetes", ip, port, "Secrets not encrypted at rest", "high",
                    "Secret objects are readable through the unauthenticated API path.",
                    "Enable encryption at rest and prevent unauthenticated secret access."
                ))

            bindings = self._kubernetes_get_json(base_url, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
            if bindings and isinstance(bindings.get("items"), list):
                cluster_admin = [
                    item.get("metadata", {}).get("name", "")
                    for item in bindings.get("items", [])
                    if item.get("roleRef", {}).get("name") == "cluster-admin"
                ]
                if cluster_admin:
                    result.findings.append(self._finding(
                        "kubernetes", ip, port, "Overly permissive RBAC (cluster-admin everywhere)", "high",
                        f"Readable RBAC shows cluster-admin bindings: {', '.join(cluster_admin[:10])}.",
                        "Review cluster-admin bindings and apply least privilege."
                    ))

            netpol = self._kubernetes_get_json(base_url, "/apis/networking.k8s.io/v1/networkpolicies")
            if netpol and isinstance(netpol.get("items"), list) and not netpol.get("items"):
                result.findings.append(self._finding(
                    "kubernetes", ip, port, "No network policies (flat network)", "medium",
                    "NetworkPolicy API is readable and no policies were returned.",
                    "Define namespace-specific NetworkPolicies for workload isolation."
                ))

            dashboard_text = self._http_get_text(base_url + "/")
            if dashboard_text and "kubernetes dashboard" in dashboard_text.lower() and "login" not in dashboard_text.lower():
                result.findings.append(self._finding(
                    "kubernetes", ip, port, "Dashboard exposed without authentication", "critical",
                    "Kubernetes Dashboard page appears reachable without a login gate.",
                    "Require authentication and avoid exposing Dashboard publicly."
                ))

            result.metadata["not_fully_verified"] = [
                "No pod security policies/admission controllers", "etcd exposed or unencrypted",
                "No audit logging enabled",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _kubernetes_base_url(self, ip: str, port: int) -> str:
        schemes = ["https", "http"] if port in {6443, 10250} else ["http", "https"]
        probes = ["/version", "/pods", "/api/v1/pods", "/"]
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            for path in probes:
                status, _, body = self._http_request(base_url + path)
                text = body.lower()
                if status in {200, 401, 403} and any(token in text for token in ["kubernetes", "kubelet", "gitversion", "podlist", "kubernetes dashboard"]):
                    return base_url
                if status in {401, 403} and port in KUBERNETES_PORTS:
                    return base_url
        return ""

    def _kubernetes_get_json(self, base_url: str, path: str) -> Dict:
        status, _, body = self._http_request(base_url + path)
        if status != 200:
            return {}
        return self._json_from_text(body)

    def _kubernetes_pod_findings(self, result: ServiceHostResult, pods: Dict) -> None:
        privileged = []
        hostpath = []
        hostns = []
        for item in pods.get("items", [])[:200]:
            metadata = item.get("metadata", {})
            spec = item.get("spec", {})
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "default")
            label = f"{namespace}/{name}"
            if spec.get("hostNetwork") or spec.get("hostPID"):
                hostns.append(label)
            for volume in spec.get("volumes", []) or []:
                if volume.get("hostPath"):
                    hostpath.append(label)
                    break
            for container in spec.get("containers", []) or []:
                security = container.get("securityContext", {}) or {}
                if security.get("privileged"):
                    privileged.append(label)
                    break
        if privileged:
            result.findings.append(self._finding(
                "kubernetes", result.ip, result.port, "Privileged pods allowed", "high",
                f"Privileged pods observed: {', '.join(privileged[:10])}.",
                "Enforce Pod Security admission and deny privileged containers."
            ))
        if hostpath:
            result.findings.append(self._finding(
                "kubernetes", result.ip, result.port, "hostPath volumes allowed", "high",
                f"Pods with hostPath volumes observed: {', '.join(hostpath[:10])}.",
                "Restrict hostPath usage with admission controls and policy."
            ))
        if hostns:
            result.findings.append(self._finding(
                "kubernetes", result.ip, result.port, "hostNetwork/hostPID enabled", "high",
                f"Pods using host namespaces observed: {', '.join(hostns[:10])}.",
                "Deny hostNetwork/hostPID except for tightly controlled system pods."
            ))

    # ─── LDAP ─────────────────────────────────────────────────────────────

    def _scan_ldap(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="ldap", ip=ip, port=port)
        sock = None
        try:
            timeout = max(3, int(getattr(self.config, "timeout", 8)))
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            if port in {636, 3269}:
                sock = ssl._create_unverified_context().wrap_socket(raw_sock, server_hostname=ip)
                result.metadata["implicit_tls"] = True
            else:
                sock = raw_sock
                result.metadata["implicit_tls"] = False

            if port in {389, 3268}:
                result.findings.append(self._finding(
                    "ldap", ip, port, "No SSL/TLS", "high",
                    f"LDAP plaintext port {port} is reachable.",
                    "Use LDAPS or require StartTLS before simple binds."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "ldap", ip, port, "LDAP exposed to internet", "high",
                    f"LDAP is reachable on public IP {ip}:{port}.",
                    "Restrict LDAP to trusted directory clients and admin networks."
                ))

            code, diagnostic = self._ldap_simple_bind(sock, 1, "", "")
            result.metadata["anonymous_bind_code"] = code
            if code == 0:
                result.findings.append(self._finding(
                    "ldap", ip, port, "Anonymous bind allowed", "critical",
                    "LDAP simple bind with empty DN/password succeeded.",
                    "Disable anonymous bind or restrict it to RootDSE-only metadata."
                ))
                result.findings.append(self._finding(
                    "ldap", ip, port, "Null bind permitted", "high",
                    "LDAP accepted an empty DN and empty password bind.",
                    "Reject null binds and require authenticated directory access."
                ))
            elif diagnostic and len(diagnostic) > 80:
                result.findings.append(self._finding(
                    "ldap", ip, port, "Verbose error messages", "low",
                    diagnostic[:250],
                    "Reduce LDAP diagnostic detail exposed to unauthenticated clients."
                ))

            root_dse = self._ldap_root_dse(sock, 2)
            if root_dse:
                result.metadata["root_dse_strings"] = root_dse[:50]
                disclosure = ", ".join(root_dse[:12])
                result.findings.append(self._finding(
                    "ldap", ip, port, "Information disclosure", "low",
                    f"RootDSE is readable: {disclosure}.",
                    "Review unauthenticated RootDSE disclosure and hide nonessential metadata."
                ))
                outdated = self._ldap_outdated_evidence(" ".join(root_dse))
                if outdated:
                    result.findings.append(self._finding(
                        "ldap", ip, port, "Outdated LDAP server", "high",
                        outdated,
                        "Upgrade LDAP directory software to a supported release."
                    ))

            result.metadata["not_fully_verified"] = [
                "Weak admin passwords", "LDAP injection vulnerabilities",
                "Excessive permissions granted", "Sensitive data in attributes",
                "No access controls", "Default configurations", "No logging enabled",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        result.scan_time = time.time() - start
        return result

    def _ldap_simple_bind(self, sock: socket.socket, message_id: int, dn: str, password: str) -> Tuple[int, str]:
        content = (
            self._ber_integer(3)
            + self._ber_octet(dn.encode("utf-8"))
            + self._ber_tlv(0x80, password.encode("utf-8"))
        )
        message = self._ldap_message(message_id, 0x60, content)
        sock.sendall(message)
        response = self._ldap_recv(sock)
        return self._ldap_result_code(response), self._ldap_diagnostic(response)

    def _ldap_root_dse(self, sock: socket.socket, message_id: int) -> List[str]:
        attrs = [b"namingContexts", b"defaultNamingContext", b"vendorName", b"vendorVersion", b"supportedSASLMechanisms"]
        attr_seq = self._ber_sequence(b"".join(self._ber_octet(attr) for attr in attrs))
        search = (
            self._ber_octet(b"")
            + self._ber_tlv(0x0A, b"\x00")
            + self._ber_tlv(0x0A, b"\x00")
            + self._ber_integer(0)
            + self._ber_integer(5)
            + self._ber_tlv(0x01, b"\x00")
            + self._ber_tlv(0x87, b"objectClass")
            + attr_seq
        )
        sock.sendall(self._ldap_message(message_id, 0x63, search))
        response = self._ldap_recv(sock, multi=True)
        strings = []
        for item in re.findall(rb"[ -~]{4,}", response):
            text = item.decode("utf-8", errors="ignore")
            if text not in strings:
                strings.append(text)
        return strings

    def _ldap_recv(self, sock: socket.socket, multi: bool = False) -> bytes:
        chunks = []
        deadline = time.time() + max(3, int(getattr(self.config, "timeout", 8)))
        while time.time() < deadline:
            try:
                data = sock.recv(8192)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            blob = b"".join(chunks)
            if not multi and blob:
                break
            if multi and b"e" in blob[-16:]:
                break
            if len(blob) > 1024 * 1024:
                break
        return b"".join(chunks)

    def _ldap_result_code(self, response: bytes) -> int:
        match = re.search(rb"\x0a\x01(.)", response, re.DOTALL)
        return match.group(1)[0] if match else -1

    def _ldap_diagnostic(self, response: bytes) -> str:
        strings = [s.decode("utf-8", errors="ignore") for s in re.findall(rb"[ -~]{8,}", response)]
        return strings[-1] if strings else ""

    def _ldap_message(self, message_id: int, op_tag: int, content: bytes) -> bytes:
        return self._ber_sequence(self._ber_integer(message_id) + self._ber_tlv(op_tag, content))

    def _ber_sequence(self, content: bytes) -> bytes:
        return self._ber_tlv(0x30, content)

    def _ber_integer(self, value: int) -> bytes:
        return self._ber_tlv(0x02, bytes([value]))

    def _ber_octet(self, value: bytes) -> bytes:
        return self._ber_tlv(0x04, value)

    def _ber_tlv(self, tag: int, value: bytes) -> bytes:
        return bytes([tag]) + self._ber_length(len(value)) + value

    def _ber_length(self, length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(encoded)]) + encoded

    def _ldap_outdated_evidence(self, text: str) -> str:
        checks = [
            (r"OpenLDAP[^\d]*(2\.[0-3])", "OpenLDAP before 2.4"),
            (r"389[- ]Directory[^\d]*(1\.[0-3])", "389 Directory Server before 1.4"),
            (r"Active Directory[^\d]*(2000|2003|2008)", "Legacy Active Directory version"),
        ]
        for pattern, label in checks:
            if re.search(pattern, text, re.IGNORECASE):
                return label
        return ""

    # ─── Memcached ───────────────────────────────────────────────────────

    def _scan_memcached(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="memcached", ip=ip, port=port)
        try:
            version = self._memcached_cmd(ip, port, "version")
            if not version.lower().startswith("version"):
                raise RuntimeError("Memcached did not respond to version command")
            result.banner = version.strip()
            result.findings.append(self._finding(
                "memcached", ip, port, "No authentication", "critical",
                "Memcached version command succeeded without authentication.",
                "Bind Memcached to localhost/private interfaces and enforce network ACLs."
            ))
            if port == 11211:
                result.findings.append(self._finding(
                    "memcached", ip, port, "Default port accessible", "medium",
                    "Memcached default port 11211 is reachable.",
                    "Restrict port 11211 to trusted application servers."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "memcached", ip, port, "Exposed to internet (0.0.0.0)", "critical",
                    f"Memcached is reachable on public IP {ip}:{port}.",
                    "Do not expose Memcached to the internet."
                ))
                result.findings.append(self._finding(
                    "memcached", ip, port, "No firewall restrictions", "high",
                    "Memcached is reachable from the scan host on a public address.",
                    "Apply host/network firewall rules for Memcached."
                ))
            result.findings.append(self._finding(
                "memcached", ip, port, "No encryption", "medium",
                "Memcached text protocol answered over plaintext TCP.",
                "Use private networks or TLS-capable proxies where encryption is required."
            ))

            stats = self._memcached_parse_stats(self._memcached_cmd(ip, port, "stats"))
            if stats:
                result.metadata["stats"] = {k: stats[k] for k in sorted(stats)[:50]}
                limit = int(stats.get("limit_maxbytes", "0") or 0)
                if limit >= 1024 * 1024 * 1024:
                    result.findings.append(self._finding(
                        "memcached", ip, port, "Large memory allocation (DDoS target)", "medium",
                        f"limit_maxbytes is {limit} bytes.",
                        "Keep Memcached private and size memory limits conservatively."
                    ))
                if int(stats.get("curr_items", "0") or 0) > 0:
                    result.metadata["cached_items_present"] = True

            if self._memcached_udp_version(ip, port):
                result.findings.append(self._finding(
                    "memcached", ip, port, "UDP protocol enabled (DDoS risk)", "critical",
                    "Memcached UDP version probe returned a response.",
                    "Disable Memcached UDP or block UDP/11211 at the firewall."
                ))
            result.metadata["not_fully_verified"] = [
                "Sensitive data cached", "Session data in cleartext", "No access logging",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _memcached_cmd(self, ip: str, port: int, command: str) -> str:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((command + "\r\n").encode("ascii", errors="ignore"))
            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                text = b"".join(chunks)
                if b"\r\nEND\r\n" in text or command == "version":
                    break
                if len(text) > 256 * 1024:
                    break
            return b"".join(chunks).decode("utf-8", errors="replace")

    def _memcached_parse_stats(self, text: str) -> Dict[str, str]:
        stats = {}
        for line in text.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0] == "STAT":
                stats[parts[1]] = parts[2]
        return stats

    def _memcached_udp_version(self, ip: str, port: int) -> bool:
        timeout = max(2, int(getattr(self.config, "timeout", 8)) // 2)
        packet = struct.pack(">HHHH", 1, 0, 1, 0) + b"version\r\n"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (ip, port))
                data, _ = sock.recvfrom(4096)
                return b"VERSION" in data.upper()
        except Exception:
            return False

    # --- MSSQL ------------------------------------------------------------

    def _scan_mssql(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="mssql", ip=ip, port=port)
        try:
            browser_info = self._mssql_browser_info(ip)
            if browser_info:
                result.metadata["sql_browser"] = browser_info
                result.findings.append(self._finding(
                    "mssql", ip, port, "SQL Server Browser service enabled", "medium",
                    "SQL Server Browser answered a UDP/1434 instance enumeration request.",
                    "Disable SQL Server Browser on internet-facing systems or restrict UDP/1434."
                ))

            prelogin = {}
            if port != 1434:
                prelogin = self._mssql_prelogin(ip, port)
            if prelogin:
                result.metadata["prelogin"] = prelogin
                version = prelogin.get("version", "")
                result.banner = f"SQL Server {version}".strip()
                encryption = prelogin.get("encryption", "")
                if encryption in {"ENCRYPT_OFF", "ENCRYPT_NOT_SUP"}:
                    result.findings.append(self._finding(
                        "mssql", ip, port, "Unencrypted connections", "high",
                        f"TDS prelogin reports encryption mode {encryption}.",
                        "Require encrypted SQL Server connections and deploy trusted certificates."
                    ))
                if self._mssql_outdated_version(version):
                    result.findings.append(self._finding(
                        "mssql", ip, port, "Outdated SQL Server version", "high",
                        f"TDS prelogin version appears old: {version}.",
                        "Upgrade SQL Server to a supported version and apply cumulative updates."
                    ))
            elif browser_info:
                result.banner = "SQL Server Browser reachable"
            else:
                raise RuntimeError("MSSQL did not respond to TDS prelogin or Browser probe")

            if port == 1433:
                result.findings.append(self._finding(
                    "mssql", ip, port, "Default SQL Server port accessible", "medium",
                    "MSSQL default port 1433 is reachable.",
                    "Restrict SQL Server listener access to trusted application/admin networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "mssql", ip, port, "MSSQL exposed to internet", "high",
                    f"MSSQL is reachable on public IP {ip}:{port}.",
                    "Do not expose MSSQL directly to the internet; require VPN/private network access."
                ))
            result.metadata["not_fully_verified"] = [
                "Default sa account with weak password", "xp_cmdshell enabled",
                "Excessive user permissions", "TRUSTWORTHY database property enabled",
                "Weak authentication using SQL auth instead of Windows auth",
                "Impersonation permissions granted", "Linked servers with high privileges",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _mssql_prelogin(self, ip: str, port: int) -> Dict[str, str]:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        payload = self._mssql_prelogin_payload()
        header = struct.pack(">BBHHBB", 0x12, 0x01, len(payload) + 8, 0, 1, 0)
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(header + payload)
            response_header = self._recv_exact(sock, 8)
            if len(response_header) != 8:
                return {}
            _, _, length, _, _, _ = struct.unpack(">BBHHBB", response_header)
            if length <= 8 or length > 65535:
                return {}
            return self._parse_mssql_prelogin(self._recv_exact(sock, length - 8))

    def _mssql_prelogin_payload(self) -> bytes:
        options = [
            (0x00, b"\x0e\x00\x00\x00\x00\x00"),
            (0x01, b"\x00"),
            (0x03, b"\x00\x00\x00\x00"),
            (0x04, b"\x00"),
        ]
        offset = len(options) * 5 + 1
        table = b""
        data = b""
        for token, value in options:
            table += struct.pack(">BHH", token, offset + len(data), len(value))
            data += value
        return table + b"\xff" + data

    def _parse_mssql_prelogin(self, data: bytes) -> Dict[str, str]:
        parsed = {}
        pos = 0
        option_map = {0x00: "version", 0x01: "encryption", 0x02: "instance", 0x03: "thread_id", 0x04: "mars"}
        encryption_map = {0: "ENCRYPT_OFF", 1: "ENCRYPT_ON", 2: "ENCRYPT_NOT_SUP", 3: "ENCRYPT_REQ"}
        while pos < len(data):
            token = data[pos]
            if token == 0xFF:
                break
            if pos + 5 > len(data):
                break
            offset, length = struct.unpack(">HH", data[pos + 1:pos + 5])
            value = data[offset:offset + length] if offset + length <= len(data) else b""
            name = option_map.get(token, f"option_{token}")
            if token == 0x00 and len(value) >= 6:
                major, minor = value[0], value[1]
                build, subbuild = struct.unpack(">HH", value[2:6])
                parsed[name] = f"{major}.{minor}.{build}.{subbuild}"
            elif token == 0x01 and value:
                parsed[name] = encryption_map.get(value[0], f"UNKNOWN_{value[0]}")
            elif token == 0x02:
                parsed[name] = value.decode("utf-8", errors="replace").strip("\x00")
            else:
                parsed[name] = value.hex()
            pos += 5
        return parsed

    def _mssql_browser_info(self, ip: str) -> Dict:
        timeout = max(2, int(getattr(self.config, "timeout", 8)) // 2)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(b"\x02", (ip, 1434))
                data, _ = sock.recvfrom(8192)
        except Exception:
            return {}
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r"^[^A-Za-z0-9]+", "", text).strip("\x00;\r\n ")
        instances = []
        for chunk in [c for c in text.split(";;") if c.strip()]:
            parts = [p for p in chunk.split(";") if p]
            item = {}
            for i in range(0, len(parts) - 1, 2):
                item[parts[i]] = parts[i + 1]
            if item:
                instances.append(item)
        return {"raw": text[:1000], "instances": instances}

    def _mssql_outdated_version(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.", version or "")
        if not match:
            return False
        return int(match.group(1)) < 15

    # --- NetBIOS / SMB ----------------------------------------------------

    def _scan_netbios(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="netbios", ip=ip, port=port)
        try:
            names = self._netbios_node_status(ip)
            if names:
                result.metadata["netbios_names"] = names
                result.banner = "NetBIOS " + ", ".join(sorted({n.get("name", "") for n in names if n.get("name")}))[:120]
                result.findings.append(self._finding(
                    "netbios", ip, port, "Information leakage via NetBIOS", "low",
                    f"NBSTAT query returned names: {', '.join(n.get('name', '') for n in names[:8])}.",
                    "Disable NetBIOS over TCP/IP where possible or restrict UDP/137."
                ))
                result.findings.append(self._finding(
                    "netbios", ip, port, "NBT-NS enabled", "medium",
                    "NetBIOS Name Service answered a node status query.",
                    "Disable NBT-NS/NetBIOS on networks where it is not required."
                ))

            shares = self._smbclient_anonymous_shares(ip)
            if shares is not None:
                result.metadata["anonymous_smb_shares"] = shares
                share_names = shares.get("shares", [])
                if share_names:
                    result.findings.append(self._finding(
                        "netbios", ip, port, "Null session allowed", "critical",
                        f"Anonymous SMB share listing succeeded: {', '.join(share_names[:10])}.",
                        "Disable anonymous/null sessions and require authenticated SMB access."
                    ))
                    non_default = [s for s in share_names if not s.endswith("$") and s.upper() != "IPC$"]
                    if non_default:
                        result.findings.append(self._finding(
                            "netbios", ip, port, "Weak share permissions", "high",
                            f"Anonymous user can enumerate non-admin shares: {', '.join(non_default[:10])}.",
                            "Review share and NTFS permissions; remove anonymous access."
                        ))

            if port in {137, 138, 139} or names:
                result.findings.append(self._finding(
                    "netbios", ip, port, "NetBIOS enabled", "medium",
                    f"NetBIOS-related service is reachable on port {port}.",
                    "Disable NetBIOS where SMB over TCP/445 is sufficient."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "netbios", ip, port, "NetBIOS enabled on internet-facing host", "high",
                    f"NetBIOS/SMB service is reachable on public IP {ip}:{port}.",
                    "Block NetBIOS/SMB at the perimeter and expose only through VPN/private networks."
                ))
                result.findings.append(self._finding(
                    "netbios", ip, port, "No network segmentation", "high",
                    "NetBIOS/SMB is reachable from the scan host on a public address.",
                    "Segment Windows file-sharing services away from untrusted networks."
                ))
            if not names and shares is None and not self._tcp_connectable(ip, port):
                raise RuntimeError("NetBIOS/SMB probes did not receive a response")
            result.metadata["not_fully_verified"] = [
                "No SMB signing", "LLMNR enabled", "Guest account enabled",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _netbios_node_status(self, ip: str) -> List[Dict[str, object]]:
        timeout = max(2, int(getattr(self.config, "timeout", 8)) // 2)
        transaction_id = int(time.time() * 1000) & 0xFFFF
        name = self._netbios_encode_name("*")
        packet = struct.pack(">HHHHHH", transaction_id, 0, 1, 0, 0, 0)
        packet += bytes([len(name)]) + name + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (ip, 137))
                data, _ = sock.recvfrom(8192)
        except Exception:
            return []
        return self._parse_netbios_node_status(data)

    def _netbios_encode_name(self, value: str) -> bytes:
        raw = value.encode("ascii", errors="ignore")[:15].ljust(15, b" ") + b"\x00"
        out = bytearray()
        for byte in raw:
            out.append(ord("A") + ((byte >> 4) & 0x0F))
            out.append(ord("A") + (byte & 0x0F))
        return bytes(out)

    def _parse_netbios_node_status(self, data: bytes) -> List[Dict[str, object]]:
        if len(data) < 57:
            return []
        pos = 12
        try:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1 + 4
            if pos + 12 > len(data):
                return []
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            if pos + 10 > len(data):
                return []
            _, _, _, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlength]
            if not rdata:
                return []
            count = rdata[0]
            names = []
            entry_pos = 1
            for _ in range(min(count, 64)):
                if entry_pos + 18 > len(rdata):
                    break
                raw_name = rdata[entry_pos:entry_pos + 15].decode("ascii", errors="replace").strip()
                suffix = rdata[entry_pos + 15]
                flags = struct.unpack(">H", rdata[entry_pos + 16:entry_pos + 18])[0]
                names.append({"name": raw_name, "suffix": f"0x{suffix:02x}", "group": bool(flags & 0x8000)})
                entry_pos += 18
            return names
        except Exception:
            return []

    def _smbclient_anonymous_shares(self, ip: str) -> Optional[Dict[str, object]]:
        timeout = max(8, int(getattr(self.config, "timeout", 8)) + 4)
        command = ["smbclient", "-g", "-L", f"//{ip}/", "-N", "-m", "SMB3"]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except (FileNotFoundError, OSError):
            return None
        except Exception as exc:
            return {"shares": [], "error": str(exc)}
        combined = (proc.stdout or "") + (proc.stderr or "")
        shares = []
        for line in combined.splitlines():
            parts = line.split("|", 2)
            if len(parts) >= 2 and parts[0].lower() in {"disk", "ipc", "printer"}:
                shares.append(parts[1].strip())
        return {"shares": sorted(set(shares)), "returncode": proc.returncode, "raw": combined[:1000]}

    # --- NFS ---------------------------------------------------------------

    def _scan_nfs(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="nfs", ip=ip, port=port)
        try:
            connectable = port != 111 and self._tcp_connectable(ip, port)
            rpc_code, rpc_text = self._run_external_command(["rpcinfo", "-p", ip])
            show_code, show_text = self._run_external_command(["showmount", "-e", ip])
            if connectable or rpc_text or show_text:
                result.banner = "NFS/RPC service reachable"
            else:
                raise RuntimeError("NFS probes did not receive a response")

            if rpc_text:
                versions = self._parse_rpcinfo_nfs_versions(rpc_text)
                result.metadata["rpcinfo"] = {"returncode": rpc_code, "nfs_versions": versions, "raw": rpc_text[:1000]}
                old_versions = [v for v in versions if int(v.get("version", 0)) <= 3]
                if old_versions:
                    result.findings.append(self._finding(
                        "nfs", ip, port, "NFSv2/v3 in use", "high",
                        f"rpcinfo reports old NFS versions: {old_versions[:5]}.",
                        "Prefer NFSv4 with strong authentication and retire NFSv2/v3."
                    ))
                    result.findings.append(self._finding(
                        "nfs", ip, port, "No authentication (NFSv3)", "high",
                        "NFSv2/v3 services rely primarily on host/IP controls rather than user authentication.",
                        "Use NFSv4 with Kerberos and strict export ACLs."
                    ))
                    result.findings.append(self._finding(
                        "nfs", ip, port, "No Kerberos authentication", "medium",
                        "NFSv2/v3 exposure indicates Kerberos is likely not enforced for these exports.",
                        "Require Kerberos-backed NFSv4 where sensitive data is exported."
                    ))

            exports = self._parse_showmount_exports(show_text)
            if show_text:
                result.metadata["showmount"] = {"returncode": show_code, "exports": exports, "raw": show_text[:1000]}
            if exports:
                result.findings.append(self._finding(
                    "nfs", ip, port, "No authentication / export list readable", "medium",
                    "showmount returned the export list without credentials.",
                    "Restrict mountd/showmount access to trusted management networks."
                ))
                for export in exports[:20]:
                    clients = export.get("clients", [])
                    path = export.get("path", "")
                    if not clients or "*" in clients or "everyone" in [c.lower() for c in clients]:
                        result.findings.append(self._finding(
                            "nfs", ip, port, "Shares exported to everyone", "critical",
                            f"Export {path} is available to {clients or ['*']}.",
                            "Replace wildcard exports with explicit trusted client IPs/subnets."
                        ))
                        result.findings.append(self._finding(
                            "nfs", ip, port, "No access restrictions by IP", "high",
                            f"Export {path} does not show a specific client allowlist.",
                            "Define explicit client restrictions for each export."
                        ))
                    if self._nfs_sensitive_export(path):
                        result.findings.append(self._finding(
                            "nfs", ip, port, "Sensitive directories exported", "high",
                            f"Sensitive-looking export path is visible: {path}.",
                            "Avoid exporting root, home, backup, config, or application data directories broadly."
                        ))

            if port == 2049:
                result.findings.append(self._finding(
                    "nfs", ip, port, "Default NFS port accessible", "medium",
                    "NFS default port 2049 is reachable.",
                    "Restrict NFS to trusted hosts and storage networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "nfs", ip, port, "NFS exposed to internet", "critical",
                    f"NFS/RPC is reachable on public IP {ip}:{port}.",
                    "Never expose NFS directly to the internet."
                ))
            result.metadata["not_fully_verified"] = [
                "no_root_squash enabled", "Writable shares", "Excessive permissions on files",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _parse_rpcinfo_nfs_versions(self, text: str) -> List[Dict[str, object]]:
        versions = []
        for line in text.splitlines():
            if "nfs" not in line.lower() or "100003" not in line:
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "100003" and parts[1].isdigit():
                versions.append({"version": int(parts[1]), "protocol": parts[2], "port": int(parts[3]) if parts[3].isdigit() else parts[3]})
        return versions

    def _parse_showmount_exports(self, text: str) -> List[Dict[str, object]]:
        exports = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("export list") or not line.startswith("/"):
                continue
            parts = line.split(None, 1)
            path = parts[0]
            clients = []
            if len(parts) > 1:
                clients = [c.strip().strip(",") for c in re.split(r"[\s,]+", parts[1]) if c.strip().strip(",")]
            exports.append({"path": path, "clients": clients})
        return exports

    def _nfs_sensitive_export(self, path: str) -> bool:
        sensitive = ["/", "/etc", "/home", "/root", "/var", "/backup", "/backups", "/data", "/srv", "/opt"]
        clean = (path or "").rstrip("/") or "/"
        return clean in sensitive or any(token in clean.lower() for token in ["backup", "secret", "private", "config"])

    # --- NTP ---------------------------------------------------------------

    def _scan_ntp(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="ntp", ip=ip, port=port)
        try:
            response = self._ntp_time_query(ip)
            if not response:
                raise RuntimeError("NTP time query did not receive a response")
            result.metadata["time_response"] = response
            result.banner = f"NTP v{response.get('version', '?')} stratum {response.get('stratum', '?')}"

            result.findings.append(self._finding(
                "ntp", ip, port, "No authentication", "medium",
                "Unauthenticated NTP client request received a time response.",
                "Use NTP authentication where appropriate and restrict clients by ACL."
            ))
            if port == 123:
                result.findings.append(self._finding(
                    "ntp", ip, port, "Default NTP port accessible", "low",
                    "NTP UDP/123 responded to a time query.",
                    "Restrict NTP service to approved clients where public time service is not intended."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "ntp", ip, port, "Exposed to internet", "high",
                    f"NTP is reachable on public IP {ip}:123.",
                    "Expose NTP publicly only when intentionally operating a hardened public time service."
                ))
                result.findings.append(self._finding(
                    "ntp", ip, port, "No access restrictions", "high",
                    "NTP time query succeeded from the scan host on a public address.",
                    "Configure restrict/ACL rules for allowed NTP clients."
                ))

            mode6 = self._ntp_mode6_readvar(ip)
            if mode6:
                result.metadata["mode6_readvar"] = mode6[:1000]
                result.findings.append(self._finding(
                    "ntp", ip, port, "Mode 6 queries allowed", "medium",
                    "NTP mode 6 readvar query returned data.",
                    "Restrict ntpq/mode 6 control queries to trusted management hosts."
                ))
                if len(mode6) > 80 or "version" in mode6.lower():
                    result.findings.append(self._finding(
                        "ntp", ip, port, "Verbose responses", "low",
                        mode6[:250],
                        "Limit control-query detail exposed to unauthenticated clients."
                    ))
                version = self._ntp_version_from_text(mode6)
                if version and self._ntp_outdated_version(version):
                    result.findings.append(self._finding(
                        "ntp", ip, port, "Outdated NTP version", "high",
                        f"Mode 6 response reports old NTP version: {version}.",
                        "Upgrade NTP to a supported release and apply vendor security updates."
                    ))

            if self._ntp_mode7_monlist(ip):
                result.findings.append(self._finding(
                    "ntp", ip, port, "Monlist command enabled", "critical",
                    "NTP mode 7/monlist-style probe returned a response.",
                    "Disable monlist/private mode 7 queries or upgrade to a version where it is removed."
                ))
                result.findings.append(self._finding(
                    "ntp", ip, port, "Mode 7 queries allowed", "high",
                    "NTP mode 7 private query received a response.",
                    "Block mode 7 control queries from untrusted networks."
                ))
            result.metadata["not_fully_verified"] = [
                "No rate limiting", "Default configuration", "No monitoring",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _ntp_time_query(self, ip: str) -> Dict[str, object]:
        timeout = max(2, int(getattr(self.config, "timeout", 8)) // 2)
        packet = b"\x1b" + (b"\x00" * 47)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (ip, 123))
                data, _ = sock.recvfrom(512)
        except Exception:
            return {}
        if len(data) < 48:
            return {}
        first = data[0]
        return {
            "leap": (first >> 6) & 0x03,
            "version": (first >> 3) & 0x07,
            "mode": first & 0x07,
            "stratum": data[1],
            "poll": data[2],
            "precision": struct.unpack("b", data[3:4])[0],
        }

    def _ntp_mode6_readvar(self, ip: str) -> str:
        packet = struct.pack("!BBHHHHH", (4 << 3) | 6, 2, 1, 0, 0, 0, 0)
        data = self._ntp_udp_probe(ip, packet, expect_mode=6)
        if len(data) < 12:
            return ""
        count = struct.unpack("!H", data[10:12])[0]
        payload = data[12:12 + count] if count else data[12:]
        return payload.decode("utf-8", errors="replace").strip("\x00\r\n ")

    def _ntp_mode7_monlist(self, ip: str) -> bool:
        packet = b"\x17\x00\x03\x2a" + b"\x00" * 4
        data = self._ntp_udp_probe(ip, packet, expect_mode=7)
        return bool(data)

    def _ntp_udp_probe(self, ip: str, packet: bytes, expect_mode: int) -> bytes:
        timeout = max(2, int(getattr(self.config, "timeout", 8)) // 2)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (ip, 123))
                data, _ = sock.recvfrom(4096)
        except Exception:
            return b""
        if data and (data[0] & 0x07) == expect_mode:
            return data
        return b""

    def _ntp_version_from_text(self, text: str) -> str:
        match = re.search(r"ntp(?:d|sec)?\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text or "", re.IGNORECASE)
        return match.group(1) if match else ""

    def _ntp_outdated_version(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version or "")
        if not match:
            return False
        parsed = tuple(int(part) for part in match.groups())
        return parsed < (4, 2, 8)

    # --- Oracle ------------------------------------------------------------

    def _scan_oracle(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="oracle", ip=ip, port=port)
        try:
            if not self._tcp_connectable(ip, port):
                raise RuntimeError("Oracle listener port did not accept a TCP connection")
            result.banner = "Oracle TNS listener reachable"
            if port in {1521, 1522, 2483}:
                result.findings.append(self._finding(
                    "oracle", ip, port, "No encryption", "high",
                    f"Oracle listener is reachable on non-TCPS port {port}.",
                    "Use TCPS/native network encryption and restrict plaintext listeners."
                ))
            if port == 1521:
                result.findings.append(self._finding(
                    "oracle", ip, port, "Default listener port accessible", "medium",
                    "Oracle default TNS listener port 1521 is reachable.",
                    "Restrict listener access to trusted application/admin networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "oracle", ip, port, "Listener exposed to internet", "high",
                    f"Oracle listener is reachable on public IP {ip}:{port}.",
                    "Do not expose Oracle listeners directly to the internet."
                ))
            result.metadata["not_fully_verified"] = [
                "Default credentials sys/change_on_install or system/manager",
                "Weak passwords on system accounts", "TNS Listener without password",
                "Excessive privileges granted to PUBLIC", "Java permissions too permissive",
                "UTL_* packages accessible to non-DBA users",
                "Outdated Oracle version with known CVEs", "Default SID names ORCL/XE",
                "Audit logging disabled", "OS authentication enabled without proper security",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _run_external_command(self, command: List[str], timeout: Optional[int] = None) -> Tuple[int, str]:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout or max(6, int(getattr(self.config, "timeout", 8))),
            )
            return proc.returncode, ((proc.stdout or "") + (proc.stderr or ""))
        except (FileNotFoundError, OSError):
            return -1, ""
        except Exception as exc:
            return -1, str(exc)

    # --- PostgreSQL -------------------------------------------------------

    def _scan_postgresql(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="postgresql", ip=ip, port=port)
        try:
            ssl_support = self._postgres_ssl_support(ip, port)
            startup = self._postgres_startup_probe(ip, port, user="postgres", database="postgres")
            if not ssl_support and not startup:
                raise RuntimeError("PostgreSQL did not respond to SSLRequest or startup probe")
            result.metadata["ssl_support"] = ssl_support
            result.metadata["startup_probe"] = startup
            version = startup.get("parameters", {}).get("server_version", "")
            result.banner = f"PostgreSQL {version}".strip() if version else "PostgreSQL reachable"

            if ssl_support == "N":
                result.findings.append(self._finding(
                    "postgresql", ip, port, "No SSL/TLS encryption", "high",
                    "PostgreSQL SSLRequest returned N, indicating SSL is not supported on this listener.",
                    "Enable SSL/TLS and require encrypted client connections."
                ))
            if startup.get("auth_code") == 0:
                result.findings.append(self._finding(
                    "postgresql", ip, port, "pg_hba.conf allows trust authentication", "critical",
                    "Startup probe for user postgres completed without a password challenge.",
                    "Remove trust rules from pg_hba.conf and require SCRAM or certificate authentication."
                ))
                result.findings.append(self._finding(
                    "postgresql", ip, port, "Superuser accessible remotely", "critical",
                    "The postgres account appears reachable remotely without a password challenge.",
                    "Do not allow superuser roles to authenticate remotely without strong controls."
                ))
            if port == 5432:
                result.findings.append(self._finding(
                    "postgresql", ip, port, "Default PostgreSQL port exposed", "medium",
                    "PostgreSQL default port 5432 is reachable.",
                    "Restrict PostgreSQL to trusted application/admin networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "postgresql", ip, port, "Wide open firewall rules", "high",
                    f"PostgreSQL is reachable on public IP {ip}:{port}.",
                    "Block PostgreSQL at the perimeter and allow only trusted client networks."
                ))
            if self._postgres_outdated_version(version):
                result.findings.append(self._finding(
                    "postgresql", ip, port, "Outdated PostgreSQL version", "high",
                    f"Server version appears old: {version}.",
                    "Upgrade PostgreSQL to a supported major release."
                ))
            result.metadata["not_fully_verified"] = [
                "Default credentials postgres/postgres", "Weak passwords",
                "Unnecessary extensions installed", "Logging disabled",
                "COPY PROGRAM enabled for non-superusers", "File system functions accessible",
                "No connection limits",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _postgres_ssl_support(self, ip: str, port: int) -> str:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        packet = struct.pack("!II", 8, 80877103)
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(packet)
                return sock.recv(1).decode("ascii", errors="ignore")
        except Exception:
            return ""

    def _postgres_startup_probe(self, ip: str, port: int, user: str, database: str) -> Dict:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        params = b"user\x00" + user.encode() + b"\x00database\x00" + database.encode() + b"\x00application_name\x00ReconX\x00\x00"
        body = struct.pack("!I", 196608) + params
        packet = struct.pack("!I", len(body) + 4) + body
        parsed = {"auth_code": None, "auth_method": "", "parameters": {}, "error": ""}
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(packet)
                while True:
                    header = self._recv_exact(sock, 5)
                    if len(header) != 5:
                        break
                    msg_type = header[:1].decode("ascii", errors="ignore")
                    length = struct.unpack("!I", header[1:])[0]
                    if length < 4 or length > 1024 * 1024:
                        break
                    payload = self._recv_exact(sock, length - 4)
                    if msg_type == "R" and len(payload) >= 4:
                        code = struct.unpack("!I", payload[:4])[0]
                        parsed["auth_code"] = code
                        parsed["auth_method"] = self._postgres_auth_name(code)
                        if code != 0:
                            break
                    elif msg_type == "S":
                        parts = payload.split(b"\x00")
                        if len(parts) >= 2:
                            parsed["parameters"][parts[0].decode(errors="replace")] = parts[1].decode(errors="replace")
                    elif msg_type == "E":
                        parsed["error"] = self._postgres_error_message(payload)
                        break
                    elif msg_type == "Z":
                        break
        except Exception:
            return {}
        return parsed

    def _postgres_auth_name(self, code: int) -> str:
        return {
            0: "AuthenticationOk", 3: "CleartextPassword", 5: "MD5Password",
            10: "SASL", 11: "SASLContinue", 12: "SASLFinal",
        }.get(code, f"AuthCode{code}")

    def _postgres_error_message(self, payload: bytes) -> str:
        fields = {}
        for item in payload.split(b"\x00"):
            if len(item) >= 2:
                fields[item[:1].decode(errors="ignore")] = item[1:].decode(errors="replace")
        return fields.get("M", "")[:500]

    def _postgres_outdated_version(self, version: str) -> bool:
        match = re.match(r"^(\d+)", version or "")
        return bool(match and int(match.group(1)) < 14)

    # --- RabbitMQ ---------------------------------------------------------

    def _scan_rabbitmq(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="rabbitmq", ip=ip, port=port)
        try:
            if port in {15671, 15672}:
                base_url = f"{'https' if port == 15671 else 'http'}://{ip}:{port}"
                overview_status, headers, body = self._http_request(base_url + "/api/overview")
                result.metadata["management_url"] = base_url
                result.metadata["management_status"] = overview_status
                result.banner = "RabbitMQ management interface"
                if overview_status in {200, 401, 403}:
                    result.findings.append(self._finding(
                        "rabbitmq", ip, port, "Management interface exposed", "high",
                        f"RabbitMQ management API responded with HTTP {overview_status}.",
                        "Restrict the management interface to trusted admin networks."
                    ))
                if overview_status == 200:
                    result.findings.append(self._finding(
                        "rabbitmq", ip, port, "No authentication on management API", "critical",
                        "RabbitMQ /api/overview returned data without credentials.",
                        "Require authentication and least-privilege permissions for management API access."
                    ))
                    data = self._json_from_text(body)
                    if data:
                        result.metadata["overview"] = data
                        version = str(data.get("rabbitmq_version", ""))
                        if version and self._rabbitmq_outdated_version(version):
                            result.findings.append(self._finding(
                                "rabbitmq", ip, port, "Outdated RabbitMQ version", "high",
                                f"RabbitMQ version reported as {version}.",
                                "Upgrade RabbitMQ to a supported release."
                            ))
                if base_url.startswith("http://"):
                    result.findings.append(self._finding(
                        "rabbitmq", ip, port, "No TLS/SSL encryption", "high",
                        f"Management API is reachable over plaintext HTTP at {base_url}.",
                        "Serve RabbitMQ management only over HTTPS."
                    ))
                if "rabbitmq" in body.lower() and "error" in body.lower():
                    result.findings.append(self._finding(
                        "rabbitmq", ip, port, "Verbose error messages", "low",
                        body[:250],
                        "Avoid exposing detailed management errors to untrusted clients."
                    ))
            elif port == 4369:
                if not self._tcp_connectable(ip, port):
                    raise RuntimeError("RabbitMQ EPMD port did not accept a TCP connection")
                result.banner = "Erlang EPMD reachable"
                result.findings.append(self._finding(
                    "rabbitmq", ip, port, "Erlang distribution exposed", "high",
                    "Erlang port mapper daemon is reachable.",
                    "Restrict EPMD/Erlang distribution ports to RabbitMQ cluster nodes only."
                ))
            else:
                amqp = self._rabbitmq_amqp_probe(ip, port, tls=(port == 5671))
                if not amqp:
                    raise RuntimeError("AMQP listener did not respond")
                result.metadata["amqp"] = amqp
                result.banner = amqp.get("banner", "AMQP listener reachable")
                if port == 5672:
                    result.findings.append(self._finding(
                        "rabbitmq", ip, port, "No TLS/SSL encryption", "high",
                        "AMQP plaintext port 5672 responded to protocol negotiation.",
                        "Use AMQPS on 5671 or require TLS for AMQP clients."
                    ))
                if amqp.get("mechanisms") and "PLAIN" in amqp.get("mechanisms", ""):
                    result.findings.append(self._finding(
                        "rabbitmq", ip, port, "Plain password authentication advertised", "medium",
                        f"AMQP mechanisms include {amqp.get('mechanisms')}.",
                        "Only allow password mechanisms over TLS and prefer strong auth controls."
                    ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "rabbitmq", ip, port, "RabbitMQ exposed to internet", "high",
                    f"RabbitMQ-related service is reachable on public IP {ip}:{port}.",
                    "Do not expose RabbitMQ brokers or management interfaces publicly."
                ))
            result.metadata["not_fully_verified"] = [
                "Default credentials guest/guest", "Weak admin passwords", "Guest account enabled remotely",
                "Overly permissive user permissions", "No authentication on AMQP port",
                "Erlang cookie exposed or weak", "Shovel/Federation plugins misconfigured",
                "No rate limiting on message publishing", "Sensitive data in messages", "No message encryption",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _rabbitmq_amqp_probe(self, ip: str, port: int, tls: bool = False) -> Dict[str, str]:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        sock = None
        try:
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            sock = ssl._create_unverified_context().wrap_socket(raw_sock, server_hostname=ip) if tls else raw_sock
            sock.sendall(b"AMQP\x00\x00\x09\x01")
            data = sock.recv(8192)
            text = data.decode("latin1", errors="replace")
            mechanisms = ""
            match = re.search(r"(PLAIN(?:\s+AMQPLAIN)?|AMQPLAIN(?:\s+PLAIN)?)", text)
            if match:
                mechanisms = match.group(1)
            version_match = re.search(r"RabbitMQ[^\x00-\x1f]{0,80}?([0-9]+\.[0-9]+\.[0-9]+)", text, re.IGNORECASE)
            return {
                "banner": "RabbitMQ AMQP" if b"AMQP" not in data[:8] else "AMQP listener",
                "mechanisms": mechanisms,
                "version": version_match.group(1) if version_match else "",
                "raw": text[:500],
            }
        except Exception:
            return {}
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _rabbitmq_outdated_version(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.(\d+)", version or "")
        return bool(match and (int(match.group(1)), int(match.group(2))) < (3, 12))

    # --- RDP --------------------------------------------------------------

    def _scan_rdp(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="rdp", ip=ip, port=port)
        try:
            negotiation = self._rdp_negotiation(ip, port)
            if not negotiation:
                raise RuntimeError("RDP negotiation did not respond")
            result.metadata["negotiation"] = negotiation
            result.banner = f"RDP {negotiation.get('selected_protocol', 'reachable')}"
            selected = negotiation.get("selected_protocol", "")
            if selected in {"RDP", "TLS"}:
                result.findings.append(self._finding(
                    "rdp", ip, port, "No Network Level Authentication (NLA)", "critical",
                    f"RDP selected protocol {selected} instead of CredSSP/NLA.",
                    "Require Network Level Authentication for all RDP listeners."
                ))
            if selected == "RDP":
                result.findings.append(self._finding(
                    "rdp", ip, port, "Weak encryption settings", "high",
                    "Server selected legacy Standard RDP Security.",
                    "Disable legacy RDP security and require TLS/CredSSP."
                ))
            if port == 3389:
                result.findings.append(self._finding(
                    "rdp", ip, port, "Default RDP port exposed", "medium",
                    "RDP default port 3389 is reachable.",
                    "Restrict RDP to VPN/jump hosts and trusted admin networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "rdp", ip, port, "Exposed to internet", "critical",
                    f"RDP is reachable on public IP {ip}:{port}.",
                    "Do not expose RDP directly to the internet; require VPN, MFA, and allowlists."
                ))
            result.metadata["not_fully_verified"] = [
                "Weak or default passwords", "No account lockout policy", "No certificate validation",
                "Clipboard sharing enabled", "Drive redirection enabled", "Outdated Windows version",
                "No multi-factor authentication", "Unnecessary users with RDP access", "No logging or monitoring",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _rdp_negotiation(self, ip: str, port: int) -> Dict[str, str]:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        request = bytes.fromhex("030000130ee000000000000100080003000000")
        protocol_map = {0: "RDP", 1: "TLS", 2: "CredSSP", 8: "CredSSP Early User Auth"}
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(request)
                data = sock.recv(4096)
        except Exception:
            return {}
        marker = data.find(b"\x02\x00\x08\x00")
        if marker >= 0 and marker + 8 <= len(data):
            selected = struct.unpack("<I", data[marker + 4:marker + 8])[0]
            return {"selected_protocol": protocol_map.get(selected, f"unknown:{selected}"), "raw": data.hex()[:200]}
        failure = data.find(b"\x03\x00\x08\x00")
        if failure >= 0 and failure + 8 <= len(data):
            code = struct.unpack("<I", data[failure + 4:failure + 8])[0]
            return {"selected_protocol": "negotiation_failed", "failure_code": str(code), "raw": data.hex()[:200]}
        return {"selected_protocol": "unknown", "raw": data.hex()[:200]}

    # --- Redis ------------------------------------------------------------

    def _scan_redis(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="redis", ip=ip, port=port)
        try:
            ping = self._redis_cmd(ip, port, "PING")
            if not ping:
                raise RuntimeError("Redis did not respond to PING")
            result.metadata["ping"] = ping[:200]
            result.banner = "Redis reachable"
            if ping.startswith("+PONG"):
                result.findings.append(self._finding(
                    "redis", ip, port, "No authentication (no requirepass)", "critical",
                    "PING returned PONG without authentication.",
                    "Set requirepass/ACL users and bind Redis to trusted interfaces only."
                ))
                info = self._redis_cmd(ip, port, "INFO")
                info_map = self._redis_parse_info(info)
                if info_map:
                    result.metadata["info"] = {k: info_map[k] for k in sorted(info_map)[:80]}
                    version = info_map.get("redis_version", "")
                    result.banner = f"Redis {version}".strip()
                    if info_map.get("protected_mode", "").lower() == "no":
                        result.findings.append(self._finding(
                            "redis", ip, port, "Protected mode disabled", "critical",
                            "INFO reports protected_mode:no.",
                            "Enable protected mode and use explicit bind/ACL configuration."
                        ))
                config = self._redis_cmd(ip, port, "CONFIG", "GET", "*")
                if config and not config.startswith("-"):
                    result.metadata["config_accessible"] = True
                    result.findings.append(self._finding(
                        "redis", ip, port, "CONFIG command accessible", "critical",
                        "CONFIG GET * succeeded without authentication.",
                        "Rename/disable dangerous administrative commands and require ACLs."
                    ))
                    if "\r\nrename-command\r\n" not in config.lower():
                        result.findings.append(self._finding(
                            "redis", ip, port, "Dangerous commands not renamed", "high",
                            "CONFIG output is readable and dangerous command renames were not evident.",
                            "Rename or disable CONFIG, EVAL, MODULE, SAVE, SLAVEOF/REPLICAOF where not needed."
                        ))
                    if re.search(r"\r\ndir\r\n\$\d+\r\n", config, re.IGNORECASE):
                        result.findings.append(self._finding(
                            "redis", ip, port, "Writable directories accessible", "medium",
                            "CONFIG exposes Redis dir/dbfilename settings.",
                            "Restrict filesystem write paths and disable CONFIG access to untrusted users."
                        ))
                command_info = self._redis_cmd(ip, port, "COMMAND", "INFO", "EVAL", "MODULE", "CONFIG")
                if command_info and "eval" in command_info.lower():
                    result.findings.append(self._finding(
                        "redis", ip, port, "Lua scripting enabled", "medium",
                        "COMMAND INFO shows EVAL is available.",
                        "Restrict Lua scripting to trusted users or disable it where possible."
                    ))
                if command_info and "module" in command_info.lower():
                    result.findings.append(self._finding(
                        "redis", ip, port, "Module loading allowed", "high",
                        "COMMAND INFO shows MODULE is available.",
                        "Restrict module loading to administrators only or disable it."
                    ))
            if port == 6379:
                result.findings.append(self._finding(
                    "redis", ip, port, "Default port exposed", "medium",
                    "Redis default port 6379 is reachable.",
                    "Restrict Redis to trusted application hosts and private networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "redis", ip, port, "Exposed to internet (bind 0.0.0.0)", "critical",
                    f"Redis is reachable on public IP {ip}:{port}.",
                    "Bind Redis to localhost/private IPs and block public access with firewall rules."
                ))
                result.findings.append(self._finding(
                    "redis", ip, port, "No firewall restrictions", "high",
                    "Redis is reachable from the scan host on a public address.",
                    "Apply strict network ACLs for Redis."
                ))
            result.findings.append(self._finding(
                "redis", ip, port, "No SSL/TLS encryption", "medium",
                "Redis answered on a plaintext TCP listener.",
                "Use Redis TLS or a trusted private network for Redis traffic."
            ))
            result.metadata["not_fully_verified"] = ["Weak password"]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _redis_cmd(self, ip: str, port: int, *args: str) -> str:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        encoded = f"*{len(args)}\r\n".encode("ascii")
        for arg in args:
            raw = str(arg).encode("utf-8")
            encoded += f"${len(raw)}\r\n".encode("ascii") + raw + b"\r\n"
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(encoded)
                chunks = []
                while True:
                    try:
                        data = sock.recv(8192)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
                    text = b"".join(chunks)
                    if text.startswith((b"+", b"-", b":")) and text.endswith(b"\r\n"):
                        break
                    if text.startswith(b"$"):
                        header_end = text.find(b"\r\n")
                        if header_end > 0:
                            try:
                                size = int(text[1:header_end])
                                if size < 0 or len(text) >= header_end + 2 + size + 2:
                                    break
                            except ValueError:
                                pass
                    if sum(len(chunk) for chunk in chunks) > 512 * 1024:
                        break
                return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _redis_parse_info(self, text: str) -> Dict[str, str]:
        out = {}
        for line in text.splitlines():
            if not line or line.startswith(("#", "$")) or ":" not in line:
                continue
            key, value = line.split(":", 1)
            out[key.strip()] = value.strip()
        return out

    # --- TFTP -------------------------------------------------------------

    def _scan_tftp(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="tftp", ip=ip, port=port)
        try:
            probe = self._tftp_rrq(ip, port, "reconx-nonexistent-test", timeout=3)
            if not probe:
                raise RuntimeError("TFTP probe did not receive a response")
            result.metadata["probe"] = probe
            result.banner = "TFTP reachable"
            result.findings.append(self._finding(
                "tftp", ip, port, "No authentication required", "high",
                "TFTP server responded to an unauthenticated read request.",
                "Replace TFTP where possible or restrict it to isolated provisioning networks."
            ))
            result.findings.append(self._finding(
                "tftp", ip, port, "No encryption", "medium",
                "TFTP uses unauthenticated plaintext UDP transport.",
                "Use secure transfer protocols for sensitive or persistent file storage."
            ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "tftp", ip, port, "Exposed to internet", "critical",
                    f"TFTP is reachable on public IP {ip}:{port}.",
                    "Block TFTP at the perimeter and expose it only on trusted provisioning networks."
                ))
                result.findings.append(self._finding(
                    "tftp", ip, port, "Accessible from untrusted networks", "high",
                    "TFTP answered from the scan host network.",
                    "Restrict TFTP by firewall and network segmentation."
                ))
            sensitive_hits = []
            for name in ["startup-config", "running-config", "config", "pxelinux.cfg/default", "boot.ini"]:
                rrq = self._tftp_rrq(ip, port, name, timeout=2)
                if rrq.get("opcode") == 3:
                    sensitive_hits.append(name)
            if sensitive_hits:
                result.findings.append(self._finding(
                    "tftp", ip, port, "Serving sensitive files", "critical",
                    f"Sensitive-looking files were readable: {', '.join(sensitive_hits[:10])}.",
                    "Remove sensitive files from TFTP roots and enforce strict file allowlists."
                ))
                result.findings.append(self._finding(
                    "tftp", ip, port, "No file access restrictions", "high",
                    "TFTP returned data for sensitive-looking filenames.",
                    "Restrict the TFTP root to only required provisioning artifacts."
                ))
            result.metadata["not_fully_verified"] = [
                "Write access enabled", "Root directory misconfigured", "No logging enabled",
                "Running with excessive permissions", "Default configuration unchanged",
                "Used for permanent file storage",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _tftp_rrq(self, ip: str, port: int, filename: str, timeout: int = 3) -> Dict[str, object]:
        packet = struct.pack("!H", 1) + filename.encode("utf-8", errors="ignore") + b"\x00octet\x00"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (ip, port))
                data, _ = sock.recvfrom(2048)
        except Exception:
            return {}
        if len(data) < 2:
            return {}
        opcode = struct.unpack("!H", data[:2])[0]
        out = {"opcode": opcode, "length": len(data)}
        if opcode == 5 and len(data) >= 4:
            out["error_code"] = struct.unpack("!H", data[2:4])[0]
            out["error"] = data[4:].decode("utf-8", errors="replace").strip("\x00")[:200]
        return out

    # --- Tomcat -----------------------------------------------------------

    def _scan_tomcat(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="tomcat", ip=ip, port=port)
        try:
            if port == 8009:
                if not self._tcp_connectable(ip, port):
                    raise RuntimeError("AJP port did not accept a TCP connection")
                result.banner = "Tomcat AJP reachable"
                result.findings.append(self._finding(
                    "tomcat", ip, port, "AJP connector exposed", "critical",
                    "Tomcat AJP connector port 8009 is reachable.",
                    "Disable AJP or bind it to localhost/private connector networks with a secret."
                ))
            else:
                base_url, status, headers, body = self._tomcat_find_base(ip, port)
                if not base_url:
                    raise RuntimeError("Tomcat HTTP endpoint did not respond")
                result.metadata["base_url"] = base_url
                result.metadata["root_status"] = status
                server = headers.get("server", "")
                version = self._tomcat_version("\n".join([server, body[:1000]]))
                result.banner = f"Apache Tomcat {version}".strip() if version else "Tomcat HTTP reachable"
                if base_url.startswith("http://"):
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "No HTTPS", "high",
                        f"Tomcat is reachable over plaintext HTTP at {base_url}.",
                        "Serve Tomcat applications over HTTPS only."
                    ))
                manager_status, _, manager_body = self._http_request(base_url + "/manager/html")
                if manager_status in {200, 401, 403}:
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "Manager application accessible externally", "high",
                        f"/manager/html responded with HTTP {manager_status}.",
                        "Restrict manager apps to trusted admin networks and remove them if unused."
                    ))
                if manager_status == 200 and "tomcat web application manager" in manager_body.lower():
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "No authentication required for manager", "critical",
                        "Tomcat Manager returned the manager UI without authentication.",
                        "Require strong authentication and role separation for manager access."
                    ))
                options_status, options_headers, _ = self._http_request(base_url + "/", method="OPTIONS")
                allow = options_headers.get("allow", "")
                if options_status and "PUT" in allow.upper():
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "PUT method enabled", "critical",
                        f"OPTIONS Allow header includes: {allow}.",
                        "Disable HTTP PUT unless explicitly required and authenticated."
                    ))
                if version and self._tomcat_outdated_version(version):
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "Outdated Tomcat version", "high",
                        f"Tomcat version appears old: {version}.",
                        "Upgrade Tomcat to a supported patched release."
                    ))
                for path in ["/examples/", "/docs/", "/host-manager/html"]:
                    p_status, _, p_body = self._http_request(base_url + path)
                    if p_status == 200 and any(token in p_body.lower() for token in ["apache tomcat", "manager", "examples"]):
                        result.findings.append(self._finding(
                            "tomcat", ip, port, "Example or admin applications not removed", "medium",
                            f"{path} responded with HTTP 200.",
                            "Remove Tomcat examples/docs/host-manager apps from production deployments."
                        ))
                        break
                listing_status, _, listing_body = self._http_request(base_url + "/docs/")
                if listing_status == 200 and "index of" in listing_body.lower():
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "Directory listing enabled", "medium",
                        "/docs/ appears to expose a directory listing.",
                        "Disable directory listings for Tomcat web applications."
                    ))
                sensitive_status, _, sensitive_body = self._http_request(base_url + "/conf/tomcat-users.xml")
                if sensitive_status == 200 and "tomcat-users" in sensitive_body.lower():
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "Sensitive files accessible", "critical",
                        "/conf/tomcat-users.xml is readable over HTTP.",
                        "Block access to configuration files and remove them from webroots."
                    ))
                error_status, _, error_body = self._http_request(base_url + "/reconx-invalid-%7B")
                if error_status >= 500 or "exception" in error_body.lower() or "stacktrace" in error_body.lower():
                    result.findings.append(self._finding(
                        "tomcat", ip, port, "Verbose error messages", "low",
                        error_body[:250],
                        "Disable verbose stack traces and detailed errors for external clients."
                    ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "tomcat", ip, port, "Tomcat exposed to internet", "high",
                    f"Tomcat service is reachable on public IP {ip}:{port}.",
                    "Expose only required application paths and restrict admin connectors."
                ))
            result.metadata["not_fully_verified"] = [
                "Default credentials tomcat/tomcat or admin/admin", "Weak authentication", "Running as root/SYSTEM",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _tomcat_find_base(self, ip: str, port: int) -> Tuple[str, int, Dict[str, str], str]:
        schemes = ["https", "http"] if port == 8443 else ["http", "https"]
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            status, headers, body = self._http_request(base_url + "/")
            if status and ("tomcat" in body.lower() or "tomcat" in headers.get("server", "").lower() or port in TOMCAT_PORTS):
                return base_url, status, headers, body
        return "", 0, {}, ""

    def _tomcat_version(self, text: str) -> str:
        match = re.search(r"Tomcat[/\s-]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text or "", re.IGNORECASE)
        return match.group(1) if match else ""

    def _tomcat_outdated_version(self, version: str) -> bool:
        match = re.match(r"^(\d+)\.(\d+)", version or "")
        return bool(match and int(match.group(1)) < 10)

    # --- VNC --------------------------------------------------------------

    def _scan_vnc(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="vnc", ip=ip, port=port)
        try:
            probe = self._vnc_probe(ip, port)
            if not probe:
                raise RuntimeError("VNC/RFB handshake did not respond")
            result.metadata["handshake"] = probe
            result.banner = probe.get("protocol", "VNC reachable")
            security_types = probe.get("security_types", [])
            if 1 in security_types:
                result.findings.append(self._finding(
                    "vnc", ip, port, "No authentication (None auth type)", "critical",
                    "RFB security type list includes None authentication.",
                    "Disable None authentication and require strong VNC authentication behind VPN."
                ))
            result.findings.append(self._finding(
                "vnc", ip, port, "No encryption (standard VNC)", "high",
                "VNC/RFB handshake completed without a TLS wrapper.",
                "Use encrypted VNC variants or tunnel VNC through VPN/SSH."
            ))
            if port in VNC_PORTS:
                result.findings.append(self._finding(
                    "vnc", ip, port, "Default ports exposed", "medium",
                    f"VNC default-style port {port} is reachable.",
                    "Restrict VNC ports to trusted management networks."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "vnc", ip, port, "Exposed to internet", "critical",
                    f"VNC is reachable on public IP {ip}:{port}.",
                    "Do not expose VNC directly to the internet."
                ))
                result.findings.append(self._finding(
                    "vnc", ip, port, "No network isolation", "high",
                    "VNC is reachable from the scan host on a public address.",
                    "Place VNC behind VPN/jump hosts and strict firewall rules."
                ))
            if "003.003" in probe.get("protocol", ""):
                result.findings.append(self._finding(
                    "vnc", ip, port, "Outdated VNC server", "medium",
                    f"Server uses old RFB protocol: {probe.get('protocol')}.",
                    "Upgrade the VNC server and require modern security types."
                ))
            result.metadata["not_fully_verified"] = [
                "Weak VNC passwords", "Clipboard sharing enabled", "File transfer enabled", "No connection logging",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _vnc_probe(self, ip: str, port: int) -> Dict[str, object]:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                proto = sock.recv(12)
                if not proto.startswith(b"RFB"):
                    return {}
                sock.sendall(proto)
                version = proto.decode("ascii", errors="replace").strip()
                if version.endswith("003.003"):
                    raw = self._recv_exact(sock, 4)
                    sec = [struct.unpack("!I", raw)[0]] if len(raw) == 4 else []
                else:
                    count_raw = self._recv_exact(sock, 1)
                    if not count_raw:
                        return {"protocol": version, "security_types": []}
                    count = count_raw[0]
                    sec = list(self._recv_exact(sock, count)) if count else []
                return {"protocol": version, "security_types": sec}
        except Exception:
            return {}

    # --- WebDAV -----------------------------------------------------------

    def _scan_webdav(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="webdav", ip=ip, port=port)
        try:
            base_url = self._webdav_base_url(ip, port)
            if not base_url:
                raise RuntimeError("WebDAV endpoint did not respond")
            result.metadata["base_url"] = base_url
            result.banner = "WebDAV reachable"
            options_status, options_headers, options_body = self._http_request(base_url + "/", method="OPTIONS")
            allow = options_headers.get("allow", "")
            dav = options_headers.get("dav", "")
            result.metadata["options"] = {"status": options_status, "allow": allow, "dav": dav}
            if base_url.startswith("http://"):
                result.findings.append(self._finding(
                    "webdav", ip, port, "No SSL/TLS encryption", "high",
                    f"WebDAV endpoint is reachable over HTTP at {base_url}.",
                    "Require HTTPS for WebDAV endpoints."
                ))
            if "PUT" in allow.upper():
                result.findings.append(self._finding(
                    "webdav", ip, port, "PUT method enabled", "critical",
                    f"OPTIONS Allow header includes: {allow}.",
                    "Disable WebDAV writes unless authenticated and tightly scoped."
                ))
                result.findings.append(self._finding(
                    "webdav", ip, port, "Writable webroot possible", "high",
                    "PUT is advertised by the WebDAV endpoint.",
                    "Ensure upload paths are not web-executable and require strict authorization."
                ))
            if "DELETE" in allow.upper():
                result.findings.append(self._finding(
                    "webdav", ip, port, "DELETE method enabled", "high",
                    f"OPTIONS Allow header includes: {allow}.",
                    "Disable DELETE for untrusted clients."
                ))
            propfind_status, propfind_headers, propfind_body = self._http_request(
                base_url + "/", method="PROPFIND", headers={"Depth": "0"}
            )
            result.metadata["propfind_status"] = propfind_status
            if propfind_status in {200, 207}:
                result.findings.append(self._finding(
                    "webdav", ip, port, "No authentication required", "critical",
                    f"PROPFIND returned HTTP {propfind_status} without credentials.",
                    "Require authentication and authorization for all WebDAV methods."
                ))
            get_status, _, get_body = self._http_request(base_url + "/")
            if get_status == 200 and "index of" in get_body.lower():
                result.findings.append(self._finding(
                    "webdav", ip, port, "Directory listing enabled", "medium",
                    "Root path appears to expose a directory listing.",
                    "Disable directory listing on WebDAV-backed paths."
                ))
            if any(token in options_body.lower() + propfind_body.lower() for token in ["exception", "stack trace", "traceback"]):
                result.findings.append(self._finding(
                    "webdav", ip, port, "Verbose error messages", "low",
                    (options_body + propfind_body)[:250],
                    "Reduce detailed WebDAV error output."
                ))
            result.metadata["not_fully_verified"] = [
                "Weak credentials", "No file type restrictions", "No upload size limits",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    def _webdav_base_url(self, ip: str, port: int) -> str:
        schemes = ["https", "http"] if port in {443, 8443} else ["http", "https"]
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            status, headers, _ = self._http_request(base_url + "/", method="OPTIONS")
            if headers.get("dav") or "PROPFIND" in headers.get("allow", "").upper() or status in {207}:
                return base_url
        return ""

    # --- WinRM ------------------------------------------------------------

    def _scan_winrm(self, ip: str, port: int) -> ServiceHostResult:
        start = time.time()
        result = ServiceHostResult(service="winrm", ip=ip, port=port)
        try:
            scheme = "https" if port == 5986 else "http"
            base_url = f"{scheme}://{ip}:{port}"
            status, headers, body = self._http_request(base_url + "/wsman")
            if status == 0 and not self._tcp_connectable(ip, port):
                raise RuntimeError("WinRM did not respond")
            result.metadata["base_url"] = base_url
            result.metadata["status"] = status
            result.metadata["headers"] = {k: headers[k] for k in sorted(headers) if k in {"server", "www-authenticate"}}
            result.banner = headers.get("server", "WinRM reachable") or "WinRM reachable"
            if port == 5985 or base_url.startswith("http://"):
                result.findings.append(self._finding(
                    "winrm", ip, port, "Unencrypted traffic", "high",
                    "WinRM HTTP port 5985 is reachable.",
                    "Prefer WinRM over HTTPS with trusted certificates or restrict HTTP to trusted networks."
                ))
                result.findings.append(self._finding(
                    "winrm", ip, port, "No certificate validation (HTTP instead of HTTPS)", "medium",
                    "WinRM is exposed over HTTP rather than HTTPS.",
                    "Use HTTPS listeners and validate certificates."
                ))
            auth_header = headers.get("www-authenticate", "")
            if "credssp" in auth_header.lower():
                result.findings.append(self._finding(
                    "winrm", ip, port, "CredSSP enabled", "high",
                    f"WWW-Authenticate advertises CredSSP: {auth_header}.",
                    "Disable CredSSP unless explicitly required and tightly controlled."
                ))
            if status in {200, 401, 405} or "Microsoft-HTTPAPI" in result.banner:
                result.findings.append(self._finding(
                    "winrm", ip, port, "WinRM enabled", "medium",
                    f"WinRM /wsman responded with HTTP {status}.",
                    "Enable WinRM only on systems that require remote management."
                ))
            if self._is_public_ip(ip):
                result.findings.append(self._finding(
                    "winrm", ip, port, "Unrestricted WinRM access", "high",
                    f"WinRM is reachable on public IP {ip}:{port}.",
                    "Restrict WinRM to admin subnets, VPN, or jump hosts."
                ))
                result.findings.append(self._finding(
                    "winrm", ip, port, "No network segmentation", "high",
                    "WinRM is reachable from the scan host on a public address.",
                    "Segment Windows remote management from untrusted networks."
                ))
            result.metadata["not_fully_verified"] = [
                "Weak or default credentials", "WinRM enabled on all machines",
                "Excessive user permissions", "TrustedHosts set to *", "No logging or monitoring of WinRM sessions",
            ]
        except Exception as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        result.scan_time = time.time() - start
        return result

    # ─── Generic HTTP helpers ─────────────────────────────────────────────

    def _http_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, str], str]:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        request_headers = {"User-Agent": "ReconX"}
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        context = ssl._create_unverified_context() if url.startswith("https://") else None
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                body = response.read(1024 * 1024).decode("utf-8", errors="replace")
                return response.status, {k.lower(): v for k, v in response.headers.items()}, body
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(256 * 1024).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body
        except Exception:
            return 0, {}, ""

    def _json_from_text(self, text: str) -> Dict:
        try:
            parsed = json.loads(text) if text else {}
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}

    def _http_get_first_json(self, ip: str, port: int, schemes: List[str], path: str) -> Tuple[str, Optional[Dict]]:
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            data = self._http_get_json(base_url + path)
            if isinstance(data, dict) and data:
                return base_url, data
        return "", None

    def _http_get_first_text(self, ip: str, port: int, schemes: List[str], path: str) -> Tuple[str, str]:
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            text = self._http_get_text(base_url + path)
            if text:
                return base_url, text
        return "", ""

    def _http_get_json(self, url: str) -> Optional[object]:
        text = self._http_get_text(url)
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def _http_get_text(self, url: str) -> str:
        timeout = max(3, int(getattr(self.config, "timeout", 8)))
        request = urllib.request.Request(url, headers={"User-Agent": "ReconX"})
        context = ssl._create_unverified_context() if url.startswith("https://") else None
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return response.read(1024 * 1024).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            try:
                return exc.read(256 * 1024).decode("utf-8", errors="replace")
            except Exception:
                return ""
        except Exception:
            return ""

    # ─── Stats ─────────────────────────────────────────────────────────────

    def _compute_stats(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        not_verified = 0
        total = 0
        for result in self.results.values():
            total += len(result.findings)
            not_verified += len(result.metadata.get("not_fully_verified", []))
            for finding in result.findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        self.stats.findings_total = total
        self.stats.critical = counts.get("critical", 0)
        self.stats.high = counts.get("high", 0)
        self.stats.medium = counts.get("medium", 0)
        self.stats.low = counts.get("low", 0)
        self.stats.info = counts.get("info", 0)
        self.stats.checks_not_verified = not_verified
