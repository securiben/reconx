"""
Technology Stack Profiler.
Detects web technologies, frameworks, and CMS platforms.
Special attention to Spring Boot Actuator endpoints.
"""

import re
import random
from typing import List, Dict, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import TechSignature, TechMatch, Subdomain, Severity
from ..utils import check_http
from ..config import ScannerConfig


# ─── Technology Signature Database ────────────────────────────────────────────

TECH_SIGNATURES: List[TechSignature] = [
    # CRITICAL
    TechSignature(
        name="Spring Boot Actuator",
        category="framework",
        severity=Severity.CRITICAL,
        match_location="Body",
        indicators=[
            "Whitelabel Error Page",
            '"_links"',
            "actuator",
            '{"status":"UP"}',
            "management.endpoints",
        ],
        description="Actuator endpoints may expose /env, /heapdump, /mappings",
        endpoints_to_check=[
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/info", "/actuator/mappings", "/actuator/beans",
            "/env", "/heapdump", "/mappings", "/trace", "/dump",
        ],
    ),

    # HIGH
    TechSignature(
        name="Apache Tomcat",
        category="server",
        severity=Severity.HIGH,
        match_location="Body",
        indicators=[
            "Apache Tomcat",
            "Tomcat/",
            "org.apache.catalina",
            "tomcat-users.xml",
        ],
        description="Java app server \u2013 check /manager, /host-manager, /status",
        endpoints_to_check=[
            "/manager/html", "/host-manager/html", "/status",
            "/manager/status", "/docs/", "/examples/",
        ],
    ),
    TechSignature(
        name="Spring Boot",
        category="framework",
        severity=Severity.HIGH,
        match_location="Body",
        indicators=[
            "Whitelabel Error Page",
            "springframework",
            "spring-boot",
            "Spring Framework",
            "BasicErrorController",
        ],
        description="Java framework \u2013 check for Actuator, SpEL injection, mass assignment",
        endpoints_to_check=[
            "/actuator", "/actuator/health", "/env",
            "/error", "/swagger-ui.html", "/v2/api-docs",
        ],
    ),

    # MEDIUM
    TechSignature(
        name="Postmark",
        category="email",
        severity=Severity.MEDIUM,
        match_location="Header",
        indicators=[
            "X-PM-Message-Id",
            "postmarkapp.com",
        ],
        description="Transactional email service \u2013 check for email injection vectors",
        endpoints_to_check=[],
    ),
    TechSignature(
        name="Shopify",
        category="cms",
        severity=Severity.MEDIUM,
        match_location="Body",
        indicators=[
            "cdn.shopify.com",
            "Shopify.theme",
            "myshopify.com",
            "shopify-section",
        ],
        description="E-commerce platform \u2013 check for open admin, API keys in source",
        endpoints_to_check=[
            "/admin", "/admin/api", "/.json",
        ],
    ),
    TechSignature(
        name="WordPress",
        category="cms",
        severity=Severity.MEDIUM,
        match_location="Body",
        indicators=[
            "wp-content",
            "wp-includes",
            "wp-json",
            "WordPress",
            "/xmlrpc.php",
        ],
        description="CMS \u2013 check /wp-admin, /xmlrpc.php, plugin vulns",
        endpoints_to_check=[
            "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
            "/wp-json/wp/v2/users", "/readme.html",
        ],
    ),

    # LOW / INFO
    TechSignature(
        name="Nginx",
        category="server",
        severity=Severity.LOW,
        match_location="Header",
        indicators=[
            "nginx",
            "openresty",
        ],
        description="Web server \u2013 check version disclosure, misconfigurations",
        endpoints_to_check=[],
    ),
    TechSignature(
        name="Express.js",
        category="framework",
        severity=Severity.LOW,
        match_location="Header",
        indicators=[
            "X-Powered-By: Express",
        ],
        description="Node.js framework \u2013 check for debug mode, verbose errors",
        endpoints_to_check=[],
    ),
    TechSignature(
        name="React",
        category="frontend",
        severity=Severity.INFO,
        match_location="Body",
        indicators=[
            "react-root",
            "__NEXT_DATA__",
            "data-reactroot",
            "_react",
        ],
        description="Frontend library \u2013 check for exposed source maps",
        endpoints_to_check=[],
    ),
    TechSignature(
        name="Laravel",
        category="framework",
        severity=Severity.MEDIUM,
        match_location="Body",
        indicators=[
            "laravel_session",
            "Laravel",
            "XSRF-TOKEN",
            "csrf-token",
        ],
        description="PHP framework \u2013 check /telescope, debug mode, .env exposure",
        endpoints_to_check=[
            "/telescope", "/.env", "/storage/logs/laravel.log",
        ],
    ),
    TechSignature(
        name="Django",
        category="framework",
        severity=Severity.MEDIUM,
        match_location="Body",
        indicators=[
            "csrfmiddlewaretoken",
            "django",
            "__debug__",
        ],
        description="Python framework \u2013 check /admin, debug mode, settings exposure",
        endpoints_to_check=[
            "/admin/", "/__debug__/", "/api/",
        ],
    ),
    TechSignature(
        name="ASP.NET",
        category="framework",
        severity=Severity.LOW,
        match_location="Header",
        indicators=[
            "X-AspNet-Version",
            "X-Powered-By: ASP.NET",
            "__VIEWSTATE",
        ],
        description=".NET framework \u2013 check for verbose errors, ViewState deserialization",
        endpoints_to_check=[],
    ),
    TechSignature(
        name="Apache HTTP Server",
        category="server",
        severity=Severity.LOW,
        match_location="Header",
        indicators=[
            "Apache/",
            "mod_ssl",
            "mod_php",
        ],
        description="Web server \u2013 check version disclosure, /server-status",
        endpoints_to_check=[
            "/server-status", "/server-info",
        ],
    ),
    TechSignature(
        name="Grafana",
        category="monitoring",
        severity=Severity.HIGH,
        match_location="Body",
        indicators=[
            '"appTitle":"Grafana"',
            "grafana-app",
            "/api/dashboards",
        ],
        description="Monitoring dashboard \u2013 check for unauthenticated access, default creds",
        endpoints_to_check=[
            "/api/dashboards/home", "/api/org", "/api/users",
        ],
    ),
    TechSignature(
        name="Jenkins",
        category="ci",
        severity=Severity.HIGH,
        match_location="Body",
        indicators=[
            "Dashboard [Jenkins]",
            "Jenkins-Crumb",
            "hudson",
        ],
        description="CI/CD server \u2013 check for unauthenticated access, script console",
        endpoints_to_check=[
            "/script", "/manage", "/api/json",
        ],
    ),
]


class TechProfiler:
    """
    Technology Stack Profiler.
    Scans subdomains for known technology signatures and
    checks for exposed sensitive endpoints.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.signatures = TECH_SIGNATURES
        self.total_signatures = len(TECH_SIGNATURES)

    def scan(self, subdomains: List[Subdomain]) -> List[TechMatch]:
        """
        Profile technology stacks for all subdomains.
        Uses multi-threading for concurrent HTTP checks.
        """
        matches = []

        def profile_single(sub: Subdomain) -> List[TechMatch]:
            findings = []
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub.hostname}"
                status, body = check_http(url, timeout=self.config.timeout)
                if status is None:
                    continue

                for sig in self.signatures:
                    for indicator in sig.indicators:
                        if indicator.lower() in body.lower():
                            findings.append(TechMatch(
                                subdomain=sub.hostname,
                                tech=sig,
                                evidence=f"Matched '{indicator}' in response body",
                                match_location=sig.match_location,
                            ))
                            break  # One match per signature per subdomain

                if findings:
                    break  # Found on HTTPS, skip HTTP

            return findings

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = {
                executor.submit(profile_single, sub): sub
                for sub in subdomains
            }
            for future in as_completed(futures):
                try:
                    findings = future.result()
                    matches.extend(findings)
                except Exception:
                    pass

        return matches

    def scan_demo(self, domain: str) -> Tuple[List[TechMatch], Dict[str, List[TechMatch]]]:
        """
        Generate demo tech profiling results matching reference output.
        The reference image shows 7 narrative rows grouped by subdomain clusters:
        
        Group A (sub1): Actuator + Spring Boot
        Group B (sub2): Apache Tomcat 
        Group C (sub3): Actuator + Spring Boot
        Group D (sub4): Actuator + Spring Boot  (indented)
        
        Plus medium findings: Postmark, Shopify x2, WordPress
        
        Returns (all_matches, severity_grouped_dict).
        """
        matches = []
        severity_groups: Dict[str, List[TechMatch]] = defaultdict(list)

        # Get specific signatures by name
        sig_map = {sig.name: sig for sig in self.signatures}

        actuator_sig = sig_map["Spring Boot Actuator"]
        spring_sig = sig_map["Spring Boot"]
        tomcat_sig = sig_map["Apache Tomcat"]

        # ── Group A: sub1 has Actuator + Spring Boot ─────────────────────
        sub_a = f"svc-app-01.internal.{domain}"
        m1 = TechMatch(subdomain=sub_a, tech=actuator_sig,
                        evidence="Matched 'actuator' in response body",
                        match_location="Body")
        m2 = TechMatch(subdomain=sub_a, tech=spring_sig,
                        evidence="Matched 'Whitelabel Error Page' in response body",
                        match_location="Body")
        # Add Actuator as CRITICAL, Spring as HIGH
        severity_groups["CRITICAL"].append(m1)
        severity_groups["high"].append(m2)
        matches.extend([m1, m2])

        # ── Group B: sub2 has Apache Tomcat ──────────────────────────────
        sub_b = f"mgmt-portal.infra.{domain}"
        m3 = TechMatch(subdomain=sub_b, tech=tomcat_sig,
                        evidence="Matched 'Apache Tomcat' in response body",
                        match_location="Body")
        severity_groups["high"].append(m3)
        matches.append(m3)

        # ── Group C: sub3 has Actuator + Spring Boot ─────────────────────
        sub_c = f"api-gateway.prod.{domain}"
        m4 = TechMatch(subdomain=sub_c, tech=actuator_sig,
                        evidence="Matched 'actuator' in response body",
                        match_location="Body")
        m5 = TechMatch(subdomain=sub_c, tech=spring_sig,
                        evidence="Matched 'Whitelabel Error Page' in response body",
                        match_location="Body")
        severity_groups["CRITICAL"].append(m4)
        severity_groups["high"].append(m5)
        matches.extend([m4, m5])

        # ── Group D: sub4 has Actuator + Spring Boot (deeper indent) ─────
        sub_d = f"backend-svc.staging.{domain}"
        m6 = TechMatch(subdomain=sub_d, tech=actuator_sig,
                        evidence="Matched 'actuator' in response body",
                        match_location="Body")
        m7 = TechMatch(subdomain=sub_d, tech=spring_sig,
                        evidence="Matched 'Whitelabel Error Page' in response body",
                        match_location="Body")
        severity_groups["CRITICAL"].append(m6)
        severity_groups["high"].append(m7)
        matches.extend([m6, m7])

        # ── MEDIUM: Postmark x1 ─────────────────────────────────────────
        postmark_sig = sig_map["Postmark"]
        m = TechMatch(subdomain=f"mail.{domain}", tech=postmark_sig,
                      evidence="Matched 'X-PM-Message-Id' in headers",
                      match_location="Header")
        matches.append(m)
        severity_groups["medium"].append(m)

        # ── MEDIUM: Shopify x2 ──────────────────────────────────────────
        shopify_sig = sig_map["Shopify"]
        for i in range(2):
            m = TechMatch(subdomain=f"shop-{i+1}.{domain}", tech=shopify_sig,
                          evidence="Matched 'cdn.shopify.com' in response body",
                          match_location="Body")
            matches.append(m)
            severity_groups["medium"].append(m)

        # ── MEDIUM: WordPress x1 ────────────────────────────────────────
        wp_sig = sig_map["WordPress"]
        m = TechMatch(subdomain=f"blog.{domain}", tech=wp_sig,
                      evidence="Matched 'wp-content' in response body",
                      match_location="Body")
        matches.append(m)
        severity_groups["medium"].append(m)

        return matches, dict(severity_groups)

    def group_by_severity(self, matches: List[TechMatch]) -> Dict[str, List[TechMatch]]:
        """Group tech matches by severity level."""
        groups: Dict[str, List[TechMatch]] = defaultdict(list)
        for m in matches:
            groups[m.tech.severity.value].append(m)
        return dict(groups)
