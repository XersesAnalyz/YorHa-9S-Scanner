#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# YorHa 9S - CloudBuster Framework v5.0
# "Everything that lives is designed to end."

import requests
import random
import time
import sys
import json
import urllib.parse
import base64
import os
import subprocess
import threading
import socket
import re
from concurrent.futures import ThreadPoolExecutor

class Colors:
    RED = '\033[38;5;196m'
    GREEN = '\033[38;5;46m'
    YELLOW = '\033[38;5;226m'
    BLUE = '\033[38;5;51m'
    PURPLE = '\033[38;5;129m'
    CYAN = '\033[38;5;87m'
    WHITE = '\033[38;5;255m'
    ORANGE = '\033[38;5;214m'
    PINK = '\033[38;5;205m'
    GRAY = '\033[38;5;240m'
    BOLD = '\033[1m'
    END = '\033[0m'

def display_security_warning():
    """YorHa Security Protocol"""
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""{Colors.RED}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    {Colors.WHITE}⚡ YORHA UNIT 9S - SECURITY PROTOCOL ⚡{Colors.RED}           ║
    ║                                                              ║
    ║    {Colors.YELLOW}Glory to Mankind...                          {Colors.RED}           ║
    ║                                                              ║
    ║    {Colors.WHITE}tool ini HANYA untuk:                    {Colors.RED}           ║
    ║    {Colors.GREEN}✅ Testing website milik sendiri             {Colors.RED}           ║
    ║    {Colors.GREEN}✅ penetration dengan IZIN                          {Colors.RED}           ║
    ║    {Colors.GREEN}✅ Tujuan edukasi dan pembelajaran                       {Colors.RED}           ║
    ║    {Colors.GREEN}✅ Research keamanan                       {Colors.RED}           ║
    ║                                                              ║
    ║    {Colors.RED}DILARANG digunakan untuk:                                     {Colors.RED}           ║
    ║    {Colors.RED}❌ Aktifitas ilegal & kriminal                          {Colors.RED}           ║
    ║    {Colors.RED}❌ Hack tanpa izin pemilik                         {Colors.RED}           ║
    ║    {Colors.RED}❌ Tujuan jahat dan merugikan                            {Colors.RED}           ║
    ║    {Colors.RED}❌ Melanggar hukum yang berlaku                               {Colors.RED}           ║
    ║                                                              ║
    ║    {Colors.YELLOW}Anda bertangung jawab penuh atas penyalahgunaan tool ini.           {Colors.RED}           ║
    ║    {Colors.YELLOW}YoRHa units follow ethical protocols.        {Colors.RED}Devloper TIDAK BERTANGUNG JAWAB atas penyalahgunaan tool           ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
  # FITUR UTAMA
{Colors.CYAN}{'🎯 FITUR UTAMA YORHA 9S':^60}{Colors.END}")
{Colors.WHITE}{'═'*60}{Colors.END}")
{Colors.GREEN}✅ PORT SCANNING{Colors.END}   - Scan port terbuka (21,22,80,443,dll)")
{Colors.GREEN}✅ SERVICE DETECTION{Colors.END} - Deteksi layanan HTTP/HTTPS")
{Colors.GREEN}✅ ENDPOINT DISCOVERY{Colors.END} - Cari path (/admin, /api, /login)")
{Colors.GREEN}✅ SQL INJECTION TEST{Colors.END} - Deteksi celah database")
{Colors.GREEN}✅ XSS TEST{Colors.END}         - Check Cross-Site Scripting") 
{Colors.GREEN}✅ SECURITY HEADERS{Colors.END} - Audit keamanan HTTP headers")
{Colors.GREEN}✅ VULN REPORTING{Colors.END}   - Laporan detail kerentanan")
{Colors.WHITE}{'═'*60}{Colors.END}")

# FITUR STEALTH & ANTI-DETEKSI
{Colors.PURPLE}{'🕵️ FITUR STEALTH & ANTI-DETEKSI':^60}{Colors.END}")
{Colors.WHITE}{'═'*60}{Colors.END}")
{Colors.BLUE}🚀 WAF BYPASS{Colors.END}      - Header manipulation & parameter obfuscation")
{Colors.BLUE}🎭 TRAFFIC MIMICRY{Colors.END}  - Real browser fingerprinting & human delays")
{Colors.BLUE}🔄 ADAPTIVE EVASION{Colors.END} - Technique rotation & dynamic payloads")
{Colors.BLUE}🌐 NETWORK STEALTH{Colors.END}  - Request randomization & multi-threading")
{Colors.BLUE}🛡️ CLOUDFLARE BYPASS{Colors.END}- Browser challenge & rate limit evasion")
{Colors.BLUE}📊 DETECTION COUNTER{Colors.END} - No signature patterns & behavioral obfuscation")
{Colors.WHITE}{'═'*60}{Colors.END}")
{Colors.YELLOW} SEBELUM MELANJUTKAN,PASTIKAN SUDAH MEMBACA PERATURAN DIATAS
  {Colors.END}""")
    
    confirm = input(f"{Colors.CYAN}[9S] Confirm mission parameters (Y/N): {Colors.END}").strip().lower()
    if confirm != 'y':
        print(f"{Colors.RED}[9S] Mission aborted. Returning to base.{Colors.END}")
        sys.exit(0)

class YorHa_9S:
    def __init__(self):
        self.session = requests.Session()
        self.scan_id = f"9S-{random.randint(1000,9999)}"
        self.target_url = ""
        self.target_host = ""
        self.vulnerabilities_found = []
        
    def display_banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""{Colors.CYAN}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    {Colors.WHITE}⚡ YORHA UNIT 9S - CLOUDBUSTER FRAMEWORK ⚡{Colors.CYAN}      ║
    ║                                                              ║
    ║    {Colors.YELLOW}    "This cannot continue."                    {Colors.CYAN}      ║
    ║    {Colors.YELLOW}    "This cannot continue."                    {Colors.CYAN}      ║
    ║    {Colors.YELLOW}    "This cannot continue."                    {Colors.CYAN}      ║
    ║                                                              ║
    ║    {Colors.WHITE}[{Colors.GREEN}✓{Colors.WHITE}] Scanner Unit:        {Colors.GREEN}ONLINE{Colors.CYAN}                 ║
    ║    {Colors.WHITE}[{Colors.GREEN}✓{Colors.WHITE}] Pod Communication:   {Colors.GREEN}ACTIVE{Colors.CYAN}                 ║
    ║    {Colors.WHITE}[{Colors.GREEN}✓{Colors.WHITE}] Combat System:       {Colors.GREEN}OPERATIONAL{Colors.CYAN}           ║
    ║    {Colors.WHITE}[{Colors.GREEN}✓{Colors.WHITE}] Mission ID:          {Colors.BLUE}{self.scan_id}{Colors.CYAN}           ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    {Colors.END}""")

    def print_status(self, message, status="INFO"):
        status_colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN, 
            "WARNING": Colors.ORANGE,
            "ERROR": Colors.RED,
            "VULN": Colors.RED + Colors.BOLD,
            "SCANNING": Colors.CYAN,
            "BYPASS": Colors.PURPLE
        }
        color = status_colors.get(status, Colors.WHITE)
        print(f"{color}[9S] {message}{Colors.END}")

    def initialize_pod(self):
        """Initialize scanning pod"""
        self.print_status("Initializing Scanner Pod...", "INFO")
        time.sleep(1)
        self.print_status("Loading combat data...", "SCANNING")
        time.sleep(1)
        self.print_status("Pod ready for mission", "SUCCESS")

    def run_security_scan(self, target_url):
        """Main security scanning mission"""
        self.target_url = target_url
        self.target_host = urllib.parse.urlparse(target_url).netloc
        
        self.print_status(f"Mission Target: {self.target_url}", "INFO")
        
        # Phase 1: Reconnaissance
        self.print_status("PHASE 1: RECONNAISSANCE", "SCANNING")
        recon_data = self.perform_reconnaissance()
        
        # Phase 2: Vulnerability Assessment
        self.print_status("PHASE 2: VULNERABILITY ASSESSMENT", "SCANNING")
        vuln_data = self.assess_vulnerabilities()
        
        # Phase 3: WAF Evasion Test
        self.print_status("PHASE 3: WAF EVASION", "BYPASS")
        waf_data = self.test_waf_evasion()
        
        # Generate Mission Report
        self.generate_mission_report(recon_data, vuln_data, waf_data)

    def perform_reconnaissance(self):
        """Phase 1: Gather target intelligence"""
        self.print_status("Deploying reconnaissance drones...", "INFO")
        
        recon_results = {}
        
        # Port Scanning
        self.print_status("Scanning open ports...", "SCANNING")
        recon_results['ports'] = self.port_scan()
        
        # Service Detection
        self.print_status("Detecting services...", "SCANNING")
        recon_results['services'] = self.detect_services()
        
        # Endpoint Discovery
        self.print_status("Discovering endpoints...", "SCANNING")
        recon_results['endpoints'] = self.discover_endpoints()
        
        return recon_results

    def port_scan(self):
        """Advanced port scanning"""
        common_ports = [21, 22, 23, 25, 53, 80, 443, 993, 995, 8080, 8443]
        open_ports = []
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((self.target_host, port))
                    if result == 0:
                        open_ports.append(port)
                        self.print_status(f"Port {port} - OPEN", "SUCCESS")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(scan_port, common_ports)
        
        return open_ports

    def detect_services(self):
        """Detect running services"""
        services = {}
        try:
            # HTTP/HTTPS detection
            for scheme in ['http', 'https']:
                test_url = f"{scheme}://{self.target_host}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    services[scheme] = {
                        'status': response.status_code,
                        'server': response.headers.get('Server', 'Unknown'),
                        'powered_by': response.headers.get('X-Powered-By', 'Unknown')
                    }
                    self.print_status(f"{scheme.upper()} Service detected", "SUCCESS")
                except:
                    pass
        except Exception as e:
            self.print_status(f"Service detection failed: {str(e)}", "ERROR")
        
        return services

    def discover_endpoints(self):
        """Discover common endpoints"""
        endpoints = []
        common_paths = [
            '/admin', '/login', '/api', '/wp-admin', '/config',
            '/backup', '/test', '/debug', '/phpinfo', '/.git',
            '/upload', '/images', '/css', '/js', '/sql'
        ]
        
        for path in common_paths:
            test_url = self.target_url + path
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    endpoints.append({
                        'path': path,
                        'status': response.status_code
                    })
                    self.print_status(f"Endpoint found: {path} [{response.status_code}]", "SUCCESS")
            except:
                pass
        
        return endpoints

    def assess_vulnerabilities(self):
        """Phase 2: Vulnerability assessment"""
        self.print_status("Initiating vulnerability scan...", "SCANNING")
        
        vulnerabilities = []
        
        # SQL Injection Test
        self.print_status("Testing SQL Injection...", "SCANNING")
        sqli_result = self.test_sql_injection()
        if sqli_result:
            vulnerabilities.append(sqli_result)
        
        # XSS Test
        self.print_status("Testing Cross-Site Scripting...", "SCANNING")
        xss_result = self.test_xss()
        if xss_result:
            vulnerabilities.append(xss_result)
        
        # Security Misconfiguration
        self.print_status("Checking security headers...", "SCANNING")
        security_result = self.check_security_headers()
        if security_result:
            vulnerabilities.append(security_result)
        
        return vulnerabilities

    def test_sql_injection(self):
        """Intelligent SQL Injection test"""
        unique_id = random.randint(10000, 99999)
        payloads = [
            f"' AND {unique_id}={unique_id}--",
            f"' OR {unique_id}={unique_id}--",
            f"'; SELECT {unique_id}--"
        ]
        
        for payload in payloads:
            test_url = self.inject_payload(self.target_url, payload)
            try:
                response = self.session.get(test_url, timeout=8)
                if str(unique_id) in response.text:
                    # Verify it's not a false positive
                    original = self.session.get(self.target_url, timeout=8)
                    if original and str(unique_id) not in original.text:
                        self.print_status("SQL Injection vulnerability found!", "VULN")
                        return {
                            'type': 'SQL Injection',
                            'payload': payload,
                            'risk': 'HIGH',
                            'evidence': f'Payload {unique_id} executed'
                        }
            except:
                continue
        return None

    def test_xss(self):
        """Intelligent XSS test"""
        unique_payload = f"XSS_9S_{random.randint(10000,99999)}"
        payloads = [
            f"<script>alert('{unique_payload}')</script>",
            f"<img src=x onerror=alert('{unique_payload}')>"
        ]
        
        for payload in payloads:
            test_url = self.inject_payload(self.target_url, payload)
            try:
                response = self.session.get(test_url, timeout=8)
                if unique_payload in response.text:
                    original = self.session.get(self.target_url, timeout=8)
                    if original and unique_payload not in original.text:
                        self.print_status("XSS vulnerability found!", "VULN")
                        return {
                            'type': 'Cross-Site Scripting',
                            'payload': payload,
                            'risk': 'MEDIUM',
                            'evidence': f'Payload reflected: {unique_payload}'
                        }
            except:
                continue
        return None

    def check_security_headers(self):
        """Check security headers"""
        try:
            response = self.session.get(self.target_url, timeout=8)
            security_headers = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security'
            ]
            
            missing = []
            for header in security_headers:
                if header not in response.headers:
                    missing.append(header)
            
            if missing:
                self.print_status("Security headers missing!", "WARNING")
                return {
                    'type': 'Missing Security Headers',
                    'risk': 'LOW',
                    'evidence': f'Missing: {", ".join(missing)}'
                }
        except:
            pass
        return None

    def test_waf_evasion(self):
        """Phase 3: WAF evasion techniques"""
        self.print_status("Testing WAF bypass techniques...", "BYPASS")
        
        techniques = [
            self.yorha_technique_alpha,
            self.yorha_technique_beta,
            self.yorha_technique_gamma
        ]
        
        successful_bypasses = []
        
        for technique in techniques:
            result = technique()
            if result and result.status_code == 200:
                successful_bypasses.append(technique.__name__)
                self.print_status(f"Bypass successful: {technique.__name__}", "SUCCESS")
        
        return successful_bypasses

    def yorha_technique_alpha(self):
        """YorHa Technique Alpha: Header Manipulation"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1'
            }
            return self.session.get(self.target_url, headers=headers, timeout=10)
        except:
            return None

    def yorha_technique_beta(self):
        """YorHa Technique Beta: Parameter Pollution"""
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                polluted = {}
                for key, value in params.items():
                    polluted[key] = value[0]
                    polluted[f"{key}[]"] = value[0]
                    polluted[f"_{key}"] = value[0]
                
                new_query = urllib.parse.urlencode(polluted, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                return self.session.get(test_url, timeout=10)
        except:
            pass
        return None

    def yorha_technique_gamma(self):
        """YorHa Technique Gamma: Case Variation"""
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            path = parsed.path
            # Random case variation
            varied_path = ''.join(
                c.upper() if random.random() > 0.5 else c.lower() 
                for c in path
            )
            test_url = urllib.parse.urlunparse(parsed._replace(path=varied_path))
            return self.session.get(test_url, timeout=10)
        except:
            pass
        return None

    def inject_payload(self, url, payload):
        """Inject payload into URL parameters"""
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            if params:
                first_param = list(params.keys())[0]
                test_params = params.copy()
                test_params[first_param] = payload
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                return urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        return f"{url}?test={urllib.parse.quote(payload)}"

    def generate_mission_report(self, recon_data, vuln_data, waf_data):
        """Generate comprehensive mission report"""
        print(f"\n{Colors.CYAN}{'═' * 70}{Colors.END}")
        print(f"{Colors.WHITE}{Colors.BOLD}           YORHA 9S - MISSION REPORT{Colors.END}")
        print(f"{Colors.CYAN}{'═' * 70}{Colors.END}")
        
        # Reconnaissance Results
        print(f"\n{Colors.BLUE}[ RECONNAISSANCE DATA ]{Colors.END}")
        print(f"{Colors.WHITE}Open Ports: {recon_data['ports']}{Colors.END}")
        print(f"{Colors.WHITE}Discovered Endpoints: {len(recon_data['endpoints'])}{Colors.END}")
        
        # Vulnerability Results
        print(f"\n{Colors.YELLOW}[ VULNERABILITY ASSESSMENT ]{Colors.END}")
        if vuln_data:
            for vuln in vuln_data:
                print(f"{Colors.RED}⚠️  {vuln['type']} - Risk: {vuln['risk']}{Colors.END}")
                print(f"{Colors.WHITE}   Evidence: {vuln['evidence']}{Colors.END}")
        else:
            print(f"{Colors.GREEN}✅ No critical vulnerabilities detected{Colors.END}")
        
        # WAF Bypass Results
        print(f"\n{Colors.PURPLE}[ WAF EVASION RESULTS ]{Colors.END}")
        if waf_data:
            for technique in waf_data:
                print(f"{Colors.GREEN}✅ {technique} - Successful{Colors.END}")
        else:
            print(f"{Colors.YELLOW}⚠️  No successful WAF bypasses{Colors.END}")
        
        print(f"\n{Colors.CYAN}{'═' * 70}{Colors.END}")
        print(f"{Colors.GREEN}           MISSION COMPLETE - GLORY TO MANKIND{Colors.END}")
        print(f"{Colors.CYAN}{'═' * 70}{Colors.END}")

def main():
    display_security_warning()
    
    scanner = YorHa_9S()
    scanner.display_banner()
    scanner.initialize_pod()
    
    try:
        target = input(f"{Colors.CYAN}[9S] Enter target URL: {Colors.END}").strip()
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            
        print()
        scanner.run_security_scan(target)
        
    except KeyboardInterrupt:
        scanner.print_status("Mission aborted by operator", "ERROR")
    except Exception as e:
        scanner.print_status(f"System failure: {str(e)}", "ERROR")

if __name__ == "__main__":
    main()
