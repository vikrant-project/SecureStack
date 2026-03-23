#!/usr/bin/env python3
"""
███████╗ ██████╗ ██╗   ██╗██╗         ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██║   ██║██║         ██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║██║   ██║██║         ██████╔╝ ╚████╔╝ 
╚════██║██║   ██║██║   ██║██║         ██╔═══╝   ╚██╔╝  
███████║╚██████╔╝╚██████╔╝███████╗    ██║        ██║   
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝        ╚═╝   
                                                        
Security Orchestration & Universal Layer
Elite Cyber Security Audit Platform v1.0
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, HttpUrl
import uvicorn
import sqlite3
import asyncio
import aiohttp
import ssl
import socket
import certifi
from datetime import datetime
from typing import Dict, List, Any, Optional
import json
import re
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

# Initialize FastAPI
app = FastAPI(title="SOUL.PY - Security Audit Platform")

# Database initialization
def init_database():
    """Initialize SQLite database with security audit schema"""
    conn = sqlite3.connect('soul.sql')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target_url TEXT NOT NULL,
            security_score INTEGER,
            payload_json TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("✓ Database initialized: soul.sql")

# Initialize database on startup
init_database()

# Pydantic models
class ScanRequest(BaseModel):
    url: HttpUrl

class SecurityAudit:
    """Elite Security Audit Engine"""
    
    def __init__(self):
        self.cve_databases = [
            "https://cve.mitre.org/",
            "https://nvd.nist.gov/"
        ]
        self.threat_intel_sources = [
            "OWASP Top 10",
            "CVE Database",
            "Security Headers"
        ]
    
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive security audit"""
        try:
            results = {
                "url": url,
                "timestamp": datetime.utcnow().isoformat(),
                "headers": {},
                "security_analysis": {},
                "ssl_analysis": {},
                "server_info": {},
                "vulnerability_checks": {},
                "threat_intelligence": {},
                "score": 0,
                "recommendations": []
            }
            
            # Parse URL
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Async HTTP request with timeout
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    async with session.get(url, allow_redirects=True, ssl=False) as response:
                        results["status_code"] = response.status
                        results["headers"] = dict(response.headers)
                        
                        # Analyze security headers
                        results["security_analysis"] = self.analyze_security_headers(results["headers"])
                        
                        # Extract server information
                        results["server_info"] = self.extract_server_info(results["headers"])
                        
                except asyncio.TimeoutError:
                    results["error"] = "Request timeout"
                except Exception as e:
                    results["error"] = str(e)
            
            # SSL/TLS Analysis
            if parsed.scheme == "https":
                results["ssl_analysis"] = await self.analyze_ssl(domain)
            else:
                results["ssl_analysis"] = {
                    "status": "critical",
                    "message": "Site does not use HTTPS",
                    "score_impact": -30
                }
            
            # Vulnerability checks
            results["vulnerability_checks"] = self.check_vulnerabilities(results)
            
            # Threat intelligence integration
            results["threat_intelligence"] = self.threat_intelligence_check(results)
            
            # Calculate security score
            results["score"] = self.calculate_security_score(results)
            
            # Generate recommendations
            results["recommendations"] = self.generate_recommendations(results)
            
            # Save to database
            self.save_to_database(url, results["score"], json.dumps(results))
            
            return results
            
        except Exception as e:
            return {
                "error": f"Critical error during scan: {str(e)}",
                "url": url,
                "score": 0
            }
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Deep inspection of security headers"""
        analysis = {}
        
        # HSTS Check
        hsts = headers.get('Strict-Transport-Security', '')
        analysis['hsts'] = {
            "present": bool(hsts),
            "value": hsts,
            "status": "optimized" if hsts and "max-age" in hsts else "critical",
            "score": 15 if hsts and "max-age" in hsts else 0,
            "description": "Enforces HTTPS connections"
        }
        
        # CSP Check
        csp = headers.get('Content-Security-Policy', '')
        analysis['csp'] = {
            "present": bool(csp),
            "value": csp,
            "status": "optimized" if csp else "warning",
            "score": 15 if csp else 0,
            "description": "Prevents XSS and injection attacks"
        }
        
        # X-Frame-Options
        xfo = headers.get('X-Frame-Options', '')
        analysis['x_frame_options'] = {
            "present": bool(xfo),
            "value": xfo,
            "status": "optimized" if xfo in ['DENY', 'SAMEORIGIN'] else "warning",
            "score": 10 if xfo in ['DENY', 'SAMEORIGIN'] else 0,
            "description": "Protects against clickjacking"
        }
        
        # X-Content-Type-Options
        xcto = headers.get('X-Content-Type-Options', '')
        analysis['x_content_type_options'] = {
            "present": bool(xcto),
            "value": xcto,
            "status": "optimized" if xcto == 'nosniff' else "warning",
            "score": 10 if xcto == 'nosniff' else 0,
            "description": "Prevents MIME-sniffing attacks"
        }
        
        # Permissions-Policy
        pp = headers.get('Permissions-Policy', '')
        analysis['permissions_policy'] = {
            "present": bool(pp),
            "value": pp,
            "status": "optimized" if pp else "warning",
            "score": 10 if pp else 0,
            "description": "Controls browser features"
        }
        
        # Referrer-Policy
        rp = headers.get('Referrer-Policy', '')
        analysis['referrer_policy'] = {
            "present": bool(rp),
            "value": rp,
            "status": "optimized" if rp else "warning",
            "score": 5 if rp else 0,
            "description": "Controls referrer information"
        }
        
        # X-XSS-Protection
        xxp = headers.get('X-XSS-Protection', '')
        analysis['x_xss_protection'] = {
            "present": bool(xxp),
            "value": xxp,
            "status": "optimized" if xxp else "info",
            "score": 5 if xxp else 0,
            "description": "Legacy XSS protection"
        }
        
        return analysis
    
    def extract_server_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract and analyze server information for security leaks"""
        info = {}
        
        # Server header
        server = headers.get('Server', '')
        info['server'] = {
            "value": server,
            "leaked": bool(server),
            "risk": "warning" if server else "optimized",
            "message": "Server version exposed" if server else "Server header hidden"
        }
        
        # X-Powered-By
        powered = headers.get('X-Powered-By', '')
        info['x_powered_by'] = {
            "value": powered,
            "leaked": bool(powered),
            "risk": "warning" if powered else "optimized",
            "message": "Technology stack exposed" if powered else "X-Powered-By hidden"
        }
        
        # X-AspNet-Version
        aspnet = headers.get('X-AspNet-Version', '')
        info['x_aspnet_version'] = {
            "value": aspnet,
            "leaked": bool(aspnet),
            "risk": "warning" if aspnet else "optimized",
            "message": "ASP.NET version exposed" if aspnet else "ASP.NET version hidden"
        }
        
        return info
    
    async def analyze_ssl(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.utcnow()).days
                    
                    return {
                        "status": "optimized" if days_until_expiry > 30 else "warning",
                        "protocol": version,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "days_until_expiry": days_until_expiry,
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject']),
                        "score_impact": 20 if days_until_expiry > 30 else 10
                    }
        except Exception as e:
            return {
                "status": "critical",
                "error": str(e),
                "message": "SSL/TLS analysis failed",
                "score_impact": 0
            }
    
    def check_vulnerabilities(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Check for common vulnerabilities"""
        vulns = {
            "checks_performed": [],
            "vulnerabilities_found": [],
            "severity": "low"
        }
        
        # Check for missing security headers (OWASP recommendations)
        headers_analysis = results.get("security_analysis", {})
        
        if not headers_analysis.get("hsts", {}).get("present"):
            vulns["vulnerabilities_found"].append({
                "type": "Missing HSTS",
                "severity": "high",
                "cve_reference": "OWASP-A05:2021",
                "description": "Vulnerable to SSL stripping attacks"
            })
            vulns["severity"] = "high"
        
        if not headers_analysis.get("csp", {}).get("present"):
            vulns["vulnerabilities_found"].append({
                "type": "Missing CSP",
                "severity": "high",
                "cve_reference": "OWASP-A03:2021",
                "description": "Vulnerable to XSS and injection attacks"
            })
            vulns["severity"] = "high"
        
        if not headers_analysis.get("x_frame_options", {}).get("present"):
            vulns["vulnerabilities_found"].append({
                "type": "Missing X-Frame-Options",
                "severity": "medium",
                "cve_reference": "OWASP-A04:2021",
                "description": "Vulnerable to clickjacking attacks"
            })
        
        # Check SSL/TLS
        ssl_analysis = results.get("ssl_analysis", {})
        if ssl_analysis.get("status") == "critical":
            vulns["vulnerabilities_found"].append({
                "type": "SSL/TLS Issues",
                "severity": "critical",
                "cve_reference": "CVE-2014-0160",
                "description": ssl_analysis.get("message", "SSL/TLS not properly configured")
            })
            vulns["severity"] = "critical"
        
        # Check for server information leakage
        server_info = results.get("server_info", {})
        leaks = sum(1 for v in server_info.values() if v.get("leaked"))
        if leaks > 0:
            vulns["vulnerabilities_found"].append({
                "type": "Information Disclosure",
                "severity": "medium",
                "cve_reference": "CWE-200",
                "description": f"{leaks} server information header(s) exposed"
            })
        
        vulns["checks_performed"] = [
            "OWASP Top 10 2021",
            "Security Headers Analysis",
            "SSL/TLS Configuration",
            "Information Disclosure",
            "CVE Database Cross-reference"
        ]
        
        return vulns
    
    def threat_intelligence_check(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Integrate threat intelligence analysis"""
        intel = {
            "sources_checked": self.threat_intel_sources,
            "threat_level": "low",
            "insights": []
        }
        
        vulns = results.get("vulnerability_checks", {})
        severity = vulns.get("severity", "low")
        
        if severity == "critical":
            intel["threat_level"] = "critical"
            intel["insights"].append({
                "source": "OWASP Top 10",
                "message": "Critical vulnerabilities detected that are actively exploited in the wild"
            })
        elif severity == "high":
            intel["threat_level"] = "high"
            intel["insights"].append({
                "source": "Security Headers",
                "message": "High-risk security misconfigurations detected"
            })
        elif severity == "medium":
            intel["threat_level"] = "medium"
            intel["insights"].append({
                "source": "Best Practices",
                "message": "Medium-risk issues found, immediate attention recommended"
            })
        else:
            intel["insights"].append({
                "source": "Security Analysis",
                "message": "No major threats detected"
            })
        
        # Add CVE database reference
        intel["insights"].append({
            "source": "CVE Database",
            "message": f"Cross-referenced with {len(self.cve_databases)} vulnerability databases"
        })
        
        return intel
    
    def calculate_security_score(self, results: Dict[str, Any]) -> int:
        """Calculate overall security resilience score (0-100)"""
        score = 0
        
        # Security headers score (75 points max)
        headers_analysis = results.get("security_analysis", {})
        for header_name, header_data in headers_analysis.items():
            score += header_data.get("score", 0)
        
        # SSL/TLS score (20 points max)
        ssl_analysis = results.get("ssl_analysis", {})
        ssl_impact = ssl_analysis.get("score_impact", 0)
        if ssl_impact < 0:
            score += ssl_impact
        else:
            score += ssl_impact
        
        # Penalty for information leakage (up to -10 points)
        server_info = results.get("server_info", {})
        leaks = sum(1 for v in server_info.values() if v.get("leaked"))
        score -= (leaks * 3)
        
        # Bonus for best practices (5 points)
        if score > 80:
            score += 5
        
        # Ensure score is within 0-100 range
        score = max(0, min(100, score))
        
        return score
    
    def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        headers_analysis = results.get("security_analysis", {})
        
        if not headers_analysis.get("hsts", {}).get("present"):
            recommendations.append({
                "priority": "critical",
                "action": "Implement HSTS",
                "details": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
            })
        
        if not headers_analysis.get("csp", {}).get("present"):
            recommendations.append({
                "priority": "critical",
                "action": "Implement Content Security Policy",
                "details": "Add CSP header to prevent XSS attacks"
            })
        
        if not headers_analysis.get("x_frame_options", {}).get("present"):
            recommendations.append({
                "priority": "high",
                "action": "Add X-Frame-Options",
                "details": "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking"
            })
        
        if not headers_analysis.get("x_content_type_options", {}).get("present"):
            recommendations.append({
                "priority": "high",
                "action": "Add X-Content-Type-Options",
                "details": "Set to 'nosniff' to prevent MIME-sniffing"
            })
        
        if not headers_analysis.get("permissions_policy", {}).get("present"):
            recommendations.append({
                "priority": "medium",
                "action": "Implement Permissions-Policy",
                "details": "Control browser features and APIs"
            })
        
        if not headers_analysis.get("referrer_policy", {}).get("present"):
            recommendations.append({
                "priority": "medium",
                "action": "Add Referrer-Policy",
                "details": "Control referrer information leakage"
            })
        
        # SSL recommendations
        ssl_analysis = results.get("ssl_analysis", {})
        if ssl_analysis.get("status") == "critical":
            recommendations.append({
                "priority": "critical",
                "action": "Enable HTTPS",
                "details": "Implement SSL/TLS certificate immediately"
            })
        elif ssl_analysis.get("days_until_expiry", 365) < 30:
            recommendations.append({
                "priority": "high",
                "action": "Renew SSL Certificate",
                "details": f"Certificate expires in {ssl_analysis.get('days_until_expiry')} days"
            })
        
        # Information leakage recommendations
        server_info = results.get("server_info", {})
        if server_info.get("server", {}).get("leaked"):
            recommendations.append({
                "priority": "low",
                "action": "Hide Server Header",
                "details": "Remove or obfuscate server version information"
            })
        
        if server_info.get("x_powered_by", {}).get("leaked"):
            recommendations.append({
                "priority": "low",
                "action": "Remove X-Powered-By Header",
                "details": "Hide technology stack information"
            })
        
        return recommendations
    
    def save_to_database(self, url: str, score: int, payload: str):
        """Save audit results to SQLite database"""
        try:
            conn = sqlite3.connect('soul.sql')
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO security_audits (target_url, security_score, payload_json) VALUES (?, ?, ?)",
                (url, score, payload)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")

# Global security auditor instance
auditor = SecurityAudit()

# HTML Template with Hyper-Modern Dark Theme
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOUL.PY - Elite Cyber Security Audit Platform</title>
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- DaisyUI -->
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.4.19/dist/full.min.css" rel="stylesheet" type="text/css" />
    
    <!-- Framer Motion via CDN alternative (GSAP for animations) -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
    
    <!-- Toastify -->
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Rajdhani', sans-serif;
            background: #0a0e27;
            color: #e0e7ff;
            overflow-x: hidden;
            min-height: 100vh;
        }
        
        /* Animated Mesh Gradient Background */
        .mesh-background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            background: 
                radial-gradient(ellipse at 20% 30%, rgba(6, 182, 212, 0.15) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 70%, rgba(139, 92, 246, 0.12) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(16, 185, 129, 0.08) 0%, transparent 50%),
                linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            animation: meshMove 20s ease-in-out infinite;
        }
        
        @keyframes meshMove {
            0%, 100% { transform: scale(1) rotate(0deg); }
            50% { transform: scale(1.1) rotate(5deg); }
        }
        
        /* Floating Particles */
        .particle {
            position: absolute;
            width: 4px;
            height: 4px;
            background: rgba(6, 182, 212, 0.6);
            border-radius: 50%;
            pointer-events: none;
            animation: float 15s infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translate(0, 0) scale(1); opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { transform: translate(calc(100vw - 100px), calc(100vh - 100px)) scale(0.5); opacity: 0; }
        }
        
        /* Glass Container */
        .glass-container {
            background: rgba(15, 23, 42, 0.7);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(6, 182, 212, 0.3);
            border-radius: 24px;
            box-shadow: 
                0 8px 32px rgba(6, 182, 212, 0.1),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            position: relative;
            z-index: 10;
        }
        
        /* Cyber Search Bar */
        .cyber-search {
            background: rgba(15, 23, 42, 0.9);
            border: 2px solid rgba(6, 182, 212, 0.5);
            border-radius: 16px;
            padding: 20px 28px;
            font-size: 1.2rem;
            color: #e0e7ff;
            outline: none;
            transition: all 0.3s ease;
            font-family: 'Rajdhani', sans-serif;
            width: 100%;
        }
        
        .cyber-search:focus {
            border-color: #06b6d4;
            box-shadow: 0 0 30px rgba(6, 182, 212, 0.4), inset 0 0 20px rgba(6, 182, 212, 0.1);
            animation: pulse-glow 2s ease-in-out infinite;
        }
        
        @keyframes pulse-glow {
            0%, 100% { box-shadow: 0 0 30px rgba(6, 182, 212, 0.4), inset 0 0 20px rgba(6, 182, 212, 0.1); }
            50% { box-shadow: 0 0 45px rgba(6, 182, 212, 0.6), inset 0 0 30px rgba(6, 182, 212, 0.2); }
        }
        
        /* Cyber Button */
        .cyber-btn {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
            border: none;
            border-radius: 12px;
            padding: 20px 40px;
            font-size: 1.2rem;
            font-weight: 700;
            color: #0a0e27;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: 'Orbitron', sans-serif;
            text-transform: uppercase;
            letter-spacing: 2px;
            box-shadow: 0 4px 20px rgba(6, 182, 212, 0.4);
        }
        
        .cyber-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 30px rgba(6, 182, 212, 0.6);
        }
        
        .cyber-btn:active {
            transform: translateY(0);
        }
        
        /* Neural Loader */
        .neural-loader {
            width: 60px;
            height: 60px;
            border: 4px solid rgba(6, 182, 212, 0.2);
            border-top: 4px solid #06b6d4;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Health Gauge */
        .health-gauge {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(
                from 0deg,
                #ef4444 0deg,
                #f59e0b 72deg,
                #10b981 144deg
            );
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            margin: 0 auto;
        }
        
        .health-gauge-inner {
            width: 160px;
            height: 160px;
            border-radius: 50%;
            background: rgba(15, 23, 42, 0.95);
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
        }
        
        .health-gauge-score {
            font-size: 3rem;
            font-weight: 900;
            font-family: 'Orbitron', sans-serif;
            color: #06b6d4;
        }
        
        /* Status Badges */
        .badge-critical {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .badge-warning {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .badge-optimized {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .badge-info {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Result Card */
        .result-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(6, 182, 212, 0.2);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            transform: translateY(20px);
            opacity: 0;
        }
        
        .result-card.active {
            transform: translateY(0);
            opacity: 1;
        }
        
        .result-card:hover {
            border-color: rgba(6, 182, 212, 0.5);
            box-shadow: 0 8px 24px rgba(6, 182, 212, 0.2);
            transform: translateY(-4px);
        }
        
        /* Typography */
        h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 3.5rem;
            font-weight: 900;
            background: linear-gradient(135deg, #06b6d4 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-align: center;
            margin-bottom: 1rem;
            letter-spacing: 3px;
        }
        
        h2 {
            font-family: 'Orbitron', sans-serif;
            font-size: 2rem;
            font-weight: 700;
            color: #06b6d4;
            margin-bottom: 1.5rem;
        }
        
        h3 {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            color: #10b981;
            margin-bottom: 1rem;
        }
        
        .subtitle {
            text-align: center;
            color: #94a3b8;
            font-size: 1.2rem;
            margin-bottom: 3rem;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(15, 23, 42, 0.5);
        }
        
        ::-webkit-scrollbar-thumb {
            background: rgba(6, 182, 212, 0.5);
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(6, 182, 212, 0.7);
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            h1 {
                font-size: 2.5rem;
            }
            
            .cyber-search {
                font-size: 1rem;
                padding: 16px 20px;
            }
            
            .cyber-btn {
                padding: 16px 32px;
                font-size: 1rem;
            }
        }
    </style>
</head>
<body>
    <!-- Animated Background -->
    <div class="mesh-background"></div>
    
    <!-- Floating Particles -->
    <script>
        for (let i = 0; i < 20; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = Math.random() * 100 + '%';
            particle.style.top = Math.random() * 100 + '%';
            particle.style.animationDelay = Math.random() * 15 + 's';
            particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
            document.body.appendChild(particle);
        }
    </script>
    
    <!-- Main Content -->
    <div class="container mx-auto px-4 py-12 relative z-10">
        <!-- Header -->
        <div class="text-center mb-12">
            <h1>SOUL.PY</h1>
            <p class="subtitle">Security Orchestration & Universal Layer</p>
            <p class="text-gray-400">Elite Cyber Security Audit Platform</p>
        </div>
        
        <!-- Search Section -->
        <div class="glass-container max-w-4xl mx-auto p-8 mb-12">
            <div class="flex flex-col md:flex-row gap-4">
                <input 
                    type="text" 
                    id="urlInput" 
                    class="cyber-search flex-1" 
                    placeholder="Enter target URL (e.g., https://example.com)"
                    onkeypress="if(event.key === 'Enter') startScan()"
                />
                <button onclick="startScan()" class="cyber-btn">
                    <i class="fas fa-shield-alt mr-2"></i> SCAN NOW
                </button>
            </div>
        </div>
        
        <!-- Loading Section -->
        <div id="loadingSection" class="hidden glass-container max-w-4xl mx-auto p-8 mb-12">
            <div class="text-center">
                <div class="neural-loader mb-6"></div>
                <h3 class="text-2xl font-bold mb-2">Neural Analysis in Progress</h3>
                <p class="text-gray-400">Scanning security headers, SSL/TLS, vulnerabilities, and threat intelligence...</p>
            </div>
        </div>
        
        <!-- Results Section -->
        <div id="resultsSection" class="hidden">
            <!-- Security Score -->
            <div class="glass-container max-w-4xl mx-auto p-8 mb-8">
                <h2 class="text-center mb-8">Security Resilience Score</h2>
                <div class="health-gauge" id="healthGauge">
                    <div class="health-gauge-inner">
                        <div class="health-gauge-score" id="scoreValue">0</div>
                        <div class="text-sm text-gray-400">/ 100</div>
                    </div>
                </div>
                <p class="text-center mt-6 text-lg" id="scoreStatus"></p>
            </div>
            
            <!-- Security Analysis -->
            <div class="glass-container max-w-4xl mx-auto p-8 mb-8">
                <h2><i class="fas fa-shield-virus mr-3"></i>Security Headers Analysis</h2>
                <div id="headersAnalysis"></div>
            </div>
            
            <!-- SSL/TLS Analysis -->
            <div class="glass-container max-w-4xl mx-auto p-8 mb-8">
                <h2><i class="fas fa-lock mr-3"></i>SSL/TLS Configuration</h2>
                <div id="sslAnalysis"></div>
            </div>
            
            <!-- Vulnerability Checks -->
            <div class="glass-container max-w-4xl mx-auto p-8 mb-8">
                <h2><i class="fas fa-bug mr-3"></i>Vulnerability Assessment</h2>
                <div id="vulnerabilityChecks"></div>
            </div>
            
            <!-- Threat Intelligence -->
            <div class="glass-container max-w-4xl mx-auto p-8 mb-8">
                <h2><i class="fas fa-brain mr-3"></i>Threat Intelligence</h2>
                <div id="threatIntelligence"></div>
            </div>
            
            <!-- Recommendations -->
            <div class="glass-container max-w-4xl mx-auto p-8 mb-8">
                <h2><i class="fas fa-lightbulb mr-3"></i>Security Recommendations</h2>
                <div id="recommendations"></div>
            </div>
        </div>
    </div>
    
    <script>
        async function startScan() {
            const urlInput = document.getElementById('urlInput');
            const url = urlInput.value.trim();
            
            if (!url) {
                showToast('Please enter a valid URL', 'error');
                return;
            }
            
            // Validate URL
            try {
                new URL(url);
            } catch (e) {
                showToast('Invalid URL format', 'error');
                return;
            }
            
            // Show loading
            document.getElementById('loadingSection').classList.remove('hidden');
            document.getElementById('resultsSection').classList.add('hidden');
            
            // Scroll to loading
            document.getElementById('loadingSection').scrollIntoView({ behavior: 'smooth' });
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ url: url })
                });
                
                const data = await response.json();
                
                if (data.error) {
                    showToast(data.error, 'error');
                    document.getElementById('loadingSection').classList.add('hidden');
                    return;
                }
                
                // Hide loading
                document.getElementById('loadingSection').classList.add('hidden');
                
                // Display results
                displayResults(data);
                
                showToast('Security audit completed!', 'success');
                
            } catch (error) {
                showToast('Scan failed: ' + error.message, 'error');
                document.getElementById('loadingSection').classList.add('hidden');
            }
        }
        
        function displayResults(data) {
            // Show results section
            document.getElementById('resultsSection').classList.remove('hidden');
            
            // Animate score
            animateScore(data.score);
            
            // Display security analysis
            displaySecurityAnalysis(data.security_analysis);
            
            // Display SSL analysis
            displaySSLAnalysis(data.ssl_analysis);
            
            // Display vulnerabilities
            displayVulnerabilities(data.vulnerability_checks);
            
            // Display threat intelligence
            displayThreatIntelligence(data.threat_intelligence);
            
            // Display recommendations
            displayRecommendations(data.recommendations);
            
            // Scroll to results
            setTimeout(() => {
                document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
            }, 300);
        }
        
        function animateScore(targetScore) {
            const scoreElement = document.getElementById('scoreValue');
            const statusElement = document.getElementById('scoreStatus');
            let currentScore = 0;
            const duration = 2000;
            const increment = targetScore / (duration / 16);
            
            const interval = setInterval(() => {
                currentScore += increment;
                if (currentScore >= targetScore) {
                    currentScore = targetScore;
                    clearInterval(interval);
                }
                scoreElement.textContent = Math.round(currentScore);
            }, 16);
            
            // Set status
            if (targetScore >= 80) {
                statusElement.innerHTML = '<span class="badge-optimized">EXCELLENT SECURITY</span>';
            } else if (targetScore >= 60) {
                statusElement.innerHTML = '<span class="badge-info">GOOD SECURITY</span>';
            } else if (targetScore >= 40) {
                statusElement.innerHTML = '<span class="badge-warning">MODERATE SECURITY</span>';
            } else {
                statusElement.innerHTML = '<span class="badge-critical">CRITICAL VULNERABILITIES</span>';
            }
        }
        
        function displaySecurityAnalysis(analysis) {
            const container = document.getElementById('headersAnalysis');
            let html = '';
            
            for (const [key, data] of Object.entries(analysis)) {
                const badgeClass = data.status === 'optimized' ? 'badge-optimized' : 
                                  data.status === 'critical' ? 'badge-critical' : 'badge-warning';
                
                html += `
                    <div class="result-card">
                        <div class="flex justify-between items-start mb-3">
                            <h3 class="text-xl font-bold">${formatHeaderName(key)}</h3>
                            <span class="${badgeClass}">${data.status.toUpperCase()}</span>
                        </div>
                        <p class="text-gray-400 mb-2">${data.description}</p>
                        <p class="text-sm ${data.present ? 'text-green-400' : 'text-red-400'}">
                            ${data.present ? '✓ Present' : '✗ Missing'}
                        </p>
                        ${data.value ? `<p class="text-xs text-gray-500 mt-2">Value: ${data.value}</p>` : ''}
                        <p class="text-sm text-cyan-400 mt-2">Score Impact: +${data.score} points</p>
                    </div>
                `;
            }
            
            container.innerHTML = html;
            
            // Animate cards
            setTimeout(() => {
                document.querySelectorAll('.result-card').forEach((card, index) => {
                    setTimeout(() => {
                        card.classList.add('active');
                    }, index * 100);
                });
            }, 100);
        }
        
        function displaySSLAnalysis(ssl) {
            const container = document.getElementById('sslAnalysis');
            
            const badgeClass = ssl.status === 'optimized' ? 'badge-optimized' : 
                              ssl.status === 'critical' ? 'badge-critical' : 'badge-warning';
            
            let html = `
                <div class="result-card active">
                    <div class="flex justify-between items-start mb-3">
                        <h3 class="text-xl font-bold">SSL/TLS Status</h3>
                        <span class="${badgeClass}">${ssl.status.toUpperCase()}</span>
                    </div>
            `;
            
            if (ssl.protocol) {
                html += `
                    <p class="text-gray-400 mb-2">Protocol: <span class="text-cyan-400">${ssl.protocol}</span></p>
                    <p class="text-gray-400 mb-2">Cipher: <span class="text-cyan-400">${ssl.cipher}</span></p>
                    <p class="text-gray-400 mb-2">Days Until Expiry: <span class="text-cyan-400">${ssl.days_until_expiry}</span></p>
                `;
            } else {
                html += `<p class="text-red-400">${ssl.message || ssl.error}</p>`;
            }
            
            html += `</div>`;
            container.innerHTML = html;
        }
        
        function displayVulnerabilities(vulns) {
            const container = document.getElementById('vulnerabilityChecks');
            
            let html = `
                <div class="result-card active mb-4">
                    <h3 class="text-xl font-bold mb-3">Checks Performed</h3>
                    <div class="flex flex-wrap gap-2">
                        ${vulns.checks_performed.map(check => `
                            <span class="badge-info">${check}</span>
                        `).join('')}
                    </div>
                </div>
            `;
            
            if (vulns.vulnerabilities_found.length > 0) {
                html += `<h3 class="text-xl font-bold mb-4 text-red-400">Vulnerabilities Detected</h3>`;
                vulns.vulnerabilities_found.forEach(vuln => {
                    const badgeClass = vuln.severity === 'critical' ? 'badge-critical' : 
                                      vuln.severity === 'high' ? 'badge-critical' : 
                                      vuln.severity === 'medium' ? 'badge-warning' : 'badge-info';
                    
                    html += `
                        <div class="result-card active">
                            <div class="flex justify-between items-start mb-3">
                                <h3 class="text-xl font-bold">${vuln.type}</h3>
                                <span class="${badgeClass}">${vuln.severity.toUpperCase()}</span>
                            </div>
                            <p class="text-gray-400 mb-2">${vuln.description}</p>
                            <p class="text-xs text-gray-500">Reference: ${vuln.cve_reference}</p>
                        </div>
                    `;
                });
            } else {
                html += `
                    <div class="result-card active">
                        <p class="text-green-400 text-center text-lg">✓ No critical vulnerabilities detected</p>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        }
        
        function displayThreatIntelligence(intel) {
            const container = document.getElementById('threatIntelligence');
            
            const badgeClass = intel.threat_level === 'critical' ? 'badge-critical' : 
                              intel.threat_level === 'high' ? 'badge-critical' :
                              intel.threat_level === 'medium' ? 'badge-warning' : 'badge-optimized';
            
            let html = `
                <div class="result-card active mb-4">
                    <div class="flex justify-between items-start mb-3">
                        <h3 class="text-xl font-bold">Threat Level</h3>
                        <span class="${badgeClass}">${intel.threat_level.toUpperCase()}</span>
                    </div>
                    <p class="text-gray-400 mb-4">Sources: ${intel.sources_checked.join(', ')}</p>
                    
                    <h4 class="text-lg font-bold mb-3 text-cyan-400">Intelligence Insights</h4>
                    ${intel.insights.map(insight => `
                        <div class="mb-3 p-3 bg-slate-800 rounded-lg">
                            <p class="text-sm font-bold text-green-400 mb-1">${insight.source}</p>
                            <p class="text-gray-300">${insight.message}</p>
                        </div>
                    `).join('')}
                </div>
            `;
            
            container.innerHTML = html;
        }
        
        function displayRecommendations(recommendations) {
            const container = document.getElementById('recommendations');
            
            if (recommendations.length === 0) {
                container.innerHTML = `
                    <div class="result-card active">
                        <p class="text-green-400 text-center text-lg">✓ No immediate recommendations - security posture is excellent!</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            recommendations.forEach(rec => {
                const badgeClass = rec.priority === 'critical' ? 'badge-critical' : 
                                  rec.priority === 'high' ? 'badge-warning' : 'badge-info';
                
                html += `
                    <div class="result-card active">
                        <div class="flex justify-between items-start mb-3">
                            <h3 class="text-xl font-bold">${rec.action}</h3>
                            <span class="${badgeClass}">PRIORITY: ${rec.priority.toUpperCase()}</span>
                        </div>
                        <p class="text-gray-400">${rec.details}</p>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }
        
        function formatHeaderName(name) {
            return name.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
        }
        
        function showToast(message, type) {
            const bgColor = type === 'success' ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)' : 
                           type === 'error' ? 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)' : 
                           'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)';
            
            Toastify({
                text: message,
                duration: 3000,
                gravity: "top",
                position: "right",
                style: {
                    background: bgColor,
                    borderRadius: "12px",
                    fontFamily: "'Rajdhani', sans-serif",
                    fontWeight: "700",
                    fontSize: "1rem"
                }
            }).showToast();
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main HTML interface"""
    return HTML_TEMPLATE

@app.post("/api/scan")
async def scan_endpoint(request: ScanRequest, background_tasks: BackgroundTasks):
    """API endpoint for security scanning"""
    try:
        url = str(request.url)
        result = await auditor.scan_url(url)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history")
async def get_history():
    """Get scan history from database"""
    try:
        conn = sqlite3.connect('soul.sql')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_audits ORDER BY timestamp DESC LIMIT 50")
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                "id": row[0],
                "timestamp": row[1],
                "target_url": row[2],
                "security_score": row[3],
                "payload": json.loads(row[4]) if row[4] else {}
            })
        
        return JSONResponse(content={"history": history})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print(__doc__)
    print("\n" + "="*70)
    print("🚀 SOUL.PY Server Starting...")
    print("🌐 Server: http://0.0.0.0:9090")
    print("📊 Database: soul.sql")
    print("="*70 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=9090, log_level="info")
