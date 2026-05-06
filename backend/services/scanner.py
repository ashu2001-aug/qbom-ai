"""
services/scanner.py — Crypto primitive discovery for repos and websites.
Feeds raw findings to the LangGraph enricher agent.
"""
from __future__ import annotations

import re
import ssl
import socket
import subprocess
import tempfile
import json
import asyncio
from pathlib import Path
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from git import Repo

# ── Regex patterns for 20+ crypto primitives ──────────────────────────────────
CRYPTO_PATTERNS: dict[str, list[str]] = {
    "RSA":      [r"\bRSA\b", r"rsa\.generate_private_key", r"RSA\.new\(", r"createSign\(.RSA"],
    "ECC":      [r"\bECC\b", r"\bECDSA\b", r"\bECDH\b", r"ec\.generate_private_key", r"secp256k1"],
    "AES-128":  [r"AES-128", r"AES\.new\(", r"aes128", r"Cipher\.AES"],
    "AES-256":  [r"AES-256", r"aes256"],
    "SHA-1":    [r"\bSHA1\b", r"\bSHA-1\b", r"hashlib\.sha1", r"DigestAlgorithm\.SHA1"],
    "SHA-256":  [r"\bSHA256\b", r"\bSHA-256\b", r"hashlib\.sha256"],
    "MD5":      [r"\bMD5\b", r"hashlib\.md5", r"createHash\(.md5"],
    "DH":       [r"DiffieHellman", r"dh\.generate_parameters", r"\bDHE\b"],
    "DSA":      [r"\bDSA\b", r"dsa\.generate_private_key"],
    "3DES":     [r"\b3DES\b", r"\bTripleDES\b", r"DES3\.new\("],
    "RC4":      [r"\bRC4\b", r"ARC4\.new\("],
    "Blowfish": [r"\bBlowfish\b"],
}

QUANTUM_VULNERABLE = {"RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "3DES", "RC4", "MD5", "SHA-1", "AES-128"}

JS_CRYPTO_PATTERNS = [
    "CryptoJS.AES", "CryptoJS.RSA", "crypto.subtle", "forge.pki.rsa",
    "new NodeRSA", "ec.keyFromPrivate", "secp256k1", "elliptic", "jsrsasign",
    "createSign", "createCipher", "createDiffieHellman",
]

VULNERABLE_TLS_CIPHERS = {
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA", "AES128-SHA",
}


# ── Repository scanning ───────────────────────────────────────────────────────
async def clone_and_scan(repo_url: str) -> list[dict]:
    """Clone a git repo into a temp dir and scan all source files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        await asyncio.to_thread(
            Repo.clone_from, repo_url, tmpdir, multi_options=["--depth=1"]
        )
        findings = []
        findings.extend(_scan_directory(tmpdir))
        findings.extend(await _run_codeql_scan(tmpdir))
        return _deduplicate(findings)


def _scan_directory(root: str) -> list[dict]:
    findings = []
    extensions = {".py", ".js", ".ts", ".java", ".go", ".rs", ".cs", ".cpp", ".c", ".rb"}
    for path in Path(root).rglob("*"):
        if path.suffix not in extensions or ".git" in path.parts:
            continue
        try:
            code = path.read_text(errors="ignore")
            for line_no, line in enumerate(code.splitlines(), 1):
                for algo, patterns in CRYPTO_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "algorithm": algo,
                                "location": f"{path.relative_to(root)}:{line_no}",
                                "snippet": line.strip()[:120],
                                "quantum_vulnerable": algo in QUANTUM_VULNERABLE,
                                "source": "regex_scan",
                            })
                            break
        except Exception:
            continue
    return findings


async def _run_codeql_scan(repo_path: str) -> list[dict]:
    """Run CodeQL for deep AST-level analysis (if CLI available)."""
    try:
        db_path = f"{repo_path}/.codeqldb"
        await asyncio.to_thread(subprocess.run, [
            "codeql", "database", "create", db_path,
            "--language=python,javascript,java",
            "--source-root", repo_path,
            "--overwrite"
        ], capture_output=True, timeout=120)

        result = await asyncio.to_thread(subprocess.run, [
            "codeql", "database", "analyze", db_path,
            "python-security-experimental.qls",
            "--format=sarif-latest", "--output=/tmp/qbom_codeql.sarif"
        ], capture_output=True, timeout=180)

        return _parse_sarif("/tmp/qbom_codeql.sarif")
    except Exception:
        return []   # CodeQL not installed — graceful degradation


def _parse_sarif(sarif_path: str) -> list[dict]:
    try:
        with open(sarif_path) as f:
            sarif = json.load(f)
        findings = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                location = result.get("locations", [{}])[0]
                uri = location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                line = location.get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                findings.append({
                    "algorithm": _rule_to_algorithm(rule_id),
                    "location": f"{uri}:{line}",
                    "snippet": result.get("message", {}).get("text", "")[:120],
                    "quantum_vulnerable": True,
                    "source": "codeql",
                })
        return findings
    except Exception:
        return []


def _rule_to_algorithm(rule_id: str) -> str:
    mappings = {
        "py/weak-cryptographic-algorithm": "RSA",
        "js/weak-cryptographic-algorithm": "SHA-1",
        "java/weak-crypto": "3DES",
    }
    return mappings.get(rule_id, rule_id)


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f["algorithm"], f["location"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── Website scanning ──────────────────────────────────────────────────────────
async def scan_website(url: str) -> list[dict]:
    findings = []
    tls = await _scan_tls(url)
    headers = await _scan_headers(url)
    js = await _scan_js_bundles(url)
    findings.extend(tls + headers + js)
    return findings


async def _scan_tls(url: str) -> list[dict]:
    findings = []
    try:
        host = urlparse(url).hostname
        ctx = ssl.create_default_context()
        def _connect():
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cipher_name, tls_ver, _ = tls_sock.cipher()
                    cert = tls_sock.getpeercert()
                    return cipher_name, tls_ver, cert
        cipher_name, tls_ver, cert = await asyncio.to_thread(_connect)

        findings.append({
            "algorithm": cipher_name,
            "location": f"TLS handshake: {host}",
            "snippet": f"TLS {tls_ver} — cipher: {cipher_name}",
            "quantum_vulnerable": (
                cipher_name in VULNERABLE_TLS_CIPHERS or
                "RSA" in cipher_name or "ECDHE" in cipher_name
            ),
            "source": "tls_scan",
            "platform": "network",
        })

        sig_algo = cert.get("signatureAlgorithm", "")
        if sig_algo:
            findings.append({
                "algorithm": sig_algo,
                "location": f"X.509 certificate: {host}",
                "snippet": f"Cert signature: {sig_algo}, expires: {cert.get('notAfter')}",
                "quantum_vulnerable": any(v in sig_algo.upper() for v in ["RSA", "ECDSA", "SHA1"]),
                "source": "cert_scan",
                "platform": "pki",
            })
    except Exception as e:
        findings.append({"algorithm": "unknown", "location": url, "snippet": str(e),
                         "quantum_vulnerable": False, "source": "tls_error"})
    return findings


async def _scan_headers(url: str) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.head(url)
        hsts = resp.headers.get("strict-transport-security", "")
        if hsts:
            findings.append({
                "algorithm": "HSTS",
                "location": f"Header: Strict-Transport-Security",
                "snippet": hsts[:120],
                "quantum_vulnerable": False,
                "source": "header_scan",
            })
    except Exception:
        pass
    return findings


async def _scan_js_bundles(url: str) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            page = await client.get(url)
            soup = BeautifulSoup(page.text, "html.parser")
            base = f"{urlparse(url).scheme}://{urlparse(url).hostname}"

            for tag in soup.find_all("script", src=True)[:8]:
                src = tag["src"]
                js_url = src if src.startswith("http") else f"{base}{src}"
                try:
                    js_resp = await client.get(js_url, timeout=10)
                    js_code = js_resp.text[:200_000]
                    matches = [p for p in JS_CRYPTO_PATTERNS if p in js_code]
                    if matches:
                        idx = js_code.find(matches[0])
                        snippet = js_code[max(0, idx-40):idx+100].strip()
                        findings.append({
                            "algorithm": matches[0].split(".")[0],
                            "location": f"JS bundle: {js_url.split('/')[-1]}",
                            "snippet": snippet[:120],
                            "quantum_vulnerable": True,
                            "source": "js_scan",
                            "platform": "browser",
                            "patterns": matches,
                        })
                except Exception:
                    continue
    except Exception:
        pass
    return findings
