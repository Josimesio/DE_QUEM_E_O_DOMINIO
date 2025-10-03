#!/usr/bin/env python3
"""
rdap_history_master.py
Faz uma busca profunda para tentar recuperar histórico de propriedade de um domínio.

Instalação:
    pip install requests dnspython tabulate

Variáveis de ambiente (opcional):
    WHOISXMLAPI_KEY  -> chave WhoisXMLAPI (whois-history)
    SECURITYTRAILS_KEY -> chave SecurityTrails (history endpoints)
    WHOXY_KEY -> chave Whoxy (history)

Uso:
    python rdap_history_master.py bellofoods.com
    python rdap_history_master.py -o resultado.csv bellofoods.com
"""
import os
import sys
import time
import json
import re
import subprocess
import argparse
from typing import Any, Dict, List, Optional

import requests
import dns.resolver

# optional prettiness
try:
    from tabulate import tabulate
except Exception:
    tabulate = None

# globals
TIMEOUT = 10
RDAP_PRIMARY = "https://rdap.org/domain/{}"
RDAP_VERISIGN = "https://rdap.verisign.com/com/v1/domain/{}"
WHOISXMLAPI_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
SECURITYTRAILS_WHOIS = "https://api.securitytrails.com/v1/history/{}/whois"
WHOXY_API = "https://api.whoxy.com/?history={}&key={}"
WAYBACK_CDX = "http://web.archive.org/cdx/search/cdx?url={}&output=json&limit=20&filter=statuscode:200&from=1996"

EMAIL_RE = re.compile(r"[a-zA-Z0-9.\-_+%]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)


def try_get(url: str, params: dict = None, headers: dict = None, timeout: int = TIMEOUT) -> Optional[requests.Response]:
    try:
        return requests.get(url, params=params, headers=headers or {}, timeout=timeout)
    except Exception:
        return None


def rdap_lookup(domain: str) -> Dict[str, Any]:
    for tpl in (RDAP_PRIMARY, RDAP_VERISIGN):
        url = tpl.format(domain)
        r = try_get(url, headers={"User-Agent":"rdap-history/1.0"})
        if r and r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"_error": "rdap returned non-json"}
    return {"_error": "rdap failed"}


def whois_subprocess(domain: str) -> Optional[str]:
    try:
        out = subprocess.check_output(["whois", domain], text=True, stderr=subprocess.STDOUT, timeout=15)
        return out
    except Exception:
        return None


def dns_lookup(domain: str, resolvers: List[str] = ["8.8.8.8","1.1.1.1"]) -> Dict[str, List[str]]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = resolvers
    resolver.lifetime = 5.0
    data = {}
    for t in ("NS","A","MX"):
        try:
            ans = resolver.resolve(domain, t)
            vals = []
            for a in ans:
                if t == "MX":
                    try:
                        vals.append(f"{a.preference} {a.exchange.to_text()}")
                    except Exception:
                        vals.append(a.to_text())
                else:
                    vals.append(a.to_text())
            data[t] = vals
        except Exception:
            data[t] = []
    return data


def wayback_snapshots(domain: str) -> List[Dict[str, Any]]:
    url = WAYBACK_CDX.format(domain)
    r = try_get(url, timeout=10)
    if not r or r.status_code != 200:
        return []
    try:
        arr = r.json()
        # first row are headers per CDX JSON; subsequent rows are snapshots
        if not arr or len(arr) < 2:
            return []
        headers = arr[0]
        snaps = []
        for row in arr[1:]:
            rec = dict(zip(headers, row))
            snaps.append(rec)
        return snaps
    except Exception:
        return []


def whoisxmlapi_history(domain: str, api_key: str) -> Optional[Dict[str, Any]]:
    # WhoisXMLAPI has a specific WHOIS History endpoint; for the basic WHOIS endpoint:
    params = {"apiKey": api_key, "domainName": domain, "outputFormat": "JSON", "mode": "history"}
    try:
        r = requests.get(WHOISXMLAPI_URL, params=params, timeout=15)
        if r.status_code == 200:
            return r.json()
        return {"_error": f"status {r.status_code}"}
    except Exception as e:
        return {"_error": str(e)}


def securitytrails_whois(domain: str, key: str) -> Optional[Dict[str, Any]]:
    url = SECURITYTRAILS_WHOIS.format(domain)
    headers = {"APIKEY": key}
    r = try_get(url, headers=headers, timeout=15)
    if not r:
        return None
    if r.status_code == 200:
        try:
            return r.json()
        except Exception:
            return {"_error": "non-json"}
    return {"_error": f"status {r.status_code}"}


def whoxy_history(domain: str, key: str) -> Optional[Dict[str, Any]]:
    url = WHOXY_API.format(domain, key)
    r = try_get(url, timeout=15)
    if not r:
        return None
    try:
        return r.json()
    except Exception:
        return {"_error": "non-json"}


def extract_emails_from_text(text: str) -> List[str]:
    return list(dict.fromkeys(EMAIL_RE.findall(text)))  # dedupe


def analyze(domain: str, use_whoisxml: bool = False) -> Dict[str, Any]:
    out = {"domain": domain, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "rdap": None, "whois_raw": None, "dns": None, "wayback": None, "history": {}}
    out["rdap"] = rdap_lookup(domain)
    out["dns"] = dns_lookup(domain)
    out["whois_raw"] = whois_subprocess(domain)

    # wayback snapshots
    out["wayback"] = wayback_snapshots(domain)

    # attempt provider historical APIs if keys present
    whoisxml_key = os.environ.get("WHOISXMLAPI_KEY")
    securitytrails_key = os.environ.get("SECURITYTRAILS_KEY")
    whoxy_key = os.environ.get("WHOXY_KEY")

    if use_whoisxml and whoisxml_key:
        out["history"]["whoisxmlapi"] = whoisxmlapi_history(domain, whoisxml_key)
    if securitytrails_key:
        out["history"]["securitytrails"] = securitytrails_whois(domain, securitytrails_key)
    if whoxy_key:
        out["history"]["whoxy"] = whoxy_history(domain, whoxy_key)

    # collect emails from whois raw and wayback pages
    emails = []
    if out.get("whois_raw"):
        emails.extend(extract_emails_from_text(out["whois_raw"]))
    # also try to fetch contact links from RDAP and scrape for emails (simple)
    rd = out.get("rdap") or {}
    links = []
    for l in (rd.get("links") or []):
        if isinstance(l, dict):
            href = l.get("href") or l.get("value")
            if href:
                links.append(href)
    # entity links
    for e in (rd.get("entities") or []):
        for l in (e.get("links") or []):
            if isinstance(l, dict):
                href = l.get("href") or l.get("value")
                if href:
                    links.append(href)
    out["contact_links"] = list(dict.fromkeys(links))
    # simple scrape of contact links for emails (best-effort)
    for u in out["contact_links"]:
        try:
            r = try_get(u)
            if r and r.status_code == 200:
                emails.extend(extract_emails_from_text(r.text))
        except Exception:
            pass

    # dedupe emails
    out["found_emails"] = list(dict.fromkeys([e for e in emails if "@" in e]))

    return out


def print_result(res: Dict[str, Any]):
    print("\n" + "="*40)
    print("Domain:", res.get("domain"))
    rd = res.get("rdap") or {}
    print("LDH:", rd.get("ldhName"))
    print("RDAP handle:", rd.get("handle"))
    for ev in (rd.get("events") or []):
        print(" -", ev.get("eventAction"), ev.get("eventDate"))
    print("Registrar:", rd.get("registrar"))
    print("\nContact links (RDAP):", res.get("contact_links") or [])
    print("Found emails:", res.get("found_emails") or [])
    print("\nDNS:", res.get("dns"))
    print("\nWayback snapshots (latest 10):")
    for s in (res.get("wayback") or [])[:10]:
        # show timestamp and original
        print(" -", s.get("timestamp"), s.get("original"))
    print("\nHistory API results keys:", list(res.get("history", {}).keys()))
    # snippet WHOIS raw
    if res.get("whois_raw"):
        print("\nWHOIS snippet:")
        print("\n".join(res["whois_raw"].splitlines()[:20]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("domains", nargs="+")
    parser.add_argument("-o", "--output", help="save JSON output to file")
    parser.add_argument("--whoisxml", action="store_true", help="call WhoisXMLAPI (requires WHOISXMLAPI_KEY)")
    args = parser.parse_args()

    all_results = []
    for d in args.domains:
        print(f"[+] analyzing {d} ...")
        r = analyze(d, use_whoisxml=args.whoisxml)
        print_result(r)
        all_results.append(r)
        time.sleep(1)  # tiny pause

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print("Saved to", args.output)


if __name__ == "__main__":
    main()
