#!/usr/bin/env python3
"""
whois_rdap_dns.py
Consulta WHOIS (via python-whois), se falhar faz RDAP via rdap.org e também consulta DNS (NS, A, MX).
Uso: python whois_rdap_dns.py exemplo.com
"""

import sys
import json
import socket
from datetime import datetime

try:
    import whois  # pip install whois
except Exception:
    whois = None

try:
    import requests  # pip install requests
except Exception:
    requests = None

def print_section(title):
    print("\n" + "="*6 + f" {title} " + "="*6)

def do_whois(domain):
    if not whois:
        return None
    try:
        w = whois.whois(domain)
        # w is often a dict-like object; convert to normal dict
        result = {}
        for k, v in w.items():
            # sanitize datetimes for printing
            if isinstance(v, (list, tuple)):
                result[k] = [str(x) for x in v]
            elif hasattr(v, 'isoformat'):
                result[k] = v.isoformat()
            else:
                result[k] = str(v)
        return result
    except Exception as e:
        return None

def do_rdap(domain):
    if not requests:
        return None
    base = f"https://rdap.org/domain/{domain}"
    try:
        r = requests.get(base, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def dns_lookup(domain):
    data = {}
    # NS
    try:
        import subprocess
        ns = subprocess.check_output(["dig", "+short", "NS", domain], text=True).strip().splitlines()
        data['nameservers'] = ns
    except Exception:
        data['nameservers'] = []

    # A records
    try:
        a = subprocess.check_output(["dig", "+short", "A", domain], text=True).strip().splitlines()
        data['A'] = a
    except Exception:
        data['A'] = []

    # MX
    try:
        mx = subprocess.check_output(["dig", "+short", "MX", domain], text=True).strip().splitlines()
        data['MX'] = mx
    except Exception:
        data['MX'] = []

    return data

def pretty_print_whois_dict(d):
    for k in sorted(d.keys()):
        print(f"{k}: {d[k]}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python whois_rdap_dns.py <dominio>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()

    print_section("DOMAIN")
    print(domain)

    # 1) WHOIS (python library)
    print_section("WHOIS (python-whois)")
    whois_data = do_whois(domain)
    if whois_data:
        pretty_print_whois_dict(whois_data)
    else:
        print("Consulta WHOIS via python-whois não disponível ou falhou.")

    # 2) RDAP (fallback)
    print_section("RDAP (rdap.org)")
    rdap = do_rdap(domain)
    if rdap:
        # print some useful fields
        print("objectClassName:", rdap.get("objectClassName"))
        print("handle:", rdap.get("handle"))
        print("ldhName:", rdap.get("ldhName"))
        # events -> registration/updated/expiry
        events = rdap.get("events") or []
        for ev in events:
            print(f"event: {ev.get('eventAction')} -> {ev.get('eventDate')}")
        # entities for contacts
        entities = rdap.get("entities") or []
        if entities:
            print("\nContacts/Entities:")
            for ent in entities:
                print("-", ent.get("roles"), ":", ent.get("handle") or ent.get("vcardArray", [{}])[1] if ent else "")
        # raw dump (short)
        # print(json.dumps(rdap, indent=2)[:2000])
    else:
        print("Consulta RDAP falhou ou 'requests' não está instalado.")

    # 3) DNS
    print_section("DNS (dig)")
    dns = dns_lookup(domain)
    print(json.dumps(dns, indent=2, ensure_ascii=False))

    print_section("OBS")
    print("Se os dados WHOIS estiverem parcialmente ocultos (GDPR/private), procure registrar/registrar WHOIS ou RDAP para contato do registrar.")
    print("Para consultas em massa, utilize um serviço com API e chave (evita bloqueios).")

if __name__ == "__main__":
    main()
