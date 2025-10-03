#!/usr/bin/env python3
"""
rdap_dns.py
Consulta informações de domínio via RDAP e mostra registros DNS.
Uso:
    python rdap_dns.py exemplo.com
"""

import sys
import requests
import json
import subprocess

def rdap_lookup(domain: str) -> dict:
    """Consulta RDAP via rdap.org"""
    url = f"https://rdap.org/domain/{domain}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"erro": str(e)}

def dns_lookup(domain: str) -> dict:
    """Consulta registros DNS usando dig"""
    data = {}
    for record in ["NS", "A", "MX"]:
        try:
            output = subprocess.check_output(
                ["dig", "+short", record, domain],
                text=True
            ).strip().splitlines()
            data[record] = output
        except Exception:
            data[record] = []
    return data

def print_section(title: str):
    print("\n" + "="*10 + f" {title} " + "="*10)

def main():
    if len(sys.argv) < 2:
        print("Uso: python rdap_dns.py <dominio>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()

    print_section("RDAP INFO")
    rdap = rdap_lookup(domain)
    if "erro" in rdap:
        print("Falha na consulta RDAP:", rdap["erro"])
    else:
        # Mostrar informações principais
        print("Domain:", rdap.get("ldhName"))
        print("Handle:", rdap.get("handle"))
        print("Status:", rdap.get("status"))
        if rdap.get("events"):
            for ev in rdap["events"]:
                print(f"{ev.get('eventAction')}: {ev.get('eventDate')}")
        # Se quiser ver tudo: print(json.dumps(rdap, indent=2, ensure_ascii=False))

    print_section("DNS INFO")
    dns = dns_lookup(domain)
    print(json.dumps(dns, indent=2, ensure_ascii=False))

    print_section("OBS")
    print("Se os dados WHOIS aparecerem ocultos (privacidade/GDPR), "
          "use as informações do 'registrar' para contato.")

if __name__ == "__main__":
    main()
