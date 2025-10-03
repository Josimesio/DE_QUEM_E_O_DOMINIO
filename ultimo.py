#!/usr/bin/env python3
"""
rdap_owner_dns.py
Consulta RDAP e DNS para descobrir informações de domínio.

Uso:
    pip install requests
    python rdap_owner_dns.py exemplo.com
"""

import sys
import requests
import subprocess
import json
from typing import Dict, Any, List

RDAP_BASE = "https://rdap.org/domain/{}"
TIMEOUT = 10

# ==============================
# RDAP
# ==============================
def rdap_lookup(domain: str) -> Dict[str, Any]:
    try:
        r = requests.get(RDAP_BASE.format(domain), timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        return {"_error": f"HTTPError: {e} - status {getattr(e.response, 'status_code', None)}"}
    except Exception as e:
        return {"_error": str(e)}

def parse_vcard(vcard_array: List[Any]) -> Dict[str, str]:
    result = {}
    try:
        items = vcard_array[1]
        for item in items:
            key = item[0].lower()
            value = item[3] if len(item) > 3 else ""
            if key == "fn":
                result["full_name"] = value
            elif key == "org":
                result["organization"] = value
            elif key in ("email", "email;internet"):
                result.setdefault("emails", []).append(value)
            elif key in ("tel", "tel;voice"):
                result.setdefault("phones", []).append(value)
            elif key == "adr":
                if isinstance(value, list):
                    addr = ", ".join([p for p in value if p])
                    result["address"] = addr
                else:
                    result["address"] = str(value)
    except Exception:
        pass
    return result

def extract_entities(rdap_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    entities = rdap_json.get("entities") or []
    parsed = []
    for ent in entities:
        ent_obj = {"handle": ent.get("handle"), "roles": ent.get("roles")}
        vcard = ent.get("vcardArray")
        if vcard:
            ent_obj.update(parse_vcard(vcard))
        parsed.append(ent_obj)
    return parsed

def find_registrant(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches = []
    for e in entities:
        roles = [r.lower() for r in (e.get("roles") or [])]
        if any("registrant" in r or "owner" in r for r in roles):
            matches.append(e)
    return matches

# ==============================
# DNS
# ==============================
def dns_lookup(domain: str) -> Dict[str, List[str]]:
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

# ==============================
# Helpers
# ==============================
def print_section(title: str):
    print("\n" + "="*10 + f" {title} " + "="*10)

def print_owner_info(domain: str, rdap_json: Dict[str, Any]):
    if "_error" in rdap_json:
        print(f"Erro RDAP: {rdap_json['_error']}")
        return

    print_section(f"RDAP INFO - {domain}")
    print("Nome (ldhName):", rdap_json.get("ldhName"))
    print("Handle:", rdap_json.get("handle"))
    events = rdap_json.get("events") or []
    for ev in events:
        print(f"{ev.get('eventAction')}: {ev.get('eventDate')}")

    entities = extract_entities(rdap_json)
    registrants = find_registrant(entities)

    if registrants:
        print_section("PROPRIETÁRIO (registrant)")
        for r in registrants:
            if r.get("full_name"): print("Nome:", r.get("full_name"))
            if r.get("organization"): print("Organização:", r.get("organization"))
            if r.get("emails"): print("Emails:", ", ".join(r.get("emails")))
            if r.get("phones"): print("Telefones:", ", ".join(r.get("phones")))
            if r.get("address"): print("Endereço:", r.get("address"))
            print("Roles:", r.get("roles"))
    else:
        print_section("Nenhum registrante explícito encontrado")
        for e in entities:
            print(f"- Handle: {e.get('handle')}, Roles: {e.get('roles')}")
            if e.get("organization"):
                print("  Org:", e.get("organization"))
            if e.get("full_name"):
                print("  Nome:", e.get("full_name"))
            if e.get("emails"):
                print("  Emails:", ", ".join(e.get("emails")))

    # registrar info
    registrar = rdap_json.get("registrar")
    if registrar:
        print("\nRegistrar:", registrar)

    # abuse/contact links
    links = rdap_json.get("links") or []
    if links:
        print_section("LINKS DE CONTATO / ABUSE")
        for l in links:
            href = l.get("href") or l.get("value")
            if href:
                print("-", href)

# ==============================
# MAIN
# ==============================
def main():
    if len(sys.argv) < 2:
        print("Uso: python rdap_owner_dns.py <dominio>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()

    # RDAP
    rdap = rdap_lookup(domain)
    print_owner_info(domain, rdap)

    # DNS
    print_section("DNS INFO")
    dns = dns_lookup(domain)
    print(json.dumps(dns, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
