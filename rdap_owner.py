#!/usr/bin/env python3
"""
rdap_owner.py
Consulta RDAP e tenta extrair o proprietário/registrante de um domínio.

Uso:
    pip install requests
    python rdap_owner.py exemplo.com
"""

import sys
import requests
from typing import Dict, Any, List

RDAP_BASE = "https://rdap.org/domain/{}"
TIMEOUT = 10

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
    """
    vcard_array expected like: ["vcard", [ [ "fn", {}, "text", "Full Name"], ... ] ]
    Return dict with common fields.
    """
    result = {}
    try:
        items = vcard_array[1]
        for item in items:
            key = item[0].lower()
            # value typically at index 3
            value = item[3] if len(item) > 3 else ""
            if key == "fn":
                result["full_name"] = value
            elif key == "org":
                result["organization"] = value
            elif key in ("email", "email;internet"):
                # normalize email key
                result.setdefault("emails", []).append(value)
            elif key in ("tel", "tel;voice"):
                result.setdefault("phones", []).append(value)
            elif key == "adr":
                # adr items: [ "adr", {}, "text", ["", "street", "city", "region", "postal", "country"] ]
                adr = value
                if isinstance(adr, list):
                    addr = ", ".join([p for p in adr if p])
                    result["address"] = addr
                else:
                    result["address"] = str(adr)
    except Exception:
        pass
    return result

def extract_entities(rdap_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    entities = rdap_json.get("entities") or []
    parsed = []
    for ent in entities:
        ent_roles = ent.get("roles") or []
        ent_handle = ent.get("handle")
        ent_obj = {"handle": ent_handle, "roles": ent_roles}
        # try vcardArray
        vcard = ent.get("vcardArray")
        if vcard:
            ent_obj.update(parse_vcard(vcard))
        # also try to extract public emails/links
        if "remarks" in ent and not ent_obj.get("description"):
            ent_obj["description"] = ent.get("remarks")
        parsed.append(ent_obj)
    return parsed

def find_registrant(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # prefer roles containing 'registrant' or 'registrar' (registrar is the company that manages)
    matches = []
    for e in entities:
        roles = [r.lower() for r in e.get("roles", [])]
        if any(r in ("registrant", "registrant/owner", "owner") or "registrant" in r for r in roles):
            matches.append(e)
    return matches

def print_owner_info(domain: str, rdap_json: Dict[str, Any]):
    if "_error" in rdap_json:
        print(f"Erro RDAP: {rdap_json['_error']}")
        return

    print(f"\n=== Domínio: {domain} ===")
    print("Nome (ldhName):", rdap_json.get("ldhName"))
    print("Handle:", rdap_json.get("handle"))
    # events
    events = rdap_json.get("events") or []
    for ev in events:
        print(f"{ev.get('eventAction')}: {ev.get('eventDate')}")

    entities = extract_entities(rdap_json)
    if not entities:
        print("\nNenhuma 'entity' retornada pelo RDAP.")
    else:
        # tenta achar registrante
        registrants = find_registrant(entities)
        if registrants:
            print("\n--- Registrante(s) encontrado(s) ---")
            for r in registrants:
                print(f"Handle: {r.get('handle')}")
                if r.get("full_name"):
                    print("Nome:", r.get("full_name"))
                if r.get("organization"):
                    print("Organização:", r.get("organization"))
                if r.get("emails"):
                    print("Emails:", ", ".join(r.get("emails")))
                if r.get("phones"):
                    print("Telefones:", ", ".join(r.get("phones")))
                if r.get("address"):
                    print("Endereço:", r.get("address"))
                print("Roles:", r.get("roles"))
                print("-"*30)
        else:
            print("\nNenhum registrante explícito encontrado. Listando entidades retornadas (roles):")
            for e in entities:
                print(f"- Handle: {e.get('handle')}, Roles: {e.get('roles')}")
                if e.get("organization"):
                    print("  Org:", e.get("organization"))
                if e.get("full_name"):
                    print("  Nome:", e.get("full_name"))
                if e.get("emails"):
                    print("  Emails:", ", ".join(e.get("emails")))
            # tenta localizar registrar (empresa)
            registrar_candidates = [e for e in entities if any("registrar" in str(r).lower() for r in e.get("roles", []))]
            if registrar_candidates:
                print("\nRegistrar(s):")
                for reg in registrar_candidates:
                    print(" -", reg.get("organization") or reg.get("full_name") or reg.get("handle"))
            else:
                print("\nNão foi possível identificar registrante/registrar pelo RDAP.")

    # fallback: registrar info in top-level
    registrar = rdap_json.get("registrar")
    if registrar:
        print("\nTop-level registrar:", registrar)

    # links (às vezes contém contato abuse)
    links = rdap_json.get("links") or []
    if links:
        print("\nLinks:")
        for l in links:
            print("-", l.get("value") or l.get("href") or l)

def main():
    if len(sys.argv) < 2:
        print("Uso: python rdap_owner.py <dominio>")
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    rdap = rdap_lookup(domain)
    print_owner_info(domain, rdap)

if __name__ == "__main__":
    main()
