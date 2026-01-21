#!/usr/bin/env python3
"""
Global Sanctions & Export Control Screening with snapshot + audit logging.

Author: Rafael Sene <rpsene@gmail.com>
License: Apache License 2.0

Data sources (official):
- OFAC SDN (Specially Designated Nationals): sanctionslistservice.ofac.treas.gov
- OFAC Consolidated (non-SDN): sanctionslistservice.ofac.treas.gov
- BIS Entity List (EL): Export control restrictions
- BIS Unverified List (UVL): Unable to verify end-use
- BIS Military End-User List (MEU): Military end-user restrictions
- UN Security Council Consolidated Sanctions: scsanctions.un.org
- EU Financial Sanctions: webgate.ec.europa.eu
- UK Sanctions List (FCDO/OFSI): sanctionslist.fcdo.gov.uk

What this script provides (compliance-oriented baseline):
- Immutable list snapshots (raw files + manifest w/ SHA256 hashes)
- Deterministic screening runs against all major sanctions regimes
- Explainable scoring with source list identification
- Audit log (JSONL) with inputs, snapshot id, thresholds, and top matches

"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests
from tqdm import tqdm

# Official SLS API pattern (download by filename).
SLS_DOWNLOAD_BASE = "https://sanctionslistservice.ofac.treas.gov/api/download"

# Consolidated (non-SDN) list core CSV set (primary + aliases + addresses + overflow remarks).
FILES_CONSOLIDATED = [
    "CONS_PRIM.CSV",
    "CONS_ALT.CSV",
    "CONS_ADD.CSV",
    "CONS_COMMENTS.CSV",
]

# SDN (Specially Designated Nationals) list CSV set.
FILES_SDN = [
    "SDN.CSV",
    "ALT.CSV",
    "ADD.CSV",
    "SDN_COMMENTS.CSV",
]

# Combined: both SDN and consolidated non-SDN lists.
FILES_OFAC = FILES_CONSOLIDATED + FILES_SDN

# BIS (Bureau of Industry and Security) export control lists.
BIS_DOWNLOAD_BASE = "https://www.bis.gov/media/documents"
BIS_FILES = {
    "bis_entity_list.csv": f"{BIS_DOWNLOAD_BASE}/entity-list",
    "bis_unverified.csv": f"{BIS_DOWNLOAD_BASE}/unverified-list",
    "bis_meu.csv": f"{BIS_DOWNLOAD_BASE}/military-end-user-list",
}

# International sanctions lists.
INTL_FILES = {
    "un_consolidated.xml": "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
    "eu_consolidated.csv": "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList/content?token=dG9rZW4tMjAxNw",
    "uk_sanctions.csv": "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv",
    # Added lists
    "sema_sanctions.xml": "https://www.international.gc.ca/world-monde/assets/office_docs/international_relations-relations_internationales/sanctions/sema-lmes.xml",
    "au_sanctions.xlsx": "https://data.opensanctions.org/datasets/latest/au_dfat_sanctions/source.xlsx",
    "seco_sanctions.xml": "https://www.sesam.search.admin.ch/sesam-search-web/pages/downloadXmlGesamtliste.xhtml?lang=en&action=downloadXmlGesamtlisteAction",
    "wb_debarred.csv": "https://data.opensanctions.org/datasets/latest/worldbank_debarred/targets.simple.csv",
}

DEFAULT_CACHE_DIR = Path(".") / ".sanctions"
DEFAULT_USER_AGENT = "sanctions-screen/1.0"

# Decision policy (tune to your risk appetite; OFAC does not recommend a threshold).
# Low thresholds by default to surface all potential matches for human review.
DEFAULT_BLOCK_THRESHOLD = 90.0
DEFAULT_REVIEW_THRESHOLD = 20.0


@dataclass(frozen=True)
class MatchEvidence:
    field: str                 # "primary" or "alias"
    matched_value: str
    score: float


@dataclass(frozen=True)
class EntityHit:
    entity_id: str
    source_list: str               # e.g., "OFAC-SDN", "OFAC-CONS", "BIS-EL", "BIS-DPL", etc.
    best_score: float
    best_evidence: MatchEvidence
    primary_names: List[str]
    alias_names: List[str]
    programs: List[str]
    addresses: List[str]


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _normalize(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    s = s.lower()
    s = s.replace("&", " and ")
    s = re.sub(r"[^a-z0-9]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _token_set_similarity(a: str, b: str) -> float:
    """
    Token-set similarity 0..100, no external deps.
    """
    import difflib

    a_n = _normalize(a)
    b_n = _normalize(b)
    if not a_n or not b_n:
        return 0.0

    a_t = set(a_n.split())
    b_t = set(b_n.split())
    inter = a_t & b_t
    union = a_t | b_t
    jacc = len(inter) / max(1, len(union))

    # Add a small boost for near-spelling similarity of the normalized full string.
    seq = difflib.SequenceMatcher(None, a_n, b_n).ratio()

    score = (0.80 * jacc) + (0.20 * seq)
    return max(0.0, min(100.0, score * 100.0))


def _http_get(url: str, *, timeout: int, user_agent: str, verify_ssl: bool = True, desc: str = "Downloading") -> bytes:
    response = requests.get(
        url,
        timeout=timeout,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
        },
        verify=verify_ssl,
        stream=True,
    )
    response.raise_for_status()
    
    total_size = int(response.headers.get("content-length", 0))
    block_size = 1024 * 8
    buffer = io.BytesIO()
    
    with tqdm(total=total_size, unit="iB", unit_scale=True, desc=desc, leave=False) as pbar:
        for chunk in response.iter_content(block_size):
            pbar.update(len(chunk))
            buffer.write(chunk)
            
    return buffer.getvalue()


def _snapshot_dir(cache_dir: Path, snapshot_id: str) -> Path:
    return cache_dir / "snapshots" / snapshot_id


def update_snapshot(
    cache_dir: Path,
    *,
    timeout: int = 90,
    user_agent: str = DEFAULT_USER_AGENT,
    ofac_files: List[str] = FILES_OFAC,
    include_bis: bool = True,
    include_intl: bool = True,
    verify_ssl: bool = True,
) -> str:
    """
    Downloads a new snapshot. Snapshot id is UTC timestamp + short hash of manifest content.
    Downloads OFAC, BIS, and international (UN, EU, UK) sanctions lists.
    """
    # Suppress SSL warnings if verification is disabled
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cache_dir.mkdir(parents=True, exist_ok=True)

    fetched: Dict[str, Dict[str, str]] = {}
    raw_blobs: Dict[str, bytes] = {}

    # Download OFAC files
    print("Downloading OFAC lists...", file=sys.stderr)
    for fname in ofac_files:
        url = f"{SLS_DOWNLOAD_BASE}/{fname}"
        blob = _http_get(url, timeout=timeout, user_agent=user_agent, desc=fname)
        raw_blobs[fname] = blob
        fetched[fname] = {
            "source": "OFAC",
            "url": url,
            "sha256": _sha256_bytes(blob),
            "bytes": str(len(blob)),
        }

    # Download BIS files
    if include_bis:
        print("Downloading BIS lists...", file=sys.stderr)
        for local_fname, url in BIS_FILES.items():
            try:
                blob = _http_get(url, timeout=timeout, user_agent=user_agent, verify_ssl=verify_ssl, desc=local_fname)
                raw_blobs[local_fname] = blob
                fetched[local_fname] = {
                    "source": "BIS",
                    "url": url,
                    "sha256": _sha256_bytes(blob),
                    "bytes": str(len(blob)),
                }
            except Exception as e:
                print(f"WARNING: Failed to download {local_fname}: {e}", file=sys.stderr)

    # Download international lists (UN, EU, UK)
    if include_intl:
        print("Downloading international lists (UN, EU, UK)...", file=sys.stderr)
        for local_fname, url in INTL_FILES.items():
            try:
                blob = _http_get(url, timeout=timeout, user_agent=user_agent, verify_ssl=verify_ssl, desc=local_fname)
                raw_blobs[local_fname] = blob
                source = "UN" if "un_" in local_fname else ("EU" if "eu_" in local_fname else "UK")
                fetched[local_fname] = {
                    "source": source,
                    "url": url,
                    "sha256": _sha256_bytes(blob),
                    "bytes": str(len(blob)),
                }
            except Exception as e:
                print(f"WARNING: Failed to download {local_fname}: {e}", file=sys.stderr)

    created_at = _utc_now_iso()
    manifest_obj = {
        "created_at_utc": created_at,
        "sources": {
            "OFAC": {"base": SLS_DOWNLOAD_BASE, "description": "OFAC Sanctions List Service (SDN + Consolidated)"},
            "BIS": {"base": BIS_DOWNLOAD_BASE, "description": "BIS Export Control Lists (EL, UVL, MEU)"},
            "UN": {"description": "UN Security Council Consolidated Sanctions"},
            "EU": {"description": "EU Financial Sanctions (Consolidated)"},
            "UK": {"description": "UK FCDO Sanctions List"},
            "CA": {"description": "Canada SEMA Consolidated Sanctions"},
            "AU": {"description": "Australia DFAT Consolidated Sanctions"},
            "CH": {"description": "Switzerland SECO Sanctions"},
            "WB": {"description": "World Bank Debarred Firms"},
        },
        "files": fetched,
    }
    manifest_bytes = json.dumps(manifest_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_hash = _sha256_bytes(manifest_bytes)[:12]
    snapshot_id = f"{created_at.replace(':','').replace('-','')}_{manifest_hash}"

    sdir = _snapshot_dir(cache_dir, snapshot_id)
    sdir.mkdir(parents=True, exist_ok=False)

    # Write raw files
    for fname, blob in raw_blobs.items():
        (sdir / fname).write_bytes(blob)

    # Write manifest (immutable snapshot metadata)
    (sdir / "manifest.json").write_bytes(
        json.dumps(manifest_obj, indent=2, sort_keys=True).encode("utf-8")
    )

    # Create (or append) audit log file at snapshot scope
    (sdir / "audit.jsonl").touch(exist_ok=True)

    # Write "latest" pointer (best-effort)
    (cache_dir / "LATEST").write_text(snapshot_id, encoding="utf-8")

    return snapshot_id


def get_last_updated_time(cache_dir: Path) -> str:
    """
    Returns a human-readable string of the last update time.
    """
    try:
        sid = load_latest_snapshot_id(cache_dir)
        # Snapshot ID format: YYYYMMDDTHHMMSS+0000_hash
        # Extract timestamp part: 20260121T212239
        ts_str = sid.split("_")[0]
        # Parse: 2026-01-21 T 21:22:39
        dt_obj = dt.datetime.strptime(ts_str.replace("+0000", ""), "%Y%m%dT%H%M%S")
        return dt_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Unknown (never updated?)"


def load_latest_snapshot_id(cache_dir: Path) -> str:
    latest = (cache_dir / "LATEST")
    if not latest.exists():
        raise FileNotFoundError(f"No LATEST pointer found in {cache_dir}. Run: update")
    return latest.read_text(encoding="utf-8").strip()


# SDN CSV files have no headers; define columns per OFAC documentation.
SDN_COLUMNS = ["ent_num", "SDN_Name", "SDN_Type", "Program", "Title", "Call_Sign",
               "Vess_Type", "Tonnage", "GRT", "Vess_Flag", "Vess_Owner", "Remarks"]
SDN_ALT_COLUMNS = ["ent_num", "alt_num", "alt_type", "alt_name", "remarks"]
SDN_ADD_COLUMNS = ["ent_num", "add_num", "Address", "CityStateProvincePostalCode", "Country", "remarks"]


def _read_csv_bytes(path: Path, fieldnames: Optional[List[str]] = None) -> List[Dict[str, str]]:
    # OFAC CSVs are typically Windows-1252/UTF-8-ish; be forgiving.
    b = path.read_bytes()
    text = b.decode("utf-8", errors="replace")
    f = io.StringIO(text)
    reader = csv.DictReader(f, fieldnames=fieldnames)
    rows = []
    for row in reader:
        # Normalize keys to exact header strings as present.
        rows.append({k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()})
    return rows


def _pick_entity_id(row: Dict[str, str]) -> Optional[str]:
    # SLS consolidated CSVs use "Entity Number" historically; allow variants.
    return (
        row.get("Entity Number")
        or row.get("Entity_Number")
        or row.get("entity_number")
        or row.get("EntNum")
        or row.get("ent_num")
        or row.get("ID")
        or row.get("Id")
    )


def _pick_name(row: Dict[str, str]) -> Optional[str]:
    return (row.get("Name") or row.get("name") or row.get("Entity Name") or row.get("entity_name")
            or row.get("SDN_Name") or row.get("alt_name"))


def _pick_program(row: Dict[str, str]) -> Optional[str]:
    return row.get("Program") or row.get("Programs") or row.get("program") or row.get("Sanctions Program")


def _pick_address(row: Dict[str, str]) -> Optional[str]:
    # Address columns vary; attempt a reasonable concatenation when present.
    parts = []
    for k in ("Address", "Street", "City", "State/Province", "Postal Code", "Country",
              "CityStateProvincePostalCode"):
        v = row.get(k)
        if v and v != "-0-":
            parts.append(v)
    if parts:
        return ", ".join(parts)
    # Some files provide a single "Address" field
    return row.get("address")


def _index_snapshot(snapshot_path: Path) -> Dict[str, Dict]:
    """
    Build an in-memory index keyed by composite key (source_list:entity_id):
      {
        "OFAC-SDN:12345": {
          "source_list": "OFAC-SDN",
          "entity_id": "12345",
          "primary": [..],
          "aliases": [..],
          "programs": set(..),
          "addresses": set(..)
        }
      }
    """
    idx: Dict[str, Dict] = {}

    def ensure(source_list: str, eid: str) -> Dict:
        key = f"{source_list}:{eid}"
        if key not in idx:
            idx[key] = {
                "source_list": source_list,
                "entity_id": eid,
                "primary": [],
                "aliases": [],
                "programs": set(),
                "addresses": set(),
            }
        return idx[key]

    def add_primary(source_list: str, rows: List[Dict[str, str]]) -> None:
        for r in rows:
            eid = _pick_entity_id(r)
            name = _pick_name(r)
            if not eid or not name:
                continue
            ent = ensure(source_list, eid)
            ent["primary"].append(name)
            p = _pick_program(r)
            if p:
                ent["programs"].add(p)

    def add_aliases(source_list: str, rows: List[Dict[str, str]]) -> None:
        for r in rows:
            eid = _pick_entity_id(r)
            name = _pick_name(r)
            if not eid or not name:
                continue
            ent = ensure(source_list, eid)
            ent["aliases"].append(name)

    def add_addresses(source_list: str, rows: List[Dict[str, str]]) -> None:
        for r in rows:
            eid = _pick_entity_id(r)
            if not eid:
                continue
            ent = ensure(source_list, eid)
            a = _pick_address(r)
            if a:
                ent["addresses"].add(a)

    # OFAC Consolidated (non-SDN) list
    cons_prim = snapshot_path / "CONS_PRIM.CSV"
    cons_alt = snapshot_path / "CONS_ALT.CSV"
    cons_add = snapshot_path / "CONS_ADD.CSV"
    if cons_prim.exists():
        add_primary("OFAC-CONS", _read_csv_bytes(cons_prim))
    if cons_alt.exists():
        add_aliases("OFAC-CONS", _read_csv_bytes(cons_alt))
    if cons_add.exists():
        add_addresses("OFAC-CONS", _read_csv_bytes(cons_add))

    # OFAC SDN list (no headers)
    sdn_prim = snapshot_path / "SDN.CSV"
    sdn_alt = snapshot_path / "ALT.CSV"
    sdn_add = snapshot_path / "ADD.CSV"
    if sdn_prim.exists():
        add_primary("OFAC-SDN", _read_csv_bytes(sdn_prim, fieldnames=SDN_COLUMNS))
    if sdn_alt.exists():
        add_aliases("OFAC-SDN", _read_csv_bytes(sdn_alt, fieldnames=SDN_ALT_COLUMNS))
    if sdn_add.exists():
        add_addresses("OFAC-SDN", _read_csv_bytes(sdn_add, fieldnames=SDN_ADD_COLUMNS))

    # BIS lists (have headers, use "Source List" column to distinguish)
    bis_list_codes = {
        "EL": "BIS-EL",      # Entity List
        "DPL": "BIS-DPL",    # Denied Persons List
        "UVL": "BIS-UVL",    # Unverified List
        "MEU": "BIS-MEU",    # Military End-User List
    }
    for bis_file in ["bis_entity_list.csv", "bis_denied_persons.csv", "bis_unverified.csv", "bis_meu.csv"]:
        bis_path = snapshot_path / bis_file
        if not bis_path.exists():
            continue
        rows = _read_csv_bytes(bis_path)
        for r in rows:
            # BIS files have: Source List, Entity Number, Name, Address, City, Country, etc.
            source_code = r.get("Source List", "").strip()
            source_list = bis_list_codes.get(source_code, f"BIS-{source_code}" if source_code else "BIS")
            name = r.get("Name", "").strip()
            if not name:
                continue
            # Use name as entity_id for BIS (they don't always have unique IDs)
            eid = r.get("Entity Number", "").strip() or name
            ent = ensure(source_list, eid)
            if name not in ent["primary"]:
                ent["primary"].append(name)
            # License requirement as "program"
            lic_req = r.get("License Requirement", "").strip()
            if lic_req:
                ent["programs"].add(lic_req)
            lic_pol = r.get("License Policy", "").strip()
            if lic_pol:
                ent["programs"].add(f"Policy: {lic_pol}")
            # Address
            addr_parts = []
            for k in ("Address", "City", "State/Province", "Postal Code", "Country"):
                v = r.get(k, "").strip()
                if v and v != "-0-":
                    addr_parts.append(v)
            if addr_parts:
                ent["addresses"].add(", ".join(addr_parts))

    # UN Security Council Consolidated List (XML format)
    un_path = snapshot_path / "un_consolidated.xml"
    if un_path.exists():
        try:
            tree = ET.parse(un_path)
            root = tree.getroot()
            # Parse individuals
            for ind in root.findall(".//INDIVIDUAL"):
                dataid = ind.findtext("DATAID", "").strip()
                if not dataid:
                    continue
                # Build name from components
                first = ind.findtext("FIRST_NAME", "").strip()
                second = ind.findtext("SECOND_NAME", "").strip()
                third = ind.findtext("THIRD_NAME", "").strip()
                fourth = ind.findtext("FOURTH_NAME", "").strip()
                name_parts = [p for p in [first, second, third, fourth] if p]
                name = " ".join(name_parts)
                if not name:
                    continue
                ent = ensure("UN", dataid)
                if name not in ent["primary"]:
                    ent["primary"].append(name)
                # Aliases
                for alias in ind.findall(".//INDIVIDUAL_ALIAS"):
                    alias_name = alias.findtext("ALIAS_NAME", "").strip()
                    if alias_name and alias_name not in ent["aliases"]:
                        ent["aliases"].append(alias_name)
                # Programs (UN List Type)
                un_list = ind.findtext("UN_LIST_TYPE", "").strip()
                if un_list:
                    ent["programs"].add(f"UN: {un_list}")
                # Nationality
                for nat in ind.findall(".//NATIONALITY/VALUE"):
                    if nat.text:
                        ent["addresses"].add(f"Nationality: {nat.text.strip()}")
            # Parse entities
            for entity in root.findall(".//ENTITY"):
                dataid = entity.findtext("DATAID", "").strip()
                if not dataid:
                    continue
                name = entity.findtext("FIRST_NAME", "").strip()
                if not name:
                    continue
                ent = ensure("UN", dataid)
                if name not in ent["primary"]:
                    ent["primary"].append(name)
                for alias in entity.findall(".//ENTITY_ALIAS"):
                    alias_name = alias.findtext("ALIAS_NAME", "").strip()
                    if alias_name and alias_name not in ent["aliases"]:
                        ent["aliases"].append(alias_name)
                un_list = entity.findtext("UN_LIST_TYPE", "").strip()
                if un_list:
                    ent["programs"].add(f"UN: {un_list}")
                for addr in entity.findall(".//ENTITY_ADDRESS"):
                    addr_parts = []
                    for k in ["STREET", "CITY", "STATE_PROVINCE", "COUNTRY"]:
                        v = addr.findtext(k, "").strip()
                        if v:
                            addr_parts.append(v)
                    if addr_parts:
                        ent["addresses"].add(", ".join(addr_parts))
        except Exception as e:
            print(f"WARNING: Failed to parse UN XML: {e}", file=sys.stderr)

    # EU Financial Sanctions (CSV format, semicolon-delimited, has BOM)
    eu_path = snapshot_path / "eu_consolidated.csv"
    if eu_path.exists():
        try:
            b = eu_path.read_bytes()
            text = b.decode("utf-8-sig", errors="replace")  # Handle BOM
            f = io.StringIO(text)
            reader = csv.DictReader(f, delimiter=";")
            for r in reader:
                # Use Naal_logical_id as Entity_logical_id appears twice in header
                eid = (r.get("Naal_logical_id") or "").strip()
                if not eid:
                    continue
                # Name fields: Naal_wholename, Naal_lastname, Naal_firstname
                name = (r.get("Naal_wholename") or "").strip()
                if not name:
                    last = (r.get("Naal_lastname") or "").strip()
                    first = (r.get("Naal_firstname") or "").strip()
                    name = f"{first} {last}".strip()
                if not name:
                    continue
                ent = ensure("EU", eid)
                if name not in ent["primary"]:
                    ent["primary"].append(name)
                # Program
                prog = (r.get("Programme") or "").strip()
                if prog:
                    ent["programs"].add(f"EU: {prog}")
                # Address
                addr_parts = []
                for k in ["Addr_street", "Addr_city", "Addr_country"]:
                    v = (r.get(k) or "").strip()
                    if v:
                        addr_parts.append(v)
                if addr_parts:
                    ent["addresses"].add(", ".join(addr_parts))
        except Exception as e:
            print(f"WARNING: Failed to parse EU CSV: {e}", file=sys.stderr)

    # UK Sanctions List (CSV format - has preamble row to skip)
    uk_path = snapshot_path / "uk_sanctions.csv"
    if uk_path.exists():
        try:
            b = uk_path.read_bytes()
            text = b.decode("utf-8", errors="replace")
            lines = text.splitlines()
            # Skip preamble row (starts with "Report Date:")
            if lines and lines[0].startswith("Report Date"):
                lines = lines[1:]
            f = io.StringIO("\n".join(lines))
            reader = csv.DictReader(f)
            for r in reader:
                uid = (r.get("Unique ID") or "").strip()
                if not uid:
                    continue
                # Name fields: Name 6 (surname), Name 1 (first), Name 2 (middle), etc.
                # Combine all name parts for full name
                name_parts = []
                for k in ["Name 1", "Name 2", "Name 3", "Name 4", "Name 5"]:
                    v = (r.get(k) or "").strip()
                    if v:
                        name_parts.append(v)
                surname = (r.get("Name 6") or "").strip()
                if surname:
                    name_parts.append(surname)
                name = " ".join(name_parts)
                if not name:
                    continue
                ent = ensure("UK", uid)
                if name not in ent["primary"]:
                    ent["primary"].append(name)
                # Regime/Program
                regime = (r.get("Regime Name") or "").strip()
                if regime:
                    ent["programs"].add(f"UK: {regime}")
                sanc = (r.get("Sanctions Imposed") or "").strip()
                if sanc:
                    ent["programs"].add(sanc)
                # Address
                addr_parts = []
                for k in ["Address Line 1", "Address Line 2", "Address Country"]:
                    v = (r.get(k) or "").strip()
                    if v:
                        addr_parts.append(v)
                if addr_parts:
                    ent["addresses"].add(", ".join(addr_parts))
        except Exception as e:
            print(f"WARNING: Failed to parse UK CSV: {e}", file=sys.stderr)

    # Canada (SEMA) XML
    ca_path = snapshot_path / "sema_sanctions.xml"
    if ca_path.exists():
        try:
            tree = ET.parse(ca_path)
            root = tree.getroot()
            # Handle both Individuals and Entities
            for record in root.findall(".//record"):
                uid = record.findtext("Item", "").strip() # Assuming Item is ID
                if not uid:
                    # Fallback if structure is different (it is flat in some versions)
                    # Let's try iterating children
                    pass
                
                # SEMA XML structure is often: <record> <Entity> ... </Entity> </record>
                # Or flat. Let's look for "Entity" or "GivenName"
                entity_name = record.findtext("Entity", "").strip()
                given_name = record.findtext("GivenName", "").strip()
                last_name = record.findtext("LastName", "").strip()
                
                name = entity_name
                if not name:
                    name = f"{given_name} {last_name}".strip()
                
                if not name:
                    continue
                
                # Generate a pseudo-ID if missing, or use name hash
                if not uid:
                    uid = f"CA-{_sha256_bytes(name.encode('utf-8'))[:8]}"
                
                ent = ensure("CA", uid)
                if name not in ent["primary"]:
                    ent["primary"].append(name)
                
                # Aliases (Aliases/Alias)
                aliases = record.find("Aliases")
                if aliases is not None:
                    for alias in aliases.findall("Alias"):
                        if alias.text:
                            ent["aliases"].append(alias.text.strip())
                            
                # Program (Schedule)
                schedule = record.findtext("Schedule", "").strip()
                if schedule:
                    ent["programs"].add(f"CA: {schedule}")
                    
                # Date of birth / location often in other fields
                dob = record.findtext("DateOfBirth", "").strip()
                if dob:
                    ent["addresses"].add(f"DOB: {dob}")

        except Exception as e:
            print(f"WARNING: Failed to parse Canada XML: {e}", file=sys.stderr)

    # Australia (DFAT) XLSX
    au_path = snapshot_path / "au_sanctions.xlsx"
    if au_path.exists():
        try:
            # OpenSanctions simplified or official format
            # Columns usually: "Name of Asset", "Type", "Committees"
            df = pd.read_excel(au_path)
            for _, row in df.iterrows():
                # Adapt to likely columns. OpenSanctions source.xlsx mirrors official
                # Official columns: "Reference", "Name of Individual or Entity", "Type", ...
                uid = str(row.get("Reference", "")).strip()
                if not uid or uid == "nan":
                    uid = str(row.get("id", "")).strip() # OpenSanctions ID?

                name = str(row.get("Name of Individual or Entity", "")).strip()
                if not name or name == "nan":
                    name = str(row.get("name", "")).strip()
                    
                if not name or name == "nan":
                    continue
                    
                if not uid or uid == "nan":
                     uid = f"AU-{_sha256_bytes(name.encode('utf-8'))[:8]}"

                ent = ensure("AU", uid)
                if name not in ent["primary"]:
                    ent["primary"].append(name)
                
                # Program
                prog = str(row.get("Committees", "")).strip()
                if prog and prog != "nan":
                    ent["programs"].add(f"AU: {prog}")
                    
                # Address/Citizenship
                citizen = str(row.get("Citizenship", "")).strip()
                if citizen and citizen != "nan":
                    ent["addresses"].add(f"Citizenship: {citizen}")
                    
                addr = str(row.get("Address", "")).strip()
                if addr and addr != "nan":
                    ent["addresses"].add(addr)

        except Exception as e:
            print(f"WARNING: Failed to parse Australia XLSX: {e}", file=sys.stderr)

    # Switzerland (SECO) XML
    ch_path = snapshot_path / "seco_sanctions.xml"
    if ch_path.exists():
        try:
            # SECO XML has <sanctions-program> -> <target>
            tree = ET.parse(ch_path)
            root = tree.getroot()
            ns = {'ss': 'http://www.seco.admin.ch/oss/xsd/1.0'} # Check namespace, often default
            
            # Simple iteration without namespace strictness
            for target in root.findall(".//target"):
                ssid = target.get("ssid")
                if not ssid:
                    continue
                
                ent = ensure("CH", ssid)

                # Find all name parts in identities
                for identity in target.findall(".//identity"):
                    for name_node in identity.findall(".//name"):
                        # Build ONE name from this name_node
                        parts = []
                        for name_part in name_node.findall(".//name-part"):
                             val = name_part.findtext("value", "").strip()
                             if val:
                                 parts.append(val)
                        
                        fname = " ".join(parts)
                        if fname and fname not in ent["primary"]:
                             ent["primary"].append(fname)
                
                # Program
                # <sanctions-program-id> usually parent
                # We can't easily get parent in ElementTree without tracking
                # But target has 'sanctions-set-id' often
                pass

        except Exception as e:
            print(f"WARNING: Failed to parse Switzerland XML: {e}", file=sys.stderr)

    # World Bank (Debarred) CSV
    wb_path = snapshot_path / "wb_debarred.csv"
    if wb_path.exists():
        try:
            # OpenSanctions simplified CSV
            # columns: id, schema, name, aliases, countries, ...
            df = pd.read_csv(wb_path)
            for _, row in df.iterrows():
                uid = str(row.get("id", "")).strip()
                name = str(row.get("name", "")).strip()
                if not name or name == "nan":
                    continue
                
                if not uid or uid == "nan":
                    uid = f"WB-{_sha256_bytes(name.encode('utf-8'))[:8]}"
                
                ent = ensure("WB", uid)
                if name not in ent["primary"]:
                    ent["primary"].append(name)
                
                aliases = str(row.get("aliases", "")).strip()
                if aliases and aliases != "nan":
                    for a in aliases.split(";"):
                        ent["aliases"].append(a.strip())
                
                countries = str(row.get("countries", "")).strip()
                if countries and countries != "nan":
                    ent["addresses"].add(countries)
                
                ent["programs"].add("World Bank Debarment")
                
        except Exception as e:
             print(f"WARNING: Failed to parse World Bank CSV: {e}", file=sys.stderr)

    return idx


def screen_company(
    company_name: str,
    *,
    cache_dir: Path,
    snapshot_id: Optional[str],
    top_k: int,
    review_threshold: float,
    block_threshold: float,
) -> Tuple[str, List[EntityHit], str]:
    """
    Returns (snapshot_id, hits, decision) where decision in {"PASS","REVIEW","BLOCK"}.
    """
    if not _normalize(company_name):
        raise ValueError("Company name is empty after normalization")

    if snapshot_id is None:
        snapshot_id = load_latest_snapshot_id(cache_dir)

    snapshot_path = _snapshot_dir(cache_dir, snapshot_id)
    if not snapshot_path.exists():
        raise FileNotFoundError(f"Snapshot not found: {snapshot_path}")

    index = _index_snapshot(snapshot_path)

    hits: List[EntityHit] = []
    for key, ent in index.items():
        best = MatchEvidence(field="primary", matched_value="", score=0.0)

        # Primary names
        for n in ent["primary"]:
            s = _token_set_similarity(company_name, n)
            if s > best.score:
                best = MatchEvidence(field="primary", matched_value=n, score=s)

        # Alias names
        for n in ent["aliases"]:
            s = _token_set_similarity(company_name, n)
            if s > best.score:
                best = MatchEvidence(field="alias", matched_value=n, score=s)

        if best.score >= review_threshold:
            hits.append(
                EntityHit(
                    entity_id=ent["entity_id"],
                    source_list=ent["source_list"],
                    best_score=best.score,
                    best_evidence=best,
                    primary_names=ent["primary"][:5],
                    alias_names=ent["aliases"][:5],
                    programs=sorted(ent["programs"]),
                    addresses=sorted(ent["addresses"])[:5],
                )
            )

    hits.sort(key=lambda h: h.best_score, reverse=True)
    hits = hits[:top_k]

    decision = "PASS"
    if hits:
        if hits[0].best_score >= block_threshold:
            decision = "BLOCK"
        else:
            decision = "REVIEW"

    return snapshot_id, hits, decision


def append_audit(
    cache_dir: Path,
    snapshot_id: str,
    record: Dict,
) -> None:
    snapshot_path = _snapshot_dir(cache_dir, snapshot_id)
    audit_path = snapshot_path / "audit.jsonl"
    with audit_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(
        prog="sanctions_screen",
        description="Screen names against global sanctions lists (OFAC, BIS, UN, EU, UK)"
    )
    p.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR))
    sub = p.add_subparsers(dest="cmd", required=True)

    p_up = sub.add_parser("update", help="Download all sanctions lists (OFAC, BIS, UN, EU, UK)")
    p_up.add_argument("--timeout", type=int, default=120)
    p_up.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    p_up.add_argument("--no-bis", action="store_true", help="Skip BIS export control lists")
    p_up.add_argument("--no-intl", action="store_true", help="Skip international lists (UN, EU, UK)")
    p_up.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")

    p_sc = sub.add_parser("screen", help="Screen a name against latest or given snapshot")
    p_sc.add_argument("company_name")
    p_sc.add_argument("--snapshot-id", default=None)
    p_sc.add_argument("--top-k", type=int, default=10)
    p_sc.add_argument("--review-threshold", type=float, default=DEFAULT_REVIEW_THRESHOLD)
    p_sc.add_argument("--block-threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)

    args = p.parse_args(argv)
    cache_dir = Path(args.cache_dir)

    if args.cmd == "update":
        try:
            sid = update_snapshot(
                cache_dir,
                timeout=args.timeout,
                user_agent=args.user_agent,
                include_bis=not getattr(args, 'no_bis', False),
                include_intl=not getattr(args, 'no_intl', False),
                verify_ssl=not getattr(args, 'no_ssl_verify', False),
            )
        except Exception as e:
            print(f"ERROR update: {e}", file=sys.stderr)
            return 1

        print(f"Snapshot created: {sid}", file=sys.stderr)
        print(f"Last updated: {get_last_updated_time(cache_dir)}", file=sys.stderr)
        print(sid)
        return 0

    if args.cmd == "screen":
        try:
            sid, hits, decision = screen_company(
                args.company_name,
                cache_dir=cache_dir,
                snapshot_id=args.snapshot_id,
                top_k=args.top_k,
                review_threshold=args.review_threshold,
                block_threshold=args.block_threshold,
            )
        except Exception as e:
            print(f"ERROR screen: {e}", file=sys.stderr)
            return 1

        out = {
            "timestamp_utc": _utc_now_iso(),
            "snapshot_id": sid,
            "input": {"company_name": args.company_name},
            "thresholds": {
                "review_threshold": args.review_threshold,
                "block_threshold": args.block_threshold,
            },
            "decision": decision,
            "hits": [
                {
                    "source_list": h.source_list,
                    "entity_id": h.entity_id,
                    "best_score": h.best_score,
                    "best_evidence": asdict(h.best_evidence),
                    "primary_names": h.primary_names,
                    "alias_names": h.alias_names,
                    "programs": h.programs,
                    "addresses": h.addresses,
                }
                for h in hits
            ],
        }

        append_audit(cache_dir, sid, out)

        # Human-readable output
        print(f"\n{'='*70}")
        print(f"SCREENING RESULT")
        print(f"{'='*70}")
        print(f"  Query:       {args.company_name}")
        print(f"  Snapshot:    {sid}")
        print(f"  Updated:     {get_last_updated_time(cache_dir)}")
        print(f"  Decision:    {decision}")
        print(f"  Matches:     {len(hits)}")
        print(f"{'='*70}")

        if not hits:
            print("\n  No matches found.\n")
            return 0

        # Group hits by source
        from collections import defaultdict
        grouped: Dict[str, List] = defaultdict(list)
        for h in hits:
            # Extract base source (OFAC or BIS)
            base = h.source_list.split("-")[0]
            grouped[base].append(h)

        for source in ["OFAC", "BIS", "UN", "EU", "UK", "CA", "AU", "CH", "WB"]:
            source_hits = grouped.get(source, [])
            if not source_hits:
                continue
            print(f"\n  {source} MATCHES ({len(source_hits)})")
            print(f"  {'-'*66}")
            for h in source_hits:
                ev = h.best_evidence
                score_bar = "█" * int(h.best_score / 10) + "░" * (10 - int(h.best_score / 10))
                print(f"\n  [{h.source_list}] Score: {h.best_score:5.1f}% {score_bar}")
                print(f"  Name:    {ev.matched_value}")
                print(f"  ID:      {h.entity_id}")
                if h.programs:
                    # Truncate long program text
                    prog = h.programs[0]
                    if len(prog) > 60:
                        prog = prog[:57] + "..."
                    print(f"  Program: {prog}")
                if h.addresses:
                    addr = h.addresses[0]
                    if len(addr) > 60:
                        addr = addr[:57] + "..."
                    print(f"  Address: {addr}")

        print(f"\n{'='*70}")
        print(f"SCORING METHOD")
        print(f"{'='*70}")
        print(f"  Score = 80% token overlap (Jaccard) + 20% character similarity")
        print(f"  - Tokens: words after lowercasing, removing punctuation")
        print(f"  - 100% = exact match | 50%+ = likely match | <30% = weak match")
        print(f"  - BLOCK >= {args.block_threshold}% | REVIEW >= {args.review_threshold}% | PASS < {args.review_threshold}%")
        print(f"{'='*70}\n")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
