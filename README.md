# Global Sanctions & Export Control Screening

A Python tool for downloading, parsing, and screening entities against major global sanctions and export control lists.

## Supported Data Sources

This tool aggregates data from the following official government and international organization sources:

### Primary Sanctions Lists
| Jurisdiction | List Name | Source Description | Format |
| :--- | :--- | :--- | :--- |
| **USA (OFAC)** | Specially Designated Nationals (SDN) | Treasury Dept. list of individuals/entities blocked from US financial system. | CSV |
| **USA (OFAC)** | Consolidated (Non-SDN) | Other sanctions lists (SSI, FSE, PLC, etc.) not included in SDN. | CSV |
| **USA (BIS)** | Entity List (EL) | Commerce Dept. list of parties subject to specific export licensing requirements. | CSV |
| **USA (BIS)** | Unverified List (UVL) | Parties where end-use checks could not be verified. | CSV |
| **USA (BIS)** | Military End-User (MEU) | Parties restricted from receiving items for military end-use. | CSV |
| **UN** | Security Council Consolidated | All individuals/entities subject to UN Security Council sanctions measures. | XML |
| **EU** | Financial Sanctions | Consolidated list of persons, groups, and entities subject to EU financial sanctions. | CSV |
| **UK** | Sanctions List | UK Foreign, Commonwealth & Development Office (FCDO) sanctions designations. | CSV |
| **Canada** | SEMA Consolidated | Special Economic Measures Act (SEMA) sanctions (Autonomous). | XML |
| **Australia** | DFAT Consolidated | Dept. of Foreign Affairs and Trade list of persons/entities subject to targeted sanctions. | XLSX |
| **Switzerland** | SECO Sanctions | State Secretariat for Economic Affairs measures (often mirrors UN/EU but independent). | XML |
| **World Bank** | Debarred Firms | List of firms and individuals ineligible for World Bank-financed contracts (Fraud/Corruption). | CSV |

## Installation

Ensure you have Python 3.8+ installed.

1.  **Clone or download the repository.**
2.  **Install dependencies:**
    This script requires a few external libraries for progress bars and file parsing (`pandas`, `openpyxl`, `tqdm`, `requests`).

    ```bash
    pip install pandas openpyxl tqdm requests
    ```

## Usage

The script has two main modes: `update` and `screen`.

### 1. Update Data (`update`)

Downloads the latest versions of all sanctions lists to a local cache directory (`.sanctions/`). This creates an immutable "snapshot" of the data at that point in time.

```bash
python3 ofac.py update --no-ssl-verify
```

*   **`--no-ssl-verify`**: (Recommended) Some government servers have SSL configuration issues. This flag bypasses verification to ensure downloads succeed.
*   **Data Storage**: Data is stored in `./.sanctions/snapshots/<timestamp>_hash/`.
*   **Manifest**: Each snapshot includes a `manifest.json` detailing exactly where and when each file was downloaded, along with SHA256 hashes for auditability.

### 2. Screen Entities (`screen`)

Screens a company or individual name against the latest downloaded snapshot.

```bash
python3 ofac.py screen "Name to Screen"
```

**Options:**
*   `--top-k 20`: Show the top 20 closest matches (default: 10).
*   `--review-threshold 20`: Set the minimum score (0-100) to consider a "hit" worth reviewing (default: 20).
*   `--block-threshold 90`: Set the score above which a match is considered a "BLOCK" (default: 90).
*   `--snapshot-id <ID>`: Screen against a specific historical snapshot instead of the latest one.

**Example Output:**
```text
======================================================================
SCREENING RESULT
======================================================================
  Query:       Iran Air
  Snapshot:    20260121T215443+0000_8e3dcd2b93db
  Updated:     2026-01-21 21:54:43 UTC
  Decision:    REVIEW
  Matches:     20
======================================================================

  OFAC MATCHES (7)
  ------------------------------------------------------------------
  [OFAC-SDN] Score:  53.3% █████░░░░░
  Name:    IRAN AIR
  ID:      25237
  Program: IRAN] [IRAN-CON-ARMS-EO] [RUSSIA-EO14024
  ...
```

## Screening Strategy & Scoring

The tool uses a **deterministic, explainable scoring algorithm** suitable for compliance audits.

*   **Token-Set Similarity (80% weight)**: Measures the overlap of unique words (tokens) between the query and the list entry.
    *   Ignores case and punctuation.
    *   "Iran Air" matches "Air Iran" perfectly (100%).
*   **Sequence Similarity (20% weight)**: Measures the similarity of the character sequence.
    *   Boosts scores for names that are spelled similarly and in the same order.
*   **Normalization**: All names are normalized (NFKC unicode normalization, lowercased, special characters removed) before comparison.

**Decision Logic:**
*   **BLOCK (>= 90%)**: High confidence match. Typically requires immediate freezing of transaction/account pending investigation.
*   **REVIEW (20% - 89%)**: Potential match. Requires human review to rule out false positives (e.g., common names).
*   **PASS (< 20%)**: No significant match found.

## Testing

A test suite is provided to verify that the tool correctly identifies known entities from *every* supported list.

```bash
python3 test_ofac.py
```

This verifies parsing logic for all 12+ sources and ensures that key targets (e.g., "Iran Air", "Igor Rotenberg") are being correctly indexed and scored.

## Audit Trail

Every screening run is logged to an audit file for compliance records.
Location: `.sanctions/snapshots/<snapshot_id>/audit.jsonl`

Each line is a JSON object containing:
*   Timestamp
*   Input query
*   Snapshot ID used
*   Thresholds applied
*   Full list of hits returned
*   Final system decision (PASS/REVIEW/BLOCK)

## Author

**Rafael Sene** - [rpsene@gmail.com](mailto:rpsene@gmail.com)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
