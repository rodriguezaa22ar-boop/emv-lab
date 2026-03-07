import json
from pathlib import Path

TAG_NAMES = {
    "4F": "AID",
    "50": "Application Label",
    "57": "Track 2 Equivalent Data",
    "5A": "PAN",
    "5F20": "Cardholder Name",
    "5F24": "Application Expiration Date",
    "5F25": "Application Effective Date",
    "5F28": "Issuer Country Code",
    "5F2D": "Language Preference",
    "5F34": "PAN Sequence Number",
    "5F55": "Issuer Country (Alpha2)",
    "82": "AIP",
    "84": "DF Name",
    "87": "Application Priority Indicator",
    "8C": "CDOL1",
    "8D": "CDOL2",
    "8E": "CVM List",
    "8F": "CA Public Key Index",
    "90": "Issuer Public Key Certificate",
    "94": "AFL",
    "9F07": "Application Usage Control",
    "9F08": "Application Version Number",
    "9F0D": "Issuer Action Code Default",
    "9F0E": "Issuer Action Code Denial",
    "9F0F": "Issuer Action Code Online",
    "9F1D": "Terminal Risk Management Data",
    "9F32": "Issuer Public Key Exponent",
    "9F42": "Application Currency Code",
    "9F43": "Application Reference Currency Exponent",
    "9F44": "Application Currency Exponent",
    "9F46": "ICC Public Key Certificate",
    "9F47": "ICC Public Key Exponent",
    "9F48": "ICC Public Key Remainder",
    "9F49": "DDOL",
    "9F4A": "SDA Tag List",
    "9F4D": "Log Entry",
    "9F6E": "Third Party Data",
}

REDACT_TAGS = {"5A", "57", "5F20"}

def redact(tag: str, value: str) -> str:
    value = value.replace(" ", "")
    if tag == "5A":
        return value[:6] + "...REDACTED"
    if tag == "57":
        return value[:10] + "...REDACTED"
    if tag == "5F20":
        return "REDACTED NAME"
    return value

def flatten_tlv(items):
    rows = []
    for item in items:
        rows.append(item)
        rows.extend(flatten_tlv(item.get("children", [])))
    return rows

def report_section(title):
    return f"\n{'=' * 12} {title} {'=' * 12}\n"

def main():
    base = Path(__file__).resolve().parent
    dump_file = base / "dumps" / "emv_dump.json"
    report_dir = base / "reports"
    report_dir.mkdir(exist_ok=True)
    report_file = report_dir / "emv_report.txt"

    if not dump_file.exists():
        raise SystemExit(f"Missing dump file: {dump_file}")

    with open(dump_file, "r") as f:
        data = json.load(f)

    lines = []
    lines.append("EMV REPORT")
    lines.append(f"Reader: {data.get('reader', 'unknown')}")

    lines.append(report_section("PPSE"))
    for item in flatten_tlv(data.get("ppse", {}).get("tlv", [])):
        tag = item["tag"]
        name = TAG_NAMES.get(tag, item.get("name", "Unknown"))
        value = redact(tag, item.get("display_value", item.get("value_hex", ""))) if tag in REDACT_TAGS else item.get("value_hex", "")
        lines.append(f"{tag:<6} {name:<35} {value}")

    lines.append(report_section("SELECTED APPLICATION"))
    for item in flatten_tlv(data.get("selected_aid", {}).get("tlv", [])):
        tag = item["tag"]
        name = TAG_NAMES.get(tag, item.get("name", "Unknown"))
        value = redact(tag, item.get("display_value", item.get("value_hex", ""))) if tag in REDACT_TAGS else item.get("value_hex", "")
        lines.append(f"{tag:<6} {name:<35} {value}")

    lines.append(report_section("GPO"))
    for item in flatten_tlv(data.get("gpo", {}).get("tlv", [])):
        tag = item["tag"]
        name = TAG_NAMES.get(tag, item.get("name", "Unknown"))
        value = item.get("value_hex", "")
        lines.append(f"{tag:<6} {name:<35} {value}")

    lines.append(report_section("AFL ENTRIES"))
    for entry in data.get("afl_entries", []):
        lines.append(
            f"SFI={entry['sfi']} first_record={entry['first_record']} "
            f"last_record={entry['last_record']} offline_auth_count={entry['offline_auth_count']}"
        )

    lines.append(report_section("RECORDS"))
    for rec in data.get("records", []):
        lines.append(f"Record: SFI={rec['sfi']} REC={rec['record']} SW={rec['sw1']} {rec['sw2']}")
        for item in flatten_tlv(rec.get("tlv", [])):
            tag = item["tag"]
            name = TAG_NAMES.get(tag, item.get("name", "Unknown"))
            value = redact(tag, item.get("display_value", item.get("value_hex", ""))) if tag in REDACT_TAGS else item.get("value_hex", "")
            lines.append(f"  {tag:<6} {name:<35} {value}")
        lines.append("")

    report_text = "\n".join(lines)

    with open(report_file, "w") as f:
        f.write(report_text)

    print(report_text)
    print(f"\nSaved report to {report_file}")

if __name__ == "__main__":
    main()
