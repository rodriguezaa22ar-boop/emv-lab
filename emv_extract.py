from smartcard.System import readers
from smartcard.util import toHexString
from pathlib import Path
import json

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

def transmit(conn, apdu):
    return conn.transmit(apdu)

def hx(data):
    return toHexString(data) if data else ""

def redact(tag: str, value: str) -> str:
    value = value.replace(" ", "")
    if tag == "5A":
        return value[:6] + "...REDACTED"
    if tag == "57":
        return value[:10] + "...REDACTED"
    if tag == "5F20":
        return "REDACTED NAME"
    return value

def parse_tlv(data):
    items = []
    i = 0
    n = len(data)

    while i < n:
        tag_start = i
        i += 1
        if tag_start >= n:
            break

        if (data[tag_start] & 0x1F) == 0x1F:
            while i < n and (data[i] & 0x80):
                i += 1
            if i < n:
                i += 1

        tag = data[tag_start:i]
        tag_hex = "".join(f"{b:02X}" for b in tag)

        if i >= n:
            break

        length_byte = data[i]
        i += 1

        if length_byte & 0x80:
            num_len_bytes = length_byte & 0x7F
            length = 0
            for _ in range(num_len_bytes):
                length = (length << 8) | data[i]
                i += 1
        else:
            length = length_byte

        value = data[i:i + length]
        i += length

        constructed = bool(tag[0] & 0x20)
        children = parse_tlv(value) if constructed else []

        items.append({
            "tag": tag_hex,
            "name": TAG_NAMES.get(tag_hex, "Unknown"),
            "length": length,
            "value_hex": hx(value),
            "display_value": redact(tag_hex, hx(value)) if tag_hex in REDACT_TAGS else hx(value),
            "constructed": constructed,
            "children": children,
        })

    return items

def find_tag(items, wanted):
    out = []
    for item in items:
        if item["tag"] == wanted:
            out.append(item)
        out.extend(find_tag(item["children"], wanted))
    return out

def send(conn, apdu, label):
    print(f"\n[{label}]")
    print("=>", hx(apdu))
    data, sw1, sw2 = transmit(conn, apdu)
    print("<=", hx(data))
    print("SW =", f"{sw1:02X} {sw2:02X}")

    if sw1 == 0x6C:
        fixed = apdu[:-1] + [sw2]
        print("[RETRY WITH CORRECT Le]")
        print("=>", hx(fixed))
        data, sw1, sw2 = transmit(conn, fixed)
        print("<=", hx(data))
        print("SW =", f"{sw1:02X} {sw2:02X}")

    if sw1 == 0x61:
        get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
        print("[GET RESPONSE]")
        print("=>", hx(get_response))
        data, sw1, sw2 = transmit(conn, get_response)
        print("<=", hx(data))
        print("SW =", f"{sw1:02X} {sw2:02X}")

    return data, sw1, sw2

def parse_afl_bytes(afl):
    entries = []
    for i in range(0, len(afl), 4):
        sfi_byte, first_rec, last_rec, offline_count = afl[i:i+4]
        entries.append({
            "sfi": sfi_byte >> 3,
            "first_record": first_rec,
            "last_record": last_rec,
            "offline_auth_count": offline_count,
        })
    return entries

def build_read_record_apdu(sfi, record):
    return [0x00, 0xB2, record, (sfi << 3) | 0x04, 0x00]

def main():
    r = readers()
    print("Readers:", r)
    if not r:
        raise SystemExit("No readers found")

    conn = r[0].createConnection()
    conn.connect()

    ppse = [0x00, 0xA4, 0x04, 0x00, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31]
    mc_aid = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10]
    gpo = [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00]

    ppse_data, _, _ = send(conn, ppse, "SELECT PPSE")
    aid_data, _, _ = send(conn, mc_aid, "SELECT MASTERCARD AID")
    gpo_data, gsw1, gsw2 = send(conn, gpo, "GET PROCESSING OPTIONS")

    if (gsw1, gsw2) != (0x90, 0x00):
        raise SystemExit("GPO failed")

    ppse_tlv = parse_tlv(ppse_data)
    aid_tlv = parse_tlv(aid_data)
    gpo_tlv = parse_tlv(gpo_data)

    afl_tags = find_tag(gpo_tlv, "94")
    if not afl_tags:
        raise SystemExit("No AFL found")

    afl_raw = bytes.fromhex(afl_tags[0]["value_hex"].replace(" ", ""))
    afl_entries = parse_afl_bytes(afl_raw)

    print("\n[AFL]")
    for e in afl_entries:
        print(e)

    records = []
    for entry in afl_entries:
        for rec in range(entry["first_record"], entry["last_record"] + 1):
            apdu = build_read_record_apdu(entry["sfi"], rec)
            data, sw1, sw2 = send(conn, apdu, f"READ RECORD SFI{entry['sfi']} REC{rec}")
            records.append({
                "sfi": entry["sfi"],
                "record": rec,
                "sw1": f"{sw1:02X}",
                "sw2": f"{sw2:02X}",
                "raw_hex": hx(data),
                "tlv": parse_tlv(data) if data else [],
            })

    artifact = {
        "reader": str(r[0]),
        "ppse": {"raw_hex": hx(ppse_data), "tlv": ppse_tlv},
        "selected_aid": {"raw_hex": hx(aid_data), "tlv": aid_tlv},
        "gpo": {"raw_hex": hx(gpo_data), "tlv": gpo_tlv},
        "afl_entries": afl_entries,
        "records": records,
    }

    base = Path(__file__).resolve().parent
    dump_dir = base / "dumps"
    dump_dir.mkdir(exist_ok=True)
    dump_file = dump_dir / "emv_dump.json"

    with open(dump_file, "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\nSaved structured dump to {dump_file}")

if __name__ == "__main__":
    main()
