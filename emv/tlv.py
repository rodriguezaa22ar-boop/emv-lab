def hexify(data):
    return " ".join(f"{b:02X}" for b in data)


def parse_tlv(data):
    i = 0
    items = []

    while i < len(data):
        tag = data[i]
        i += 1

        if tag & 0x1F == 0x1F:
            tag = (tag << 8) | data[i]
            i += 1

        length = data[i]
        i += 1

        if length & 0x80:
            num_bytes = length & 0x7F
            length = int.from_bytes(data[i:i+num_bytes], "big")
            i += num_bytes

        value = data[i:i+length]
        i += length

        items.append({
            "tag": f"{tag:X}",
            "length": length,
            "value": value
        })

    return items

def find_tag(items, target):
    for item in items:
        if item["tag"].upper() == target.upper():
            return item
    return None

from .tags import tag_name


def build_tlv_tree(data):
    nodes = []
    parsed = parse_tlv(data)

    for item in parsed:
        node = {
            "tag": item["tag"],
            "name": tag_name(item["tag"]),
            "length": item["length"],
            "value": item["value"],
            "children": []
        }

        if item["value"] and item["value"][0] & 0x20:
            try:
                node["children"] = build_tlv_tree(item["value"])
            except Exception:
                pass

        nodes.append(node)

    return nodes
