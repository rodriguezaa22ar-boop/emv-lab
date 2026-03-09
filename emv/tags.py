TAG_NAMES = {
    "4F": "Application Identifier (AID)",
    "50": "Application Label",
    "57": "Track 2 Equivalent Data",
    "5A": "Primary Account Number",
    "5F20": "Cardholder Name",
    "5F24": "Application Expiration Date",
    "5F25": "Application Effective Date",
    "5F28": "Issuer Country Code",
    "5F2D": "Language Preference",
    "5F34": "PAN Sequence Number",
    "5F55": "Issuer Country (Alpha2)",

    "6F": "File Control Information",
    "61": "Application Template",
    "70": "Record Template",
    "77": "Response Message Template Format 2",
    "A5": "FCI Proprietary Template",
    "BF0C": "FCI Issuer Discretionary Data",

    "82": "Application Interchange Profile",
    "84": "Dedicated File Name",
    "87": "Application Priority Indicator",
    "8C": "CDOL1",
    "8D": "CDOL2",
    "8E": "CVM List",
    "8F": "Certification Authority Public Key Index",
    "90": "Issuer Public Key Certificate",

    "94": "Application File Locator",

    "9F07": "Application Usage Control",
    "9F08": "Application Version Number",
    "9F0D": "Issuer Action Code Default",
    "9F0E": "Issuer Action Code Denial",
    "9F0F": "Issuer Action Code Online",

    "9F32": "Issuer Public Key Exponent",
    "9F37": "Unpredictable Number",
    "9F42": "Application Currency Code",
    "9F44": "Application Currency Exponent",
    "9F46": "ICC Public Key Certificate",
    "9F47": "ICC Public Key Exponent",
    "9F48": "ICC Public Key Remainder",
    "9F49": "DDOL",
    "9F4A": "SDA Tag List",
    "9F4D": "Log Entry",
    "9F6E": "Third Party Data"
}

def tag_name(tag):
    tag = tag.upper()
    return TAG_NAMES.get(tag, "Unknown")
