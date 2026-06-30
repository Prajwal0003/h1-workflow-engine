"""
Insecure Deserialization Scanner.
Ref: awesome-bugbounty-tools (ysoserial, GadgetProbe, phpggc).
"""
import re
from .utils import stealth_headers, safe_get


DESER_INDICATORS = {
    "Java": {
        "headers": ["application/x-java-serialized-object"],
        "patterns": [r"rO0AB", r"aced0005"],  # Java serialized object magic bytes (base64 and hex)
        "error_strings": ["java.io.InvalidClassException", "java.io.StreamCorruptedException",
                         "ClassNotFoundException", "ObjectInputStream"],
    },
    "PHP": {
        "headers": [],
        "patterns": [r'[OaCsi]:\d+:', r'a:\d+:\{'],  # PHP serialized format
        "error_strings": ["unserialize()", "PHP Fatal error", "__wakeup", "__destruct"],
    },
    ".NET": {
        "headers": [],
        "patterns": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "error_strings": ["System.Runtime.Serialization", "BinaryFormatter",
                         "ObjectStateFormatter"],
    },
    "Python": {
        "headers": [],
        "patterns": [r"gASV", r"\\x80\\x04\\x95"],  # Pickle magic bytes
        "error_strings": ["pickle.loads", "UnpicklingError", "_pickle"],
    },
}


def check_insecure_deserialization(url):
    """Check for insecure deserialization indicators in responses."""
    findings = []

    r = safe_get(url)
    if not r:
        return None

    # Check response body and headers for serialization indicators
    full_text = r.text
    full_headers = str(r.headers)

    for lang, checks in DESER_INDICATORS.items():
        # Check headers
        for h in checks["headers"]:
            if h.lower() in full_headers.lower():
                findings.append({
                    "type": f"DESERIALIZATION_{lang.upper()}",
                    "url": url,
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "detail": f"{lang} serialized object detected in Content-Type"
                })

        # Check patterns in body
        for pattern in checks["patterns"]:
            if re.search(pattern, full_text):
                findings.append({
                    "type": f"DESERIALIZATION_{lang.upper()}_OBJECT",
                    "url": url,
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "detail": f"{lang} serialized data found in response body"
                })
                break

    # Check for .NET ViewState without MAC
    viewstate_match = re.search(r'__VIEWSTATE[^>]*value="([^"]+)"', full_text)
    if viewstate_match:
        vs_value = viewstate_match.group(1)
        # ViewState without MAC is typically shorter and doesn't end with ==
        if len(vs_value) > 20:
            # Check if MAC is disabled
            mac_match = re.search(r'__VIEWSTATEMAC', full_text)
            if not mac_match:
                findings.append({
                    "type": "VIEWSTATE_NO_MAC",
                    "url": url,
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "detail": "ASP.NET ViewState found — MAC validation may be disabled"
                })

    return findings if findings else None
