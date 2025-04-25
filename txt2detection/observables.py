import re, validators
from typing import Any, Dict, List
from stix2 import parse as parse_stix, parse_observable

# Mapping of key regex patterns to STIX observable types
STIX_PATTERNS_KEYS = {
    "ipv4-addr": r"(?i)\b(ip|ipv4)\b",
    "ipv6-addr": r"(?i)\bipv6\b",
    "email-addr": r"(?i)\bemail\b",
    "url": r"(?i)\b(url|uri)\b",
    "directory": r"(?i)\b(directory|path)\b",
    "domain-name": r"(?i)\bdomain\b",
    "hostname": r"(?i)\bhost\b",
    "file.hashes.MD5": r"(?i)\bmd5\b",
    "file.hashes.SHA-1": r"(?i)\bsha1\b",
    "file.hashes.SHA-256": r"(?i)\bsha256\b",
    "file.hashes.SHA-512": r"(?i)\bsha512\b",
    "file.hashes.SSDEEP": r"(?i)\bssdeep\b",
    "mac-addr": r"(?i)\bmac\b",
    "user-account": r"(?i)\buser\b",
    "windows-registry-key": r"(?i)\bregistry\b",
    "x509-certificate": r"(?i)\bx509\b",
}

# Mapping of value regex patterns to STIX observable types
STIX_PATTERNS_VALUES = {
    "ipv4-addr": [r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}\b"],
    "ipv6-addr": [r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b"],
    "email-addr": [r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"],
    "url": [r"\bhttps?://[^\s/$.?#].[^\x00\s]*\b"],
    "directory": [r"(?:[A-Za-z]:)?(?:\\\\[^\\\\:*?\"<>|\r\n]+)+\\\\?"],
    "domain-name": [r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"],
    "hostname": [r"\b[a-zA-Z0-9-]{1,63}(\.[a-zA-Z0-9-]{1,63})*\b"],
    "file.hashes.MD5": [r"\b[a-fA-F0-9]{32}\b"],
    "file.hashes.SHA-1": [r"\b[a-fA-F0-9]{40}\b"],
    "file.hashes.SHA-256": [r"\b[a-fA-F0-9]{64}\b"],
    "file.hashes.SHA-512": [r"\b[a-fA-F0-9]{128}\b"],
    "file.hashes.SSDEEP": [r"\b\d{1,}:[A-Za-z0-9/+]{10,}:[A-Za-z0-9/+]{10,}\b"],
    "mac-addr": [r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b"],
    "user-account": [r"\b[A-Za-z0-9._%-]{3,}\\\\?[A-Za-z0-9._%-]{3,}\b"],
    "windows-registry-key": [r"HK\w{0,2}_[A-Z_]+\\.*"],
    "x509-certificate": [r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----"],
}


def filter_out(type, value: str):
    match type:
        case "ipv4-addr":
            return validators.ipv4(value)
        case "ipv6-addr":
            return validators.ipv6(value)
        case "email-addr":
            return validators.email(value)
        case "url":
            return validators.url(value)
        case "domain-name":
            return validators.domain(value, consider_tld=True)
        case "file.hashes.MD5":
            return validators.hashes.md5(value)
        case "file.hashes.SHA-1":
            return validators.hashes.sha1(value)
        case "file.hashes.SHA-256":
            return validators.hashes.sha256(value)
        case "file.hashes.SHA-512":
            return validators.hashes.sha512(value)
        case "file.hashes.SSDEEP":
            pass
        case "mac-addr":
            return validators.mac_address(value)
        case "user-account":
            pass

        case "windows-registry-key":
            print(value)
            ns, _, _ = value.partition("\\")
            return ns in [
                "HKEY_CLASSES_ROOT",
                "HKCR",
                "HKEY_CURRENT_USER",
                "HKCU",
                "HKEY_LOCAL_MACHINE",
                "HKLM",
                "HKEY_USERS",
                "HKU",
                "HKEY_CURRENT_CONFIG",
                "HKCC",
                "HKEY_PERFORMANCE_DATA",
                "HKEY_DYN_DATA",
            ]
        case _:
            return False
    return False


def find_stix_observables(detection: Any, matches: List[str] = None) -> List[str]:
    if matches is None:
        matches = []

    if isinstance(detection, dict):
        for key, value in detection.items():
            for stix_type, key_pattern in STIX_PATTERNS_KEYS.items():
                value_patterns = STIX_PATTERNS_VALUES.get(stix_type, [])
                if re.search(key_pattern, key, re.IGNORECASE):
                    for pattern in value_patterns:
                        if isinstance(value, str) and re.search(
                            pattern, value, re.IGNORECASE
                        ):
                            if filter_out(stix_type, value):
                                matches.append((stix_type, value))
                find_stix_observables(value, matches)
            find_stix_observables(value, matches)
    elif isinstance(detection, list):
        for item in detection:
            find_stix_observables(item, matches)
    elif isinstance(detection, str):
        for stix_type, value_patterns in STIX_PATTERNS_VALUES.items():
            for pattern in value_patterns:
                if re.search(pattern, detection, re.IGNORECASE):
                    if filter_out(stix_type, detection):
                        matches.append((stix_type, detection))
    return matches


def to_stix_object(observable_type: str, value):
    match observable_type:
        case (
            "ipv4-addr"
            | "ipv6-addr"
            | "email-addr"
            | "url"
            | "domain-name"
            | "mac-addr"
        ):
            return parse_observable(
                dict(
                    type=observable_type,
                    value=value,
                    spec_version="2.1",
                )
            )
        case (
            "file.hashes.MD5"
            | "file.hashes.SHA-1"
            | "file.hashes.SHA-256"
            | "file.hashes.SHA-512"
            | "file.hashes.SSDEEP"
        ):
            _, _, hash_type = observable_type.rpartition(".")
            return parse_observable(
                dict(type="file", spec_version="2.1", hashes={hash_type: value})
            )

        case "windows-registry-key":
            return parse_observable(
                dict(
                    type=observable_type,
                    spec_version="2.1",
                    key=value,
                )
            )
    return None


# example_detection = {
#     "selection": {
#         "source_ip": "192.168.1.10",
#         "destination_email": "attacker@example.com",
#         "url_path": "http://malicious.example.com/payload.exe",
#         "file_hash_md5": "44d88612fea8a8f36de82e1278abb02f",
#         "mac_address": "00:1A:2B:3C:4D:5E",
#         "username": "CORP\\jdoe",
#         "registry_key": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
#         "registry_key2": "HK_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
#         "certificate": "-----BEGIN CERTIFICATE-----FAKECERT-----END CERTIFICATE-----",
#         "ip": " 192.167.1.1",
#     },
#     "condition": "selection",
# }

# # Usage
# observables = find_stix_observables(example_detection)
# print(observables)

# for a, b in observables:
#     print(to_stix_object(a, b))

