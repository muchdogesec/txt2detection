import pytest
from txt2detection import observables

# from stix2 import Observable


@pytest.mark.parametrize(
    "obs_type,value,expected",
    [
        ("ipv4-addr", "192.168.1.1", True),
        ("ipv4-addr", "999.999.999.999", False),
        ("ipv6-addr", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", True),
        ("ipv6-addr", "12345::6789::abcd", False),
        ("email-addr", "test@example.com", True),
        ("email-addr", "bad-email@", False),
        ("url", "http://example.com", True),
        ("url", "notaurl", False),
        ("domain-name", "example.com", True),
        ("domain-name", "not_domain", False),
        ("file.hashes.MD5", "d41d8cd98f00b204e9800998ecf8427e", True),
        ("file.hashes.MD5", "invalidmd5hash", False),
        ("mac-addr", "00:1A:2B:3C:4D:5E", True),
        ("mac-addr", "00:00:00:00:00:ZZ", False),
        ("windows-registry-key", "HKCU\\Software\\Microsoft", True),
        ("windows-registry-key", "INVALID\\Path", False),
    ],
)
def test_filter_out(obs_type, value, expected):
    result = observables.filter_out(obs_type, value)
    assert bool(result) == expected


def test_find_stix_observables_simple():
    sha256 = "a" * 64
    detection = {
        "ip": "192.168.1.1",
        "email": "user@example.com",
        "random_key": "not an ip",
        "nested": {
            "url": "http://example.com/path",
            "sha256": sha256,
        },
        "list": [
            {"host": "example.com"},
            "https://site.com",
            "not a url",
        ],
    }
    matches = observables.find_stix_observables(detection)

    assert {
        ("ipv4-addr", "192.168.1.1"),
        ("email-addr", "user@example.com"),
        ("domain-name", "example.com"),
        ("url", "http://example.com/path"),
        ("url", "https://site.com"),
        ("file.hashes.SHA-256", sha256),
    } == set(matches)


@pytest.mark.parametrize(
    "observable_type,value,expected_type,expected_value",
    [
        ("ipv4-addr", "1.2.3.4", "ipv4-addr", "1.2.3.4"),
        ("ipv6-addr", "2001:db8::1", "ipv6-addr", "2001:db8::1"),
        ("email-addr", "a@b.com", "email-addr", "a@b.com"),
        ("url", "http://x.com", "url", "http://x.com"),
        ("domain-name", "example.com", "domain-name", "example.com"),
        ("mac-addr", "00:11:22:33:44:55", "mac-addr", "00:11:22:33:44:55"),
        ("file.hashes.MD5", "d41d8cd98f00b204e9800998ecf8427e", "file", None),
        ("file.hashes.SHA-1", "a" * 40, "file", None),
        ("file.hashes.SHA-256", "b" * 64, "file", None),
        ("file.hashes.SHA-512", "c" * 128, "file", None),
        ("file.hashes.SSDEEP", "3:abcdefghij:klmnopqrst", "file", None),
        (
            "windows-registry-key",
            "HKLM\\Software\\Microsoft",
            "windows-registry-key",
            "HKLM\\Software\\Microsoft",
        ),
        ("unknown-type", "something", None, None),
    ],
)
def test_to_stix_object(observable_type, value, expected_type, expected_value):
    stix_obj = observables.to_stix_object(observable_type, value)
    if expected_type is None:
        assert stix_obj is None
    else:
        assert stix_obj.type == expected_type
        if expected_type == "file":
            assert getattr(stix_obj, "hashes", None) is not None
        elif expected_type == "windows-registry-key":
            assert getattr(stix_obj, "key", None) == value
        else:
            # For other types, value attribute should match input value
            assert stix_obj.value == value
