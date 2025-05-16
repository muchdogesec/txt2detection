from datetime import datetime, date
from txt2detection.utils import remove_rule_specific_tags, as_date


def test_remove_rule_specific_tags():
    tags = ["attack.t1003", "cve.CVE-2023-1234", "tlp.red", "customtag", "another"]
    filtered = remove_rule_specific_tags(tags)
    assert "customtag" in filtered
    assert "another" in filtered
    # The tags with namespaces attack, cve, tlp should be removed
    assert "attack.t1003" not in filtered
    assert "cve.CVE-2023-1234" not in filtered
    assert "tlp.red" not in filtered


def test_as_date_with_datetime_and_date():
    dt_obj = datetime(2023, 1, 1, 12, 0, 0)
    d_obj = date(2023, 1, 1)
    assert as_date(dt_obj) == d_obj
    assert as_date(d_obj) == d_obj
