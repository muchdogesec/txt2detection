from unittest.mock import MagicMock

def make_fake_tactics(*tactic_name):
    return {k: dict(external_references=dict(external_id=tactic_name)) for k in tactic_name}
def test_map_technique_tactic():
    global_tactics = make_fake_tactics('initial-access', 'defense-evasion')
    rule_tactics = make_fake_tactics('defense-evasion', 'exfiltration')