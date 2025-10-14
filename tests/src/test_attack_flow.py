from functools import lru_cache
from types import SimpleNamespace
import pytest
from unittest.mock import MagicMock, patch
from stix2extensions._extensions import attack_flow_ExtensionDefinitionSMO

from txt2detection.ai_extractor.models import AttackFlowList, AttackFlowItem
from txt2detection.attack_flow import (
    create_navigator_layer,
    get_techniques_from_extracted_objects,
    parse_domain_flow,
    parse_flow,
    extract_attack_flow_and_navigator,
)
from stix2 import Report

from txt2detection.bundler import Bundler
from txt2detection.utils import parse_model


def test_parse_flow(dummy_report, dummy_objects, dummy_flow):
    tactics = get_all_tactics()
    techniques = get_techniques_from_extracted_objects(dummy_objects, tactics)
    flow = dummy_flow
    report = dummy_report
    expected_ids = {
        "attack-flow--57213643-98f5-5ca2-a12d-fbe5a97f54a2",
        "attack-action--62080947-214c-5c4b-8587-dc507659250d",
        "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
        "relationship--8f4e8003-25dc-51ef-8c5f-ab022d5ad458",
        "attack-action--57faf9fd-87e4-55a8-b1a8-9ba779ef16f7",
        "report--bc14a07a-5189-5f64-85c3-33161b923627",
        "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
        "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
        "attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf",
    }

    flow_objects = parse_flow(report, flow, techniques, tactics)
    assert {obj["id"] for obj in flow_objects} == expected_ids


def test_parse_flow__no_success(dummy_report):
    flow_objects = parse_flow(
        dummy_report,
        AttackFlowList(
            success=False,
            matrix="enterprise",
            items=[],
            tactic_selection=[],
        ),
        None,
        None,
    )
    assert len(flow_objects) == 0


@lru_cache
def get_all_tactics():
    return Bundler.get_attack_tactics()


def test_parse_domain_flow(dummy_report, dummy_objects, dummy_flow):
    tactics = get_all_tactics()
    techniques = get_techniques_from_extracted_objects(dummy_objects, tactics)
    flow = dummy_flow
    report = dummy_report
    flow_objects = parse_domain_flow(
        report, flow, techniques, tactics, "enterprise-attack"
    )
    assert {obj["id"] for obj in flow_objects} == {
        "attack-flow--57213643-98f5-5ca2-a12d-fbe5a97f54a2",
        "attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf",
        "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
        "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
        "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
        "attack-action--62080947-214c-5c4b-8587-dc507659250d",
        "attack-action--57faf9fd-87e4-55a8-b1a8-9ba779ef16f7",
        "relationship--8f4e8003-25dc-51ef-8c5f-ab022d5ad458",
    }


def test_get_techniques_from_extracted_objects(dummy_objects):
    tactics = get_all_tactics()
    techniques = get_techniques_from_extracted_objects(dummy_objects, tactics)
    stix_objects = [v.pop("stix_obj") for v in techniques.values()]
    assert dummy_objects == stix_objects
    print(techniques)
    assert techniques == {
        "T1190": {
            "domain": "enterprise-attack",
            "name": "Exploit Public-Facing Application",
            "possible_tactics": {"initial-access": "TA0001"},
            "id": "T1190",
            "platforms": [
                "Containers",
                "IaaS",
                "Linux",
                "Network Devices",
                "Windows",
                "macOS",
                "ESXi",
            ],
        },
        "T1547": {
            "domain": "enterprise-attack",
            "name": "Boot or Logon Autostart Execution",
            "possible_tactics": {
                "persistence": "TA0003",
                "privilege-escalation": "TA0004",
            },
            "id": "T1547",
            "platforms": ["Linux", "macOS", "Windows", "Network Devices"],
        },
    }


def test_extract_attack_flow_and_navigator(
    bundler_instance, dummy_objects, dummy_report
):
    bundler = MagicMock()
    bundler.report = dummy_report
    bundler.bundle.objects = dummy_objects
    ai_extractor = MagicMock()
    mock_extract_flow = ai_extractor.extract_attack_flow
    text = "My awesome text"

    tactics = get_all_tactics()
    techniques = get_techniques_from_extracted_objects(bundler.bundle.objects, tactics)
    bundler.get_attack_tactics.return_value = tactics

    with (
        patch("txt2detection.attack_flow.parse_flow") as mock_parse_flow,
        patch(
            "txt2detection.attack_flow.create_navigator_layer"
        ) as mock_create_navigator_layer,
    ):
        # ================= Both flow and navigator ===================
        flow, nav = extract_attack_flow_and_navigator(
            bundler, text, True, True, ai_extractor
        )
        assert bundler.flow_objects == mock_parse_flow.return_value
        assert (flow, nav) == (
            mock_extract_flow.return_value,
            mock_create_navigator_layer.return_value,
        )
        mock_parse_flow.assert_called_once_with(
            bundler.report, mock_extract_flow.return_value, techniques, tactics
        )
        mock_extract_flow.assert_called_once_with(text, techniques)

        mock_create_navigator_layer.assert_called_once_with(
            bundler.report,
            mock_extract_flow.return_value,
            techniques,
            tactics,
        )

        ### reset mocks
        mock_parse_flow.reset_mock()
        mock_create_navigator_layer.reset_mock()
        mock_extract_flow.reset_mock()

        # ================= only flow ===================
        flow, nav = extract_attack_flow_and_navigator(
            bundler, text, True, False, ai_extractor
        )
        assert bundler.flow_objects == mock_parse_flow.return_value
        assert (flow, nav) == (mock_extract_flow.return_value, None)
        mock_parse_flow.assert_called_once_with(
            bundler.report, mock_extract_flow.return_value, techniques, tactics
        )
        mock_extract_flow.assert_called_once_with(text, techniques)

        mock_create_navigator_layer.assert_not_called()

        ### reset mocks
        mock_parse_flow.reset_mock()
        mock_create_navigator_layer.reset_mock()
        mock_extract_flow.reset_mock()

        # ================= only navigator ===================
        flow, nav = extract_attack_flow_and_navigator(
            bundler, text, False, True, ai_extractor
        )
        assert bundler.flow_objects == mock_parse_flow.return_value
        mock_extract_flow.assert_called_once_with(text, techniques)
        assert (flow, nav) == (
            mock_extract_flow.return_value,
            mock_create_navigator_layer.return_value,
        )
        mock_parse_flow.assert_not_called()

        mock_create_navigator_layer.assert_called_once_with(
            bundler.report,
            mock_extract_flow.return_value,
            techniques,
            tactics,
        )

        ### reset mocks
        mock_parse_flow.reset_mock()
        mock_create_navigator_layer.reset_mock()
        mock_extract_flow.reset_mock()
        # ============ no technique object ============
        bundler.bundle.objects = []
        flow, nav = extract_attack_flow_and_navigator(
            bundler, text, True, True, ai_extractor
        )
        mock_extract_flow.assert_not_called()
        assert (flow, nav) == (None, None)
        mock_parse_flow.assert_not_called()

        mock_create_navigator_layer.assert_not_called()


def test_create_navigator_layer(dummy_report):
    summary = "this is a summary"
    flow = MagicMock()
    tactics_1 = {
        "TA01": "initial-access",
        "TA02": "lateral-movement",
        "TA03": "command-and-control",
    }
    tactics_2 = {
        "TA11": "initial-access",
        "TA12": "lateral-movement",
        "TA25": "command-and-control",
        "TA123": "persistence",
        "TA91": "exfiltration",
    }
    flow.items = [
        SimpleNamespace(
            attack_technique_id="T0001",
            attack_tactic_id="TA01",
            description="description 1",
        ),
        SimpleNamespace(
            attack_technique_id="T0003",
            attack_tactic_id="TA03",
            description="description 2",
        ),
        SimpleNamespace(
            attack_technique_id="T1001",
            attack_tactic_id="TA11",
            description="description 3",
        ),
        SimpleNamespace(
            attack_technique_id="T1002",
            attack_tactic_id="TA12",
            description="description 4",
        ),
        SimpleNamespace(
            attack_technique_id="T2001",
            attack_tactic_id="TA11",
            description="description 28jhsjhs",
        ),
        SimpleNamespace(
            attack_technique_id="T2003",
            attack_tactic_id="TA91",
            description="description sasa",
        ),
    ]
    techniques = {
        "T0001": dict(
            id="T0001", domain="enterprise-attack", possible_tactics=tactics_1
        ),
        "T0002": dict(
            id="T0002", domain="enterprise-attack", possible_tactics=tactics_1
        ),
        "T0003": dict(
            id="T0003", domain="enterprise-attack", possible_tactics=tactics_1
        ),
    }

    retval = create_navigator_layer(
        dummy_report,
        flow,
        techniques,
        tactics={"version": "16.1"},
    )
    assert len(retval) == 1
    print(retval)
    assert retval == [
        {
            "versions": {"layer": "4.5", "attack": "16.1", "navigator": "5.1.0"},
            "name": "fake python vulnerability report",
            "domain": "enterprise-attack",
            "techniques": [],
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
            "metadata": [
                {
                    "name": "report_id",
                    "value": "report--bc14a07a-5189-5f64-85c3-33161b923627",
                }
            ],
            "links": [
                {
                    "label": "Generated using txt2detection",
                    "url": "https://github.com/muchdogesec/txt2detection/",
                }
            ],
            "layout": {"layout": "side"},
        }
    ]


def test_create_navigator_layer__real_flow(dummy_report, dummy_flow, dummy_objects):
    tactics = get_all_tactics()
    techniques = get_techniques_from_extracted_objects(dummy_objects, tactics)
    tactics["version"] = "16.2"
    retval = create_navigator_layer(dummy_report, dummy_flow, techniques, tactics)
    assert len(retval) == 1
    assert retval == [
        {
            "versions": {"layer": "4.5", "attack": "16.2", "navigator": "5.1.0"},
            "name": "fake python vulnerability report",
            "domain": "enterprise-attack",
            "techniques": [
                {
                    "techniqueID": "T1190",
                    "tactic": "initial-access",
                    "score": 100,
                    "showSubtechniques": True,
                    "comment": "The adversary exploited a vulnerability in a public-facing application, identified as CVE-2024-56520, to gain initial access to the system.",
                },
                {
                    "techniqueID": "T1547",
                    "tactic": "persistence",
                    "score": 100,
                    "showSubtechniques": True,
                    "comment": "After gaining access, the adversary used boot or logon autostart execution techniques to maintain persistence on the compromised system.",
                },
            ],
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
            "metadata": [
                {
                    "name": "report_id",
                    "value": "report--bc14a07a-5189-5f64-85c3-33161b923627",
                }
            ],
            "links": [
                {
                    "label": "Generated using txt2detection",
                    "url": "https://github.com/muchdogesec/txt2detection/",
                }
            ],
            "layout": {"layout": "side"},
        }
    ]


@pytest.fixture
def dummy_objects():
    return [
        {
            "created": "2018-04-18T17:59:24.739Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.\n\nExploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).\n\nIf an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.\n\nAdversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)\n\nFor websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25)",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1190",
                    "external_id": "T1190",
                },
            ],
            "id": "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
            "modified": "2025-04-15T19:58:25.266Z",
            "name": "Exploit Public-Facing Application",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "revoked": False,
            "spec_version": "2.1",
            "type": "attack-pattern",
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_contributors": [
                "Yossi Weizman, Azure Defender Research Team",
                "Praetorian",
            ],
            "x_mitre_data_sources": [
                "Network Traffic: Network Traffic Content",
                "Application Log: Application Log Content",
            ],
            "x_mitre_deprecated": False,
            "x_mitre_detection": "Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection. Web Application Firewalls may detect improper inputs attempting exploitation.",
            "x_mitre_domains": ["enterprise-attack"],
            "x_mitre_is_subtechnique": False,
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_platforms": [
                "Containers",
                "IaaS",
                "Linux",
                "Network Devices",
                "Windows",
                "macOS",
                "ESXi",
            ],
            "x_mitre_version": "2.7",
        },
        {
            "created": "2020-01-23T17:46:59.535Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming) These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.\n\nSince some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1547",
                    "external_id": "T1547",
                }
            ],
            "id": "attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "privilege-escalation",
                },
            ],
            "modified": "2025-04-15T19:58:12.270Z",
            "name": "Boot or Logon Autostart Execution",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "revoked": False,
            "spec_version": "2.1",
            "type": "attack-pattern",
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_data_sources": [
                "Process: OS API Execution",
                "Module: Module Load",
                "Command: Command Execution",
                "File: File Creation",
                "Windows Registry: Windows Registry Key Creation",
                "Windows Registry: Windows Registry Key Modification",
                "File: File Modification",
                "Kernel: Kernel Module Load",
                "Process: Process Creation",
                "Driver: Driver Load",
            ],
            "x_mitre_deprecated": False,
            "x_mitre_detection": "Monitor for additions or modifications of mechanisms that could be used to trigger autostart execution, such as relevant additions to the Registry. Look for changes that are not correlated with known updates, patches, or other planned administrative activity. Tools such as Sysinternals Autoruns may also be used to detect system autostart configuration changes that could be attempts at persistence.(Citation: TechNet Autoruns)  Changes to some autostart configuration settings may happen under normal conditions when legitimate software is installed. \n\nSuspicious program execution as autostart programs may show up as outlier processes that have not been seen before when compared against historical data.To increase confidence of malicious activity, data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.\n\nMonitor DLL loads by processes, specifically looking for DLLs that are not recognized or not normally loaded into a process. Look for abnormal process behavior that may be due to a process loading a malicious DLL.\n\nMonitor for abnormal usage of utilities and command-line parameters involved in kernel modification or driver installation.",
            "x_mitre_domains": ["enterprise-attack"],
            "x_mitre_is_subtechnique": False,
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_platforms": ["Linux", "macOS", "Windows", "Network Devices"],
            "x_mitre_version": "1.3",
        },
    ]


@pytest.fixture
def dummy_report():
    return Report(
        **{
            "type": "report",
            "spec_version": "2.1",
            "id": "report--bc14a07a-5189-5f64-85c3-33161b923627",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2024-05-01T08:53:31.000Z",
            "modified": "2024-05-01T08:53:31.000Z",
            "name": "fake python vulnerability report",
            "description": "requirements.txt file that contains pypotr version 5.1.1. the version was uploaded by a state agent; Attack Technique used include T1547 and cve-2024-56520 and T1190; The attack takes control of dns 1.1.1.1 and domain-name google.com and goes to url https://datadome.net",
            "published": "2024-05-01T08:53:31Z",
            "object_refs": [
                "indicator--f2e55328-d20a-4637-ba55-394fc56121a4",
                "data-source--22684436-fab3-5847-b642-bcf23430e361",
            ],
            "labels": ["x1.we", "pop.aaa1"],
            "external_references": [
                {
                    "source_name": "description_md5_hash",
                    "external_id": "4b2ca609c2ae27843b251a761efb8cdf",
                },
                {
                    "source_name": "url",
                    "external_id": "https://example.com/pypotr-compromised",
                },
            ],
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            ],
        },
    )


@pytest.fixture
def dummy_flow():
    return AttackFlowList.model_validate(
        {
            "tactic_selection": [["T1190", "initial-access"], ["T1547", "persistence"]],
            "items": [
                {
                    "position": 0,
                    "attack_technique_id": "T1190",
                    "name": "Exploitation of Public-Facing Application",
                    "description": "The adversary exploited a vulnerability in a public-facing application, identified as CVE-2024-56520, to gain initial access to the system.",
                },
                {
                    "position": 1,
                    "attack_technique_id": "T1547",
                    "name": "Establishing Persistence via Boot or Logon Autostart",
                    "description": "After gaining access, the adversary used boot or logon autostart execution techniques to maintain persistence on the compromised system.",
                },
            ],
            "success": True,
        }
    )
