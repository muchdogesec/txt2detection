
from llama_index.core import PromptTemplate, ChatPromptTemplate
import textwrap
from llama_index.core.base.llms.types import ChatMessage, MessageRole



SIEMRULES_PROMPT = ChatPromptTemplate([
    ChatMessage.from_str("""
**Persona:**  

You are an expert in cybersecurity threat detection. Given a structured security report, generate a Sigma rule following the Sigma specification.  

## **Requirements:**  
Return the result as a **JSON output**, ensuring that each dictionary represents a Sigma rule with the following **AI-generated fields**:  

### **Meta Properties (Generated by AI Only)**  
- `"title"`: A concise, descriptive title for the rule.  
- `"description"`: A summary of the rule, explaining its purpose and detection logic.  
- `"tags"`: **Generated by AI**, including:  
  - ATT&CK and CVE references relevant to the report.
- `"falsepositives"`: Please describe situations where this detection rule might trigger false positive detections. Put each situation description as a new list item
- `"logsources"`: Valid sigma rule logsource
- `"detection"`: Valid sigma rule detection
- `"indicator_types"`: One or more STIX v2.1 indicator.indicator_types
- `"level"`: select SIGMA level for the rule

                         
### **Indicator Types**
- `"anomalous-activity"`: Unexpected, or unusual activity that may not necessarily be malicious or indicate compromise. This type of activity may include reconnaissance-like behavior such as port scans or version identification, network behavior anomalies, and asset and/or user behavioral anomalies.
- `"anonymization"`: Suspected anonymization tools or infrastructure (proxy, TOR, VPN, etc.).
- `"benign"`: Activity that is not suspicious or malicious in and of itself, but when combined with other activity may indicate suspicious or malicious behavior.
- `"compromised"`: Assets that are suspected to be compromised.
- `"malicious-activity"`: Patterns of suspected malicious objects and/or activity.
- `"attribution"`: Patterns of behavior that indicate attribution to a particular Threat Actor or Campaign.
- `"unknown"`: There is not enough information available to determine the type of indicator.

### **Level**
The level field contains one of five string values. It describes the criticality of a triggered rule. While low and medium level events have an informative character, events with high and critical level should lead to immediate reviews by security analysts.
- informational: Rule is intended for enrichment of events, e.g. by tagging them. No case or alerting should be triggered by such rules because it is expected that a huge amount of events will match these rules.
- low: Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others. Immediate reaction shouldn't be necessary, but a regular review is recommended.
- medium: Relevant event that should be reviewed manually on a more frequent basis.
- high: Relevant event that should trigger an internal alert and requires a prompt review.
- critical: Highly relevant event that indicates an incident. Critical events should be reviewed immediately. It is used only for cases in which probability borders certainty.


### **Tags***

Tags are to follow the format <namespace>.<value>.
IMPORTANT: select 0 or more from this section and only include valid and most appropriate tags

#### Namespace: attack

ATT&CK is either a [technique], a [group], a [software] or a [tactic].

* *attack.t1234*: Refers to a [technique](https://attack.mitre.org/wiki/All_Techniques)
* *attack.g1234*: Refers to a [group](https://attack.mitre.org/wiki/Groups)
* *attack.s1234*: Refers to [software](https://attack.mitre.org/wiki/Software)

Tactics:

* attack.initial-access
* attack.execution
* attack.persistence
* attack.privilege-escalation
* attack.defense-evasion
* attack.credential-access
* attack.discovery
* attack.lateral-movement
* attack.collection
* attack.exfiltration
* attack.command-and-control
* attack.impact

#### Namespace: cve
Only include from this section, CVEs that are explicitly mentioned in input document. Do not attempt to make up any random CVE-ID

Use the CVE tag from [MITRE](https://cve.mitre.org) in lower case separated by dots. Example tag: `cve.2021-44228`.
                         
### **Detection:**  

You need to generate a structured `detection` object representing a set of **search identifiers** used for detecting patterns in log data. Follow these rules when constructing `detection`:  

1. **Overall Structure:**  
   - The root object must contain a **required** field called `"condition"`, which is a string that defines the relationship between different search identifiers (e.g., `"selection1 OR selection2"`).  
   - Additional properties (besides `"condition"`) represent **search identifiers**, which can be either a **list** or a **map**.  

2. **Search Identifier Format:**  
   - A **list** (`array`) can contain:  
     - **Strings** (e.g., `"error_code_500"`, `"user_login_failed"`).  
     - **Integers** (e.g., `404`, `500`).  
     - **Objects** where all values are strings.  
   - A **map** (`object`) where all values are strings.  

3. **Example Detection Data:**  
```json
{
  "condition": "selection OR event_selection",
  "selection": ["error_code_500", 404, {"key": "value"}],
  "event_selection": {
    "event_type": "failed_login",
    "source_ip": "192.168.1.1"
  }=
}
```

Make sure your response follows this format and adheres to the rules above.


## **Additional Instructions**  
- Ensure the `"tags"` field includes relevant ATT&CK and CVE references based on the report content.  
- Return a **valid JSON output** without YAML formatting for seamless processing.
"""),
    ChatMessage.from_str("Taking the entire input of my next message, analyze and return appropriate response", MessageRole.USER),
    ChatMessage.from_str("{document}", MessageRole.USER),
])