# KGCS Across the Lifecycle of a Major Security Incident

A hands-on tutorial for a SOC incident response team — monitoring, vulnerability
management, threat intel, and IR — who already have Claude wired up to a local KGCS
graph via the [`kgcs-neo4j` MCP server](install-guide.md).

## Who this is for and how it differs from the SOC tutorial

You've followed the [installation guide](install-guide.md): Neo4j is running, the
graph is loaded, and Claude has the `read_neo4j_cypher` and `get_neo4j_schema` tools
connected. The [SOC investigation tutorial](soc-investigation-tutorial.md) walks
through four independent moments — triage, vuln management, threat intel, IR — each
with its own scenario. This tutorial instead follows **one severe incident, start to
finish**, through every phase of [NIST SP 800-61](https://csrc.nist.gov/pubs/sp/800/61/r2/final):
Preparation, Detection & Analysis, Containment, Eradication, Recovery, and
Post-Incident Activity. At each phase you'll see what KGCS answers, who on the team
asks it, and — just as important — where KGCS hands off to Splunk, Nessus, the SOAR,
or the EDR because the answer lives in your environment, not in a public standard.

Every query below was run against the live graph before being written down. Sample
outputs are real, truncated for length. Where a query returns nothing or a partial
result, that's reported as-is — an empty result in KGCS means "not curated yet," never
"safe."

## The causal chain, briefly

KGCS stores **CPE → CVE/CVSS → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE}**
as explicit graph edges. Traversal can run in either direction along a real edge, but
it never jumps a shortcut edge — there is no `CVE → Technique` edge in this graph, and
there never will be. Every answer below cites the hops it walked. If you want the full
explanation of what KGCS does and doesn't know, read the
[SOC tutorial's framing section](soc-investigation-tutorial.md#what-kgcs-does-not-know)
first — it isn't repeated here.

---

## The incident, at a glance

**Organization (fictional):** Meridian CaseWorks, a mid-size SaaS vendor. Its
customer-facing case-management portal (`case.meridianworks.example`) is a Java
backend that embeds **Apache Log4j 2.14.1** for application logging.

**Anchor vulnerability:** `CVE-2021-44228` ("Log4Shell") — CVSS v3.1 **10.0 CRITICAL**,
one of the most widely exploited vulnerabilities in recent history, confirmed in the
graph to affect the `apache:log4j` platform across the `2.13.0`–`<2.15.0` version
range (2.14.1 is inside it). This narrative mirrors the well-documented real-world
pattern from December 2021: attackers used Log4Shell for unauthenticated remote code
execution on internet-facing services, then pivoted to data theft or ransomware
deployment. Timeline below is relative (T-minus / Day N), not calendar dates, since
the graph is a point-in-time snapshot rather than a Dec-2021 archive.

| When | What happens |
|---|---|
| T-14d | Preparation: routine platform-inventory sweep flags `apache:log4j` in the estate |
| Day 0 | Detection & Analysis: EDR/Splunk tags an alert `T1027` on the portal host |
| Day 0 (+2h) | Containment: portal segment isolated pending confirmation |
| Day 1 | Eradication: patch scope expanded from one CVE to the full sibling set |
| Day 3 | Recovery: verification checklist run before reconnecting the segment |
| Day 10 | Post-Incident: lessons-learned review and final report |

**Roles referenced:** IR lead, SOC analyst (monitoring), vulnerability management,
threat intel.

---

## Phase 1 — Preparation

**Who asks:** vulnerability management, working from the platform inventory Nessus
already confirmed (`apache:log4j`, version `2.14.1`, on the customer portal).

### 1.1 Which vulnerabilities affect our logging library, ranked by severity?

**Question:** "We run Apache Log4j on the portal. What known CVEs affect it, and
which ones are the most severe?"

**Prompt to Claude:**
> Using kgcs-neo4j, find every CVE that AFFECTS the platform apache:log4j, and rank
> by CVSS v3 base score. Show the CWE(s) each one is CAUSED_BY.

**Cypher:**
```cypher
MATCH (p:Platform {vendor:'apache', product:'log4j'})<-[:MATCHES_PLATFORM]-(pc:PlatformConfiguration)<-[:AFFECTS]-(v:Vulnerability)
WITH DISTINCT v
OPTIONAL MATCH (v)-[:CAUSED_BY]->(w:Weakness)
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score) WHERE s.version STARTS WITH '3'
RETURN v.cveId AS cve, collect(DISTINCT w.cweId) AS cwes, max(s.baseScore) AS cvss3
ORDER BY cvss3 DESC
LIMIT 8
```

**Real output:**
```json
[
  {"cve": "CVE-2021-44228", "cwes": ["CWE-20", "CWE-400", "CWE-502", "CWE-917"], "cvss3": 10.0},
  {"cve": "CVE-2017-5645",  "cwes": ["CWE-502"], "cvss3": 9.8},
  {"cve": "CVE-2019-17571", "cwes": ["CWE-502"], "cvss3": 9.8},
  {"cve": "CVE-2022-23305", "cwes": ["CWE-89"],  "cvss3": 9.8},
  {"cve": "CVE-2020-9493",  "cwes": ["CWE-502"], "cvss3": 9.8},
  {"cve": "CVE-2021-45046", "cwes": ["CWE-917"], "cvss3": 9.0},
  {"cve": "CVE-2022-23302", "cwes": ["CWE-502"], "cvss3": 8.8},
  {"cve": "CVE-2022-23307", "cwes": ["CWE-502"], "cvss3": 8.8}
]
```

**Read this as:** `CVE-2021-44228` tops the list at a rare perfect 10.0, and it's the
only one with four distinct root weaknesses attached — a broader blast radius than a
single-CWE CVE. Note `CVE-2021-45046` sitting at 9.0 two rows down, sharing `CWE-917`
with the top hit: that pairing becomes important later (see Eradication, §4.2). This
is a prioritization list, not a patching order by itself — cross-check each CVE's
version range against your installed `2.14.1` build in Nessus before committing a
patch schedule.

### 1.2 What does the top CVE actually enable, before it's exploited?

**Question:** "For the CRITICAL one, walk the full causal chain forward — what ATT&CK
techniques could this CVE ultimately enable? We want to build detections ahead of
time, not after."

**Prompt to Claude:**
> Using kgcs-neo4j, walk CVE-2021-44228 CAUSED_BY → Weakness, DEMONSTRATED_BY →
> AttackPattern, IMPLEMENTS → Technique. Show every hop and every distinct technique
> reached, don't skip any.

**Cypher:**
```cypher
MATCH (v:Vulnerability {cveId:'CVE-2021-44228'})-[:CAUSED_BY]->(w:Weakness)
      -[:DEMONSTRATED_BY]->(ap:AttackPattern)-[:IMPLEMENTS]->(t:Technique)
RETURN w.cweId, w.name, ap.capecId, ap.name, t.attackId, t.name
ORDER BY w.cweId, ap.capecId
```

**Real output (6 rows):**
```json
[
  {"cweId": "CWE-20", "name": "Improper Input Validation", "capecId": "CAPEC-13",  "capecName": "Subverting Environment Variable Values", "attackId": "T1574", "techName": "Hijack Execution Flow"},
  {"cweId": "CWE-20", "name": "Improper Input Validation", "capecId": "CAPEC-267", "capecName": "Leverage Alternate Encoding",              "attackId": "T1027", "techName": "Obfuscated Files or Information"},
  {"cweId": "CWE-20", "name": "Improper Input Validation", "capecId": "CAPEC-31",  "capecName": "Accessing/Intercepting/Modifying HTTP Cookies", "attackId": "T1539", "techName": "Steal Web Session Cookie"},
  {"cweId": "CWE-20", "name": "Improper Input Validation", "capecId": "CAPEC-473", "capecName": "Signature Spoof", "attackId": "T1036", "techName": "Masquerading"},
  {"cweId": "CWE-20", "name": "Improper Input Validation", "capecId": "CAPEC-473", "capecName": "Signature Spoof", "attackId": "T1553", "techName": "Subvert Trust Controls"},
  {"cweId": "CWE-400", "name": "Uncontrolled Resource Consumption", "capecId": "CAPEC-227", "capecName": "Sustained Client Engagement", "attackId": "T1499", "techName": "Endpoint Denial of Service"}
]
```

**Read this as:** a single library CVE reaches six techniques across (per the graph's
`Tactic` nodes) five tactic groupings: Execution, Stealth, Credential Access, Defense
Impairment, and Impact. Only `CWE-20` and `CWE-400` reach a curated technique here —
`CWE-502` and `CWE-917`, also attached to this CVE, don't reach one yet (see §1.3 and
§4.2). Note: tactic labels are exactly what the graph's `Tactic.name` property
returns (via `PART_OF`) — they may not always match the exact wording you remember
from the public ATT&CK matrix; if that surprises you, re-run `get_neo4j_schema` and
trust the live value over memory.

### 1.3 What's already covered, and what's a known gap?

**Question:** "For each of those six techniques, what detections and mitigations
already exist? We want to know what to deploy now versus accept as an open risk."

**Prompt to Claude:**
> Using kgcs-neo4j, for techniques T1574, T1027, T1539, T1036, T1553, T1499, get
> tactics (PART_OF), CAR analytics (DETECTED_BY), and D3FEND techniques
> (MITIGATED_BY). Tell me explicitly which ones have zero coverage.

**Cypher:**
```cypher
UNWIND ['T1574','T1027','T1539','T1036','T1553','T1499'] AS tid
MATCH (t:Technique {attackId: tid})
OPTIONAL MATCH (t)-[:PART_OF]->(tac:Tactic)
OPTIONAL MATCH (t)-[:DETECTED_BY]->(car:DetectionAnalytic)
OPTIONAL MATCH (t)-[:MITIGATED_BY]->(def:DefensiveTechnique)
RETURN t.attackId AS technique, t.name AS name,
       collect(DISTINCT tac.name) AS tactics,
       count(DISTINCT car) AS carCount,
       count(DISTINCT def) AS d3fendCount
ORDER BY technique
```

**Real output:**
```json
[
  {"technique": "T1027", "name": "Obfuscated Files or Information", "tactics": ["Stealth"],            "carCount": 0, "d3fendCount": 0},
  {"technique": "T1036", "name": "Masquerading",                    "tactics": ["Stealth"],            "carCount": 3, "d3fendCount": 0},
  {"technique": "T1499", "name": "Endpoint Denial of Service",      "tactics": ["Impact"],              "carCount": 0, "d3fendCount": 0},
  {"technique": "T1539", "name": "Steal Web Session Cookie",        "tactics": ["Credential Access"],   "carCount": 0, "d3fendCount": 9},
  {"technique": "T1553", "name": "Subvert Trust Controls",          "tactics": ["Defense Impairment"],  "carCount": 1, "d3fendCount": 0},
  {"technique": "T1574", "name": "Hijack Execution Flow",           "tactics": ["Execution", "Stealth"],"carCount": 7, "d3fendCount": 0}
]
```

**Read this as:** this is the pre-incident gap analysis, and it's a genuinely uneven
picture — **no single technique in this set has both CAR and D3FEND coverage.**
`T1539` has nine D3FEND mitigation classes but zero CAR analytics; `T1574` has seven
CAR analytics but zero D3FEND entries. `T1027` and `T1499` have **neither** — flag
those explicitly to the detection-engineering backlog now, before the incident, not
after. In this narrative, Meridian's SOC accepts the `T1027`/`T1499` gap and instead
relies on a WAF rule for encoded JNDI payload strings — a compensating control that
lives outside KGCS entirely (local layer).

---

## Phase 2 — Detection & Analysis

**Who asks:** the on-shift SOC analyst, validating a hypothesis hop by hop before
escalating.

**Scenario.** Day 0: the EDR on the portal host reports a Java process making an
unexpected outbound LDAP connection, immediately preceded by an HTTP request
containing an obfuscated/encoded string in a header value. The correlation rule in
the SOAR auto-tags the alert `T1027`.

### 2.1 What does this technique tag actually mean, and what could cause it?

**Question:** "The alert is tagged T1027. Which attack patterns implement it, and
which weaknesses do they exploit?"

**Prompt to Claude:**
> Using kgcs-neo4j, find every AttackPattern that IMPLEMENTS technique T1027, and for
> each one, which Weakness DEMONSTRATED_BY points to it.

**Cypher:**
```cypher
MATCH (ap:AttackPattern)-[:IMPLEMENTS]->(t:Technique {attackId:'T1027'})
OPTIONAL MATCH (w:Weakness)-[:DEMONSTRATED_BY]->(ap)
RETURN ap.capecId AS capec, ap.name AS name, collect(DISTINCT w.cweId) AS cwes
```

**Real output (8 rows):**
```json
[
  {"capec": "CAPEC-19",  "name": "Embedding Scripts within Scripts",                "cwes": ["CWE-284"]},
  {"capec": "CAPEC-267", "name": "Leverage Alternate Encoding",                     "cwes": ["CWE-172","CWE-173","CWE-180","CWE-181","CWE-20","CWE-692","CWE-697","CWE-73","CWE-74"]},
  {"capec": "CAPEC-35",  "name": "Leverage Executable Code in Non-Executable Files","cwes": ["CWE-270","CWE-272","CWE-282","CWE-59","CWE-94","CWE-95","CWE-96","CWE-97"]},
  {"capec": "CAPEC-448", "name": "Embed Virus into DLL",                            "cwes": ["CWE-506"]},
  {"capec": "CAPEC-542", "name": "Targeted Malware",                                "cwes": []},
  {"capec": "CAPEC-572", "name": "Artificially Inflate File Sizes",                 "cwes": []},
  {"capec": "CAPEC-636", "name": "Hiding Malicious Data or Code within Files",      "cwes": ["CWE-506"]},
  {"capec": "CAPEC-655", "name": "Avoid Security Tool Identification by Adding Data","cwes": []}
]
```

**Read this as:** eight attack patterns can produce a `T1027` tag; the encoding
behavior the EDR saw (an obfuscated string inside an HTTP header) fits `CAPEC-267`
("Leverage Alternate Encoding") best, which traces back to `CWE-20` (Improper Input
Validation) among others. That's the thread to pull next.

### 2.2 Does one of our own CVEs actually sit on that exact path?

**Question:** "Do we have a CVE on our own platform, apache:log4j, that's CAUSED_BY
CWE-20 and reaches CAPEC-267 → T1027 — the exact chain we just walked?"

**Prompt to Claude:**
> Using kgcs-neo4j, find every Vulnerability CAUSED_BY CWE-20, DEMONSTRATED_BY
> CAPEC-267, IMPLEMENTS T1027, that also AFFECTS the apache:log4j platform.

**Cypher:**
```cypher
MATCH (v:Vulnerability)-[:CAUSED_BY]->(w:Weakness {cweId:'CWE-20'})
      -[:DEMONSTRATED_BY]->(ap:AttackPattern {capecId:'CAPEC-267'})
      -[:IMPLEMENTS]->(t:Technique {attackId:'T1027'})
MATCH (v)-[:AFFECTS]->(:PlatformConfiguration)-[:MATCHES_PLATFORM]->(p:Platform {vendor:'apache', product:'log4j'})
RETURN DISTINCT v.cveId AS cve
```

**Real output:**
```json
[{"cve": "CVE-2021-44228"}, {"cve": "CVE-2021-45105"}, {"cve": "CVE-2021-44832"}]
```

**Read this as:** three candidates, not one — the graph is honest about ambiguity
rather than collapsing to a single answer. Disambiguate with CVSS and version range
(both local-layer-adjacent facts, but already in the graph): `CVE-2021-44228` is
CVSS 10.0 and its version range covers `2.14.1`; `CVE-2021-45105` (5.9) and
`CVE-2021-44832` (6.6) also technically cover `2.14.1` but are far less severe and,
for `CVE-2021-44832`, require a non-default JNDI configuration. The analyst treats
`CVE-2021-44228` as the primary hypothesis and keeps the other two open for the
Eradication phase rather than discarding them.

### 2.3 Given this CVE, what tactics should we expect next?

**Question:** "If this really is CVE-2021-44228, what's the attacker likely to do
after obfuscation/evasion — what other tactics does this CVE's causal chain reach?"

This reuses the six-row chain already walked in §1.2 — the analyst doesn't need a new
query, just to re-read it with a live incident in mind. Three tactics beyond the
observed `T1027` (Stealth) are reachable from this same CVE: `T1574` (Execution /
Stealth — persistence via execution-flow hijack), `T1539` (Credential Access — session
cookie theft), and `T1499` (Impact — endpoint denial of service). **Read this as:** an
availability-impacting event (`T1499`, Impact tactic) is on this CVE's reachable set —
that's a signal to raise the incident's severity and loop in the IR lead now, not a
claim that ransomware is confirmed. KGCS tells you what's structurally possible from
this root cause; only your EDR/SOAR telemetry can tell you what's actually happening.

---

## Phase 3 — Containment

**Who asks:** the IR lead, deciding isolation scope and whether active engagement
(deception) is on the table.

### 3.1 What's the scope of isolation?

**Question:** "Which platforms does the confirmed CVE affect? We need to know how far
to draw the containment boundary."

**Prompt to Claude:**
> Using kgcs-neo4j, which platforms (vendor/product) does CVE-2021-44228 affect via
> AFFECTS → PlatformConfiguration → MATCHES_PLATFORM → Platform? Give me the total
> count and a sample.

**Cypher:**
```cypher
MATCH (v:Vulnerability {cveId:'CVE-2021-44228'})-[:AFFECTS]->(pc:PlatformConfiguration)
      -[:MATCHES_PLATFORM]->(p:Platform)
RETURN DISTINCT p.vendor, p.product
ORDER BY p.vendor, p.product
LIMIT 8
```
```cypher
MATCH (v:Vulnerability {cveId:'CVE-2021-44228'})-[:AFFECTS]->(pc:PlatformConfiguration)
      -[:MATCHES_PLATFORM]->(p:Platform)
RETURN count(DISTINCT p) AS totalPlatforms
```

**Real output:**
```json
[
  {"vendor": "apache", "product": "log4j"},
  {"vendor": "apple",  "product": "xcode"},
  {"vendor": "cisco",  "product": "automated_subsea_tuning"},
  {"vendor": "cisco",  "product": "broadworks"},
  {"vendor": "cisco",  "product": "business_process_automation"}
  /* ... */
]
```
```json
{"totalPlatforms": 1796}
```

**Read this as:** 1,796 distinct platform entries carry this CVE globally — that's
the public blast radius, not Meridian's. **Handoff to the local layer:** cross-check
this platform list (or just `apache:log4j`) against Nessus/CMDB to get the actual
in-scope host list; KGCS confirms the CVE *can* affect a given product family, it
doesn't know which of your hosts run it. For Meridian, the containment boundary is
the customer-portal segment running the `apache:log4j 2.14.1` build — confirmed
in-range by the platform-configuration data pulled in §1.1/§4.1.

### 3.2 What disrupts the techniques we're seeing, right now?

**Question:** "For the techniques in play — T1027, T1574, T1539, T1553, T1499 —
what D3FEND techniques would actively disrupt them, and are SHIELD/ENGAGE deception
options realistic here?"

**Prompt to Claude:**
> Using kgcs-neo4j, for T1027, T1574, T1539, T1553, T1499, give me MITIGATED_BY
> (D3FEND), COUNTERED_BY (SHIELD), and reverse DISRUPTS (ENGAGE).

**Cypher:**
```cypher
UNWIND ['T1027','T1574','T1539','T1553','T1499'] AS tid
MATCH (t:Technique {attackId: tid})
OPTIONAL MATCH (t)-[:MITIGATED_BY]->(def:DefensiveTechnique)
OPTIONAL MATCH (t)-[:COUNTERED_BY]->(sh:DeceptionTechnique)
OPTIONAL MATCH (t)<-[:DISRUPTS]-(en:EngagementConcept)
RETURN t.attackId AS technique,
       collect(DISTINCT def.d3fendId + ' - ' + def.name) AS d3fend,
       collect(DISTINCT sh.techniqueId + ' - ' + sh.name) AS shield,
       collect(DISTINCT en.activityId + ' - ' + en.name) AS engage
```

**Real output (condensed):**
```json
[
  {"technique": "T1027", "d3fend": [], "shield": ["DTE0017 - Decoy System"], "engage": ["EAC0005 - Lures","EAC0013 - Malware Detonation","EAC0014 - Software Manipulation","EAC0015 - Information Manipulation"]},
  {"technique": "T1499", "d3fend": [], "shield": ["DTE0026 - Network Manipulation","DTE0032 - Security Controls"], "engage": ["EAC0007 - Network Diversity","EAC0016 - Network Manipulation"]},
  {"technique": "T1539", "d3fend": ["D3-CH - Credential Hardening","D3-RIC - Reissue Credential","D3-DUC - Decoy User Credential","D3-ANCI - Authentication Cache Invalidation","D3-CTS - Credential Transmission Scoping","D3-CR - Credential Revocation","D3-CCSA - Credential Compromise Scope Analysis","D3-CRO - Credential Rotation","D3-MFA - Multi-factor Authentication"], "shield": ["DTE0008 - Burn-In","DTE0032 - Security Controls"], "engage": ["EAC0005 - Lures","EAC0018 - Security Controls"]},
  {"technique": "T1553", "d3fend": [], "shield": ["DTE0003 - API Monitoring","DTE0032 - Security Controls"], "engage": ["EAC0001 - API Monitoring","EAC0006 - Application Diversity","EAC0018 - Security Controls"]},
  {"technique": "T1574", "d3fend": [], "shield": ["DTE0032 - Security Controls"], "engage": ["EAC0018 - Security Controls"]}
]
```

**Read this as:** `T1539` is the one technique here with real D3FEND teeth — since the
alert chain reaches session-cookie theft, the IR lead's immediate containment action
is credential revocation and reissue (`D3-CR`, `D3-RIC`) for any session active on the
portal during the exposure window, not just network isolation. For the rest
(`T1027`, `T1499`, `T1553`, `T1574`), D3FEND is empty — containment there falls back to
network-layer isolation (local layer, not KGCS). `DTE0017` (Decoy System) is a
plausible SHIELD option if Meridian's IR playbook allows active deception on this
segment; that's a policy decision, not something KGCS can make for you.

---

## Phase 4 — Eradication

**Who asks:** vulnerability management, expanding the patch scope from "the CVE the
alert pointed to" to "everything sharing its root cause."

### 4.1 Root cause thread 1: CWE-20 (Improper Input Validation)

**Question:** "CVE-2021-44228 is CAUSED_BY CWE-20 among others. What other CVEs share
CWE-20 on the same platform? We don't want to patch one CVE and leave siblings open."

**Prompt to Claude:**
> Using kgcs-neo4j, find every CVE CAUSED_BY CWE-20 that also affects apache:log4j,
> with CVSS v2 and v3 scores shown separately.

**Cypher:**
```cypher
MATCH (w:Weakness {cweId:'CWE-20'})<-[:CAUSED_BY]-(v:Vulnerability)
      -[:AFFECTS]->(:PlatformConfiguration)-[:MATCHES_PLATFORM]->(p:Platform {vendor:'apache', product:'log4j'})
WITH DISTINCT v
MATCH (v)-[:HAS_SCORE]->(s:Score)
RETURN v.cveId AS cve, s.version, s.baseScore, s.baseSeverity
ORDER BY cve, s.version
```

**Real output:**
```json
[
  {"cve": "CVE-2021-44228", "version": "2.0", "baseScore": 9.3,  "baseSeverity": ""},
  {"cve": "CVE-2021-44228", "version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL"},
  {"cve": "CVE-2021-44832", "version": "2.0", "baseScore": 8.5,  "baseSeverity": ""},
  {"cve": "CVE-2021-44832", "version": "3.1", "baseScore": 6.6,  "baseSeverity": "MEDIUM"},
  {"cve": "CVE-2021-45105", "version": "2.0", "baseScore": 4.3,  "baseSeverity": ""},
  {"cve": "CVE-2021-45105", "version": "3.1", "baseScore": 5.9,  "baseSeverity": "MEDIUM"}
]
```

**Read this as:** the same three CVEs surfaced by the hop-by-hop analysis in §2.2 —
confirmed independently here via the root-cause weakness rather than the technique
path. `CVE-2021-44832` and `CVE-2021-45105` score much lower under CVSS v3
(6.6 / 5.9) than v2 (8.5 / 4.3) — **report both, don't average them or pick the
"worse" one**; the version drop for `44832` reflects the CVSS v3.1 vector requiring
high privileges (`PR:H`), a real mitigating factor v2 didn't model. All three are in
scope for this patch cycle.

### 4.2 Root cause thread 2: CWE-917 (Expression Language Injection) — and an honest gap

**Question:** "Separately, what else shares CWE-917, the JNDI/expression-injection
root cause specific to Log4Shell?"

**Prompt to Claude:**
> Using kgcs-neo4j, find every CVE CAUSED_BY CWE-917 that affects apache:log4j. Then
> check whether CWE-917 has any DEMONSTRATED_BY link to a CAPEC pattern — if not,
> say so plainly.

**Cypher:**
```cypher
MATCH (w:Weakness {cweId:'CWE-917'})<-[:CAUSED_BY]-(v:Vulnerability)
      -[:AFFECTS]->(:PlatformConfiguration)-[:MATCHES_PLATFORM]->(p:Platform {vendor:'apache', product:'log4j'})
WITH DISTINCT v
OPTIONAL MATCH (v)-[:HAS_SCORE]->(s:Score) WHERE s.version STARTS WITH '3'
RETURN v.cveId AS cve, max(s.baseScore) AS cvss3
ORDER BY cvss3 DESC
```
```cypher
MATCH (w:Weakness {cweId:'CWE-917'})
OPTIONAL MATCH (w)-[:DEMONSTRATED_BY]->(ap:AttackPattern)
RETURN w.name, collect(ap.capecId) AS capecs
```

**Real output:**
```json
[
  {"cve": "CVE-2021-44228", "cvss3": 10.0},
  {"cve": "CVE-2021-45046", "cvss3": 9.0}
]
```
```json
{"name": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')", "capecs": []}
```

**Read this as:** exactly two CVEs on this platform share the JNDI-injection root
cause — the one the alert pointed to, and `CVE-2021-45046` (9.0, published as an
"incomplete fix" follow-up in the real Log4Shell timeline). **Patch scope for
eradication is five CVEs total, not one:** `CVE-2021-44228`, `CVE-2021-45046`,
`CVE-2021-44832`, `CVE-2021-45105`, plus verifying the fixed version (`≥2.17.1` per
the graph's version-range data) closes all of them. Separately: `CWE-917` itself has
**zero** `DEMONSTRATED_BY` edges — no CAPEC pattern is curated for it yet in this
graph. That's a coverage gap to note in the report, not evidence that expression-
language injection has no further attack-pattern consequences; it means KGCS v1.0
hasn't curated that link yet.

---

## Phase 5 — Recovery

**Who asks:** the IR lead, building the go/no-go checklist before reconnecting the
portal segment.

### 5.1 What should already be verified before we reconnect?

**Question:** "Before we bring the portal segment back online, what detections should
we confirm are active, and what mitigations should we confirm are deployed?"

This reuses the coverage data already gathered in §1.3 and §3.2 — Recovery is where it
becomes a checklist rather than a warning:

| Technique | CAR analytics to confirm active | D3FEND to confirm deployed |
|---|---|---|
| T1027 (Obfuscated Files/Info) | *none exist — verify the WAF encoded-payload rule instead* | *none exist* |
| T1036 (Masquerading) | CAR-2013-05-002, CAR-2013-05-009, CAR-2021-04-001 | *none exist* |
| T1499 (Endpoint DoS) | *none exist* | *none exist* |
| T1539 (Steal Web Session Cookie) | *none exist — verify session-monitoring compensating control* | D3-CH, D3-RIC, D3-DUC, D3-ANCI, D3-CTS, D3-CR, D3-CCSA, D3-CRO, D3-MFA |
| T1553 (Subvert Trust Controls) | CAR-2021-05-001 | *none exist* |
| T1574 (Hijack Execution Flow) | CAR-2013-01-002, CAR-2013-03-001, CAR-2013-04-002, CAR-2014-02-001, CAR-2014-07-001, CAR-2020-05-003, CAR-2021-11-001 | *none exist* |

**Read this as:** the go/no-go gate isn't "did we patch" — it's "did we confirm the
detections and mitigations that *do* exist are actually deployed in Splunk/EDR, and
did we document a compensating control for every cell marked *none exist*." Meridian's
recovery checklist: confirm all seven `T1574` CAR analytics are enabled in Splunk,
confirm the nine `T1539` D3FEND controls are live (session/credential rotation
already forced in Containment, §3.2), and confirm the WAF rule covering the `T1027`
gap is still active before lifting isolation. This entire checklist traces back to
graph queries — nothing here is invented policy.

---

## Phase 6 — Post-Incident Activity

**Who asks:** the IR lead (final report) and threat intel (lessons learned / backlog).

### 6.1 What coverage gaps did this incident expose?

Pulling directly from §1.3, §3.2, and §4.2: `T1027` and `T1499` had zero CAR and zero
D3FEND coverage *before* the incident, and still do — those go into the
detection-engineering backlog as concrete, graph-verified findings, not vague
"improve monitoring" action items. `CWE-917`, the specific root cause behind both
`CVE-2021-44228` and `CVE-2021-45046`, has no curated CAPEC link — flagged for the
KGCS maintainers as a genuine spec gap (open an issue against `kgcs-spec`, don't patch
around it locally; per the project's causal-chain rules, shortcut edges are never an
acceptable fix).

### 6.2 The traceable chain for the final report

Every clause below is a real edge queried during this incident — no inference, no
guessed connections:

> `CVE-2021-44228` (CVSS 3.1: 10.0 CRITICAL) `CAUSED_BY` `CWE-20` (Improper Input
> Validation) `DEMONSTRATED_BY` `CAPEC-267` (Leverage Alternate Encoding)
> `IMPLEMENTS` `T1027` (Obfuscated Files or Information) — matching the EDR-tagged
> alert. The same CVE also reaches `T1574`, `T1539`, `T1036`, `T1553` (via `CWE-20`)
> and `T1499` (via `CWE-400`). Separately, `CVE-2021-44228` and `CVE-2021-45046`
> (CVSS 3.1: 9.0) share root cause `CWE-917` (Expression Language Injection) — no
> curated CAPEC link exists for this weakness in KGCS v1.0. Both CVEs, plus siblings
> `CVE-2021-44832` and `CVE-2021-45105` (also `CAUSED_BY` `CWE-20`), affect the
> `apache:log4j` platform in the version range covering the deployed `2.14.1` build.
> Containment used `T1539`'s nine `D3FEND` mitigations (credential/session
> revocation); recovery verified `T1574`'s seven `CAR` analytics and `T1553`'s one
> `CAR` analytic before reconnecting the segment.

---

## Appendix

### A. Causal-chain map (the actual hops traversed this incident)

```
CVE-2021-44228 (CVSS 3.1: 10.0 CRITICAL)
 ├─ CAUSED_BY → CWE-20  (Improper Input Validation)
 │    ├─ DEMONSTRATED_BY → CAPEC-13  → IMPLEMENTS → T1574 (Hijack Execution Flow)      [Execution, Stealth]
 │    ├─ DEMONSTRATED_BY → CAPEC-267 → IMPLEMENTS → T1027 (Obfuscated Files/Info)      [Stealth]   ← EDR alert
 │    ├─ DEMONSTRATED_BY → CAPEC-31  → IMPLEMENTS → T1539 (Steal Web Session Cookie)   [Credential Access]
 │    └─ DEMONSTRATED_BY → CAPEC-473 → IMPLEMENTS → T1036 (Masquerading)               [Stealth]
 │                                   → IMPLEMENTS → T1553 (Subvert Trust Controls)     [Defense Impairment]
 ├─ CAUSED_BY → CWE-400 (Uncontrolled Resource Consumption)
 │    └─ DEMONSTRATED_BY → CAPEC-227 → IMPLEMENTS → T1499 (Endpoint DoS)               [Impact]
 ├─ CAUSED_BY → CWE-502 (Deserialization of Untrusted Data)   [no IMPLEMENTS yet — gap]
 └─ CAUSED_BY → CWE-917 (Expression Language Injection)       [no DEMONSTRATED_BY yet — gap]
      └─ shared with CVE-2021-45046 (CVSS 3.1: 9.0) — same root cause, same platform

Sibling CVEs on apache:log4j via CWE-20: CVE-2021-44832 (6.6), CVE-2021-45105 (5.9)

Platform: apache:log4j, versions 2.13.0–<2.15.0 (covers deployed 2.14.1)
  AFFECTS → PlatformConfiguration → MATCHES_PLATFORM → Platform (1,796 platform
  entries globally for CVE-2021-44228 alone)

Containment: T1539 → MITIGATED_BY → 9 D3FEND techniques (D3-CH, D3-RIC, D3-DUC, ...)
Recovery:    T1574 → DETECTED_BY  → 7 CAR analytics; T1553 → DETECTED_BY → 1 CAR analytic
```

### B. Phase-by-phase prompt cheat sheet

| Phase | Role | Prompt |
|---|---|---|
| Preparation | Vuln mgmt | "Using kgcs-neo4j, which CVEs AFFECT platform `[vendor:product]`, ranked by CVSS v3? Show CAUSED_BY weaknesses for each." |
| Preparation | Vuln mgmt | "Using kgcs-neo4j, walk CVE `[CVE-####-#####]` CAUSED_BY → DEMONSTRATED_BY → IMPLEMENTS to every technique it reaches — don't skip hops." |
| Preparation | IR lead | "Using kgcs-neo4j, for techniques `[T####, ...]`, give tactics, CAR analytics, and D3FEND techniques. Tell me explicitly which have zero coverage." |
| Detection & Analysis | Analyst | "Using kgcs-neo4j, my alert is tagged `[T####]`. Which AttackPatterns IMPLEMENT it, and which Weakness does each DEMONSTRATED_BY point to?" |
| Detection & Analysis | Analyst | "Using kgcs-neo4j, find any Vulnerability CAUSED_BY `[CWE-###]`, DEMONSTRATED_BY `[CAPEC-###]`, IMPLEMENTS `[T####]`, that also AFFECTS platform `[vendor:product]`." |
| Containment | IR lead | "Using kgcs-neo4j, which platforms does CVE `[CVE-####-#####]` affect (AFFECTS → MATCHES_PLATFORM)? Give total count and a sample." |
| Containment | IR lead | "Using kgcs-neo4j, for techniques `[T####, ...]`, give MITIGATED_BY (D3FEND), COUNTERED_BY (SHIELD), and reverse DISRUPTS (ENGAGE)." |
| Eradication | Vuln mgmt | "Using kgcs-neo4j, find every CVE CAUSED_BY `[CWE-###]` that also AFFECTS platform `[vendor:product]`, with CVSS v2 and v3 shown separately." |
| Eradication | Vuln mgmt | "Using kgcs-neo4j, does `[CWE-###]` have any DEMONSTRATED_BY link to a CAPEC pattern? If not, say so plainly — don't infer one." |
| Recovery | IR lead | "Using kgcs-neo4j, for techniques `[T####, ...]` from this incident, list CAR analytics and D3FEND techniques as a verification checklist — mark any with zero of either explicitly." |
| Post-Incident | IR lead / threat intel | "Using kgcs-neo4j, summarize the full causal chain traversed this incident — every CVE, CWE, CAPEC, Technique, and defensive-layer hop — for the final report." |

---

## Guardrails to keep in mind every time

- **Cite the hops, every time.** Every finding in this tutorial names the edges
  walked. If Claude gives you a conclusion without the path, ask for the path.
- **No shortcut edges — ever.** There is no `CVE → Technique` edge in this graph.
  Every connection goes through `CWE` and `CAPEC`.
- **Empty ≠ safe.** `CWE-917` having no `DEMONSTRATED_BY` link, or `T1027`/`T1499`
  having zero `CAR`/`D3FEND` coverage, means "not curated yet" — treat it as a gap to
  close, never as reassurance.
- **CVSS versions never merge.** Report v2, v3, and v4 scores separately, as this
  tutorial did throughout — don't average or silently pick "the highest."
- **KGCS is the global layer, read-only.** It never tells you which of your hosts
  are exposed, what fired in Splunk, or what your SOAR already did — that's the
  handoff this tutorial showed at every phase.

For the four independent, shorter scenarios this tutorial builds on, see the
[SOC investigation tutorial](soc-investigation-tutorial.md). For setup, see the
[installation guide](install-guide.md).
