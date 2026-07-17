# Using KGCS in a SOC Investigation

A hands-on tutorial for SOC analysts — monitoring, vulnerability management, threat
intel, incident response — who already have Claude wired up to a local KGCS graph via
the [`kgcs-neo4j` MCP server](install-guide.md).

## Who this is for

You've followed the [installation guide](install-guide.md): Neo4j is running, the
graph is loaded (~6,007,052 nodes at spec v1.0.0), and Claude has the
`read_neo4j_cypher` and `get_neo4j_schema` tools connected. This tutorial doesn't
re-explain setup — it walks through the four moments a SOC analyst actually opens
KGCS during a shift, with the exact prompts and Cypher to use.

Every query below was run against the live graph before being written down. Sample
outputs are real, truncated for length.

## What KGCS is, in one paragraph

KGCS is a deterministic grounding layer, not a threat feed and not a copilot with
opinions. It stores the causal chain **CPE → CVE/CVSS → CWE → CAPEC → ATT&CK →
{D3FEND, CAR, SHIELD, ENGAGE}** as explicit graph edges, built from ten authoritative
standards (NVD, MITRE ATT&CK, CAPEC, CWE, D3FEND, CAR, SHIELD, ENGAGE, plus CPE/CVSS
scoring data). Every answer Claude gives you from this graph should show its hops.
If Claude can't name the hops, it's not a KGCS-grounded answer — push back on it.

Traversal can run in either direction along an existing edge (CVE → CWE or CWE → CVE
are both fine), but it never jumps a shortcut edge like CVE → Technique directly. If
you see an answer that skips CWE and CAPEC to connect a CVE straight to an ATT&CK
technique, that's not something the graph actually stores — ask for the real path.

## What KGCS does *not* know

This is the single most important thing to internalize before your first investigation:

KGCS holds the **global** knowledge layer — public, standards-based facts about
vulnerabilities, weaknesses, attack patterns, techniques, and defenses. It has never
seen your environment. It does not know:

- which assets you actually run (that's your CMDB / Nessus / EDR inventory)
- what fired in your SIEM last night (that's Splunk)
- what your SOAR already remediated (that's your case history)
- whether a given host is internet-facing, patched, or even real

Splunk, your SOAR, your EDR, and Nessus hold the **local** layer — what's true about
*your* estate, right now. KGCS answers "what does this ID mean and what does it imply"
questions; your tools answer "do I have this, where, and did it fire" questions.

**How to combine them, in practice:** pull the ID out of your local tool first (a
`cve_id` from a Nessus finding, an `attack_id` tag on an EDR/SIEM alert, a `cwe_id`
from a code scanner), then hand that ID to Claude with a KGCS-grounded prompt. The
sections below show exactly what that handoff looks like for each SOC role.

---

## 1. Alert triage (monitoring)

**Scenario.** Your EDR fires an alert tagged `T1053` (Scheduled Task/Job) — a host
created a scheduled task shortly after an interactive logon. Before you escalate, you
want to know: what detections *should* have caught earlier stages of this, what
mitigations are relevant, and whether there's a known vulnerability class behind it.

### 1.1 What tactics and detections does this technique belong to?

**Analyst question:** "My EDR tagged this alert T1053. What ATT&CK tactics is that
part of, and which CAR analytics and D3FEND techniques apply?"

**Prompt to Claude:**
> Using the kgcs-neo4j MCP tools, look up ATT&CK technique T1053: which tactics does
> it belong to (PART_OF → Tactic), which CAR analytics detect it (DETECTED_BY), and
> which D3FEND techniques mitigate it (MITIGATED_BY)? Cite every hop.

**Cypher:**
```cypher
MATCH (t:Technique {attackId: 'T1053'})
OPTIONAL MATCH (t)-[:PART_OF]->(tac:Tactic)
OPTIONAL MATCH (t)-[:DETECTED_BY]->(car:DetectionAnalytic)
OPTIONAL MATCH (t)-[:MITIGATED_BY]->(def:DefensiveTechnique)
RETURN t.attackId AS technique, t.name AS name,
       collect(DISTINCT tac.name) AS tactics,
       collect(DISTINCT car.analyticId + ' - ' + car.title) AS car_detections,
       collect(DISTINCT def.d3fendId + ' - ' + def.name) AS d3fend_mitigations
```

**Real output (truncated):**
```json
{
  "technique": "T1053", "name": "Scheduled Task/Job",
  "tactics": ["Execution", "Persistence", "Privilege Escalation"],
  "car_detections": [
    "CAR-2013-08-001 - Execution with schtasks",
    "CAR-2015-04-001 - Remotely Scheduled Tasks via AT",
    "CAR-2020-09-001 - Scheduled Task - FileAccess",
    "CAR-2021-12-001 - Scheduled Task Creation or Modification Containing Suspicious Scripts, Extensions or User Writable Paths"
    /* + 4 more */
  ],
  "d3fend_mitigations": [
    "D3-EAL - Executable Allowlisting", "D3-SJA - Scheduled Job Analysis",
    "D3-PSA - Process Spawn Analysis", "D3-SCF - System Call Filtering"
    /* + 12 more */
  ]
}
```

**Read this as:** T1053 spans three tactics (it's used for initial execution,
persistence, *and* privilege escalation — don't assume it's "just persistence").
CAR-2021-12-001 is your best single detection if you haven't deployed it yet; the
D3FEND set tells you which controls (allowlisting, scheduled-job analysis) actually
constrain this technique rather than just alert on it.

### 1.2 Is there a known vulnerability class behind this technique?

**Analyst question:** "Does any CWE/CAPEC pattern in the graph lead into T1053, so I
know what root cause to hunt for?"

**Prompt to Claude:**
> Using kgcs-neo4j, find any AttackPattern that IMPLEMENTS technique T1053, and trace
> back through DEMONSTRATED_BY to the Weakness (CWE). If nothing comes back, tell me
> plainly that the graph has no curated CAPEC link for this technique yet — don't
> guess one.

**Cypher:**
```cypher
MATCH (ap:AttackPattern)-[:IMPLEMENTS]->(t:Technique {attackId: 'T1053'})
RETURN ap.capecId, ap.name
```

**Real output:** `[]` — zero rows.

**Read this as:** this is a real, honest gap, not a query bug — verified by re-running
without the CWE hop too. KGCS v1.0's CAPEC↔ATT&CK coverage (`IMPLEMENTS`) currently
spans only 235 edges across 615 CAPEC patterns and 378 techniques, so a lot of
techniques — T1053 among them — have no curated backward path to a root-cause CWE yet.
**This is not "no vulnerability is behind this" — it's "the graph doesn't have that
link curated yet."** Treat an empty reverse-traversal result as a coverage gap you
note and move past, never as evidence of absence. For root-cause hunting on this
alert, fall back to your own EDR telemetry and CVE/patch history for the host.

---

## 2. Vulnerability management

**Scenario.** Nessus flags `CVE-2017-2616` on a Linux host. Raw CVSS is a
underwhelming 4.7 (MEDIUM) — on a severity-sorted list of a few hundred findings it
won't make your top page. You want to know what it actually opens up before you
deprioritize it.

### 2.1 Pull the CVSS scores

**Prompt to Claude:**
> Using kgcs-neo4j, get every CVSS score recorded for CVE-2017-2616 — don't merge
> versions, show each HAS_SCORE edge separately.

**Cypher:**
```cypher
MATCH (v:Vulnerability {cveId: 'CVE-2017-2616'})-[:HAS_SCORE]->(s:Score)
RETURN s.version, s.baseScore, s.baseSeverity, s.vectorString
```

**Real output:**
```json
[
  {"s.version": "2.0", "s.baseScore": 4.7, "s.baseSeverity": "", "s.vectorString": "AV:L/AC:M/Au:N/C:N/I:N/A:C"},
  {"s.version": "3.0", "s.baseScore": 4.7, "s.baseSeverity": "MEDIUM", "s.vectorString": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"}
]
```

Both scoring versions agree: 4.7, local attack vector, availability-only impact under
2.0 with an integrity vector switch under 3.0. Nothing here screams "urgent."

### 2.2 Walk the causal chain to see what it enables

**Prompt to Claude:**
> Using kgcs-neo4j, walk the full causal chain from CVE-2017-2616: CAUSED_BY to
> Weakness, DEMONSTRATED_BY to AttackPattern, IMPLEMENTS to Technique. Show every hop,
> don't skip any.

**Cypher:**
```cypher
MATCH (v:Vulnerability {cveId: 'CVE-2017-2616'})-[:CAUSED_BY]->(w:Weakness)
      -[:DEMONSTRATED_BY]->(ap:AttackPattern)-[:IMPLEMENTS]->(t:Technique)
RETURN w.cweId, w.name, ap.capecId, ap.name, t.attackId, t.name
```

**Real output (6 rows, truncated to the distinct techniques reached):**
```json
[
  {"w.cweId": "CWE-267", "w.name": "Privilege Defined With Unsafe Actions",
   "ap.capecId": "CAPEC-634", "ap.name": "Probe Audio and Video Peripherals",
   "t.attackId": "T1123", "t.name": "Audio Capture"},
  {"w.cweId": "CWE-267", "w.name": "Privilege Defined With Unsafe Actions",
   "ap.capecId": "CAPEC-637", "ap.name": "Collect Data from Clipboard",
   "t.attackId": "T1115", "t.name": "Clipboard Data"},
  {"w.cweId": "CWE-267", "w.name": "Privilege Defined With Unsafe Actions",
   "ap.capecId": "CAPEC-648", "ap.name": "Collect Data from Screen Capture",
   "t.attackId": "T1113", "t.name": "Screen Capture"}
  /* + Video Capture (T1125), Network Share Discovery (T1135), Screen Capture (T1513, mobile) */
]
```

**Read this as:** the low CVSS score is measuring exploit difficulty, not blast
radius. This single CWE-267 (unsafe privilege boundary) reaches six different
Collection/Discovery techniques — an attacker who lands this can capture screen,
clipboard, and audio, or enumerate network shares, all without further exploitation.
That's a materially different risk conversation than "4.7 MEDIUM, deprioritize."

### 2.3 Check the defensive picture — and don't assume coverage exists

**Prompt to Claude:**
> Using kgcs-neo4j, for technique T1113 (Screen Capture), what CAR analytics detect
> it and what D3FEND techniques mitigate it? If CAR is empty, say so explicitly.

**Cypher:**
```cypher
MATCH (t:Technique {attackId: 'T1113'})
OPTIONAL MATCH (t)-[:DETECTED_BY]->(car:DetectionAnalytic)
OPTIONAL MATCH (t)-[:MITIGATED_BY]->(def:DefensiveTechnique)
RETURN t.attackId, t.name, collect(DISTINCT car.analyticId) AS car_analytics,
       collect(DISTINCT def.d3fendId) AS d3fend
```

**Real output:**
```json
{"t.attackId": "T1113", "t.name": "Screen Capture", "car_analytics": [], "d3fend": ["D3-SCA", "D3-SCF"]}
```

**Read this as:** zero CAR analytics — MITRE hasn't published a detection analytic
for screen-capture behavior. You have D3FEND-level mitigation guidance (system-call
analysis and filtering) but no ready-made detection logic to deploy. That's the
actual finding to hand to your detection-engineering backlog: *"CWE-267 on this host
class reaches a technique with no published detection analytic — write one, or accept
the residual risk explicitly."* That's a stronger prioritization signal than the raw
CVSS number, and it's the kind of thing a CVSS-sorted list will never surface.

### 2.4 Gauge how common this root cause is

**Prompt to Claude:**
> Using kgcs-neo4j, how many CVEs in the graph share this same root-cause weakness,
> CWE-267?

**Cypher:**
```cypher
MATCH (w:Weakness {cweId: 'CWE-267'})<-[:CAUSED_BY]-(v:Vulnerability)
RETURN count(v) AS cvesWithThisCwe
```

**Real output:** `{"cvesWithThisCwe": 64}`

64 CVEs share this weakness class. If you're triaging a batch of Nessus findings,
grouping by CWE before sorting by CVSS surfaces patterns like this instead of treating
each finding as an isolated 4.7.

---

## 3. Threat intel enrichment

**Scenario.** A threat intel report names `T1021` (Remote Services) as part of a
campaign's lateral-movement TTPs. Before you brief the team, you want the full
sub-technique breakdown and the complete defensive counterpart set — what to watch
for, and what should already be stopping it.

### 3.1 Break the technique down into sub-techniques

**Prompt to Claude:**
> Using kgcs-neo4j, list every SubTechnique under ATT&CK technique T1021.

**Cypher:**
```cypher
MATCH (st:SubTechnique)-[:SUBTECHNIQUE_OF]->(t:Technique {attackId: 'T1021'})
RETURN st.attackId, st.name ORDER BY st.attackId
```

**Real output (8 rows):**
```json
[
  {"st.attackId": "T1021.001", "st.name": "Remote Desktop Protocol"},
  {"st.attackId": "T1021.002", "st.name": "SMB/Windows Admin Shares"},
  {"st.attackId": "T1021.003", "st.name": "Distributed Component Object Model"},
  {"st.attackId": "T1021.004", "st.name": "SSH"},
  {"st.attackId": "T1021.005", "st.name": "VNC"},
  {"st.attackId": "T1021.006", "st.name": "Windows Remote Management"},
  {"st.attackId": "T1021.007", "st.name": "Cloud Services"},
  {"st.attackId": "T1021.008", "st.name": "Direct Cloud VM Connections"}
]
```

If the intel report doesn't name a specific protocol, brief the team on all eight —
each needs a distinct detection story (RDP logon monitoring is not SSH key-use
monitoring).

### 3.2 Get the full defensive counterpart set for one sub-technique

**Prompt to Claude:**
> Using kgcs-neo4j, for sub-technique T1021.001 (RDP), what CAR analytics detect it
> and what D3FEND techniques mitigate it?

**Cypher:**
```cypher
MATCH (st:SubTechnique {attackId: 'T1021.001'})
OPTIONAL MATCH (st)-[:DETECTED_BY]->(car:DetectionAnalytic)
OPTIONAL MATCH (st)-[:MITIGATED_BY]->(def:DefensiveTechnique)
RETURN st.attackId, st.name,
       collect(DISTINCT car.title) AS car_detections,
       collect(DISTINCT def.name) AS d3fend_mitigations
```

**Real output:**
```json
{
  "st.attackId": "T1021.001", "st.name": "Remote Desktop Protocol",
  "car_detections": ["RDP Connection Detection", "User Login Activity Monitoring", "Remote Desktop Logon"],
  "d3fend_mitigations": [
    "Application Protocol Command Analysis", "Network Traffic Filtering",
    "Remote Terminal Session Detection", "Network Traffic Signature Analysis",
    "Client-server Payload Profiling", "Network Traffic Community Deviation",
    "Per Host Download-Upload Ratio Analysis", "Protocol Metadata Anomaly Detection",
    "User Geolocation Logon Pattern Analysis", "Session Termination"
  ]
}
```

**Read this as:** three named CAR analytics you can go check are actually deployed
in Splunk, and ten D3FEND mitigation classes to map against your existing controls
(NAC, segmentation, session monitoring) — this is the checklist for the intel brief,
not just the TTP name.

---

## 4. Incident response — a worked end-to-end case

**Scenario.** You're investigating unauthorized lateral movement into a segment
running BD Pyxis medication-management devices. Your EDR flagged `T1021` activity;
your vuln scanner separately flagged `CVE-2022-22767` on the same segment months ago
and it was never remediated. You want to know whether these are the same story.

### 4.1 Forward: does the CVE explain the alert?

**Prompt to Claude:**
> Using kgcs-neo4j, pull the CVSS scores for CVE-2022-22767, then walk CAUSED_BY →
> DEMONSTRATED_BY → IMPLEMENTS to see which ATT&CK technique it reaches.

**Cypher (scores):**
```cypher
MATCH (v:Vulnerability {cveId: 'CVE-2022-22767'})-[:HAS_SCORE]->(s:Score)
RETURN s.version, s.baseScore, s.baseSeverity, s.vectorString
```
```json
[
  {"s.version": "2.0", "s.baseScore": 8.3, "s.baseSeverity": "", "s.vectorString": "AV:A/AC:L/Au:N/C:C/I:C/A:C"},
  {"s.version": "3.1", "s.baseScore": 8.8, "s.baseSeverity": "HIGH", "s.vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
]
```

**Cypher (chain):**
```cypher
MATCH (v:Vulnerability {cveId: 'CVE-2022-22767'})-[:CAUSED_BY]->(w:Weakness)
      -[:DEMONSTRATED_BY]->(ap:AttackPattern)-[:IMPLEMENTS]->(t:Technique)
RETURN w.cweId, w.name, ap.capecId, ap.name, t.attackId, t.name
```
```json
{
  "w.cweId": "CWE-262", "w.name": "Not Using Password Aging",
  "ap.capecId": "CAPEC-555", "ap.name": "Remote Services with Stolen Credentials",
  "t.attackId": "T1021", "t.name": "Remote Services"
}
```

**Match confirmed.** CVE-2022-22767 (HIGH, 8.8) is a non-expiring-password weakness
(CWE-262) that the CAPEC library models exactly as "Remote Services with Stolen
Credentials" — and it lands on the same technique, T1021, your EDR already flagged.
The unremediated finding and the live alert are very plausibly the same root cause.

### 4.2 Confirm asset exposure

**Prompt to Claude:**
> Using kgcs-neo4j, which platforms does CVE-2022-22767 affect (AFFECTS →
> PlatformConfiguration → MATCHES_PLATFORM → Platform)?

**Cypher:**
```cypher
MATCH (v:Vulnerability {cveId: 'CVE-2022-22767'})-[:AFFECTS]->(pc:PlatformConfiguration)
      -[:MATCHES_PLATFORM]->(p:Platform)
RETURN DISTINCT p.vendor, p.product LIMIT 5
```
```json
[
  {"p.vendor": "bd", "p.product": "pyxis_anesthesia_station_es_firmware"},
  {"p.vendor": "bd", "p.product": "pyxis_ciisafe_firmware"},
  {"p.vendor": "bd", "p.product": "pyxis_logistics_firmware"},
  {"p.vendor": "bd", "p.product": "pyxis_medbank_firmware"},
  {"p.vendor": "bd", "p.product": "pyxis_medstation_4000_firmware"}
]
```

16 distinct platform entries in total (query with `count(DISTINCT p)` if you just
need the number). This confirms the CPE match is exactly your device class — cross-
check the affected model/firmware string against your asset inventory (local layer)
before you commit to the theory in your IR report.

### 4.3 Reverse: what should already be defending against this?

**Prompt to Claude:**
> Using kgcs-neo4j, for technique T1021, give me tactics, sub-techniques, CAR
> analytics, D3FEND techniques, SHIELD techniques, and ENGAGE concepts — the full
> defensive counterpart set.

**Cypher:**
```cypher
MATCH (t:Technique {attackId: 'T1021'})
OPTIONAL MATCH (t)-[dr:DETECTED_BY]->(car:DetectionAnalytic)
OPTIONAL MATCH (t)-[:MITIGATED_BY]->(d3:DefensiveTechnique)
OPTIONAL MATCH (t)-[:COUNTERED_BY]->(sh:DeceptionTechnique)
OPTIONAL MATCH (t)<-[:DISRUPTS]-(en:EngagementConcept)
OPTIONAL MATCH (t)-[:PART_OF]->(tac:Tactic)
RETURN t.attackId, t.name,
  collect(DISTINCT tac.name) AS tactics,
  collect(DISTINCT car.analyticId) AS car_analytics,
  collect(DISTINCT d3.d3fendId) AS d3fend,
  collect(DISTINCT sh.techniqueId) AS shield,
  collect(DISTINCT en.activityId) AS engage
```

**Real output (truncated):**
```json
{
  "t.attackId": "T1021", "t.name": "Remote Services",
  "tactics": ["Lateral Movement"],
  "car_analytics": ["CAR-2013-01-003", "CAR-2013-05-003", "CAR-2013-05-005",
                     "CAR-2013-07-002", "CAR-2014-11-004", "CAR-2016-04-005" /* + 5 more */],
  "d3fend": ["D3-APCA", "D3-NTF", "D3-RTSD", "D3-NTSA", "D3-CSPP" /* + 5 more */],
  "shield": ["DTE0017", "DTE0027"],
  "engage": ["EAC0002", "EAC0005", "EAC0006", "EAC0016"]
}
```

**Write this into the IR report as the "should have caught it" section:** 11 CAR
analytics existed for this technique before the incident (RDP connection detection,
SMB write monitoring, remote-PowerShell session tracking among them) — check your
Splunk deployment against that list as a post-incident gap analysis. SHIELD/ENGAGE
entries (`DTE0017` Decoy System, `EAC0002` Network Monitoring) are candidate deception
controls for the segment going forward, not things that failed this time — they're
option, not indictment.

### 4.4 Write the finding

At this point you have a fully cited chain for the IR report:

> CVE-2022-22767 (CVSS 3.1: 8.8 HIGH) → CWE-262 (Not Using Password Aging) →
> CAPEC-555 (Remote Services with Stolen Credentials) → T1021 (Remote Services,
> Lateral Movement) → matches the EDR-flagged technique. 16 BD Pyxis firmware builds
> match the vulnerable platform criteria. 11 CAR analytics and 10 D3FEND techniques
> exist for T1021 — confirm deployment status against Splunk/EDR configuration as a
> remediation action.

Every arrow in that sentence is a real graph edge you just queried — not an inference,
not a guess at what "probably" connects a HIGH CVE to a lateral-movement alert.

---

## Cheat sheet — copy-paste prompts by SOC role

Paste these directly to a Claude session with the `kgcs-neo4j` MCP server connected.
Replace the bracketed ID with the one from your alert/finding/report. Run
`get_neo4j_schema` once at the start of a session if you haven't recently — labels
and properties occasionally gain new standards as the pipeline is extended.

| Role | Prompt |
|---|---|
| Monitoring | "Using kgcs-neo4j, technique `[T####]` fired in my EDR — what tactics, CAR analytics, and D3FEND mitigations apply? Cite every hop." |
| Monitoring | "Using kgcs-neo4j, does any AttackPattern IMPLEMENTS technique `[T####]`? If not, tell me plainly there's no curated CAPEC link yet — don't invent one." |
| Vulnerability management | "Using kgcs-neo4j, walk CVE `[CVE-####-#####]` from CVSS score through CAUSED_BY → DEMONSTRATED_BY → IMPLEMENTS to every ATT&CK technique it reaches." |
| Vulnerability management | "Using kgcs-neo4j, for CWE `[CWE-###]`, how many CVEs share this root cause, and which ATT&CK techniques does it reach in total?" |
| Vulnerability management | "Using kgcs-neo4j, for technique `[T####]`, list CAR analytics and D3FEND techniques — and tell me explicitly if CAR coverage is empty." |
| Threat intel | "Using kgcs-neo4j, list every SubTechnique under `[T####]` with names." |
| Threat intel | "Using kgcs-neo4j, give me the full defensive counterpart set (CAR, D3FEND, SHIELD, ENGAGE) for `[T####.###]`." |
| Incident response | "Using kgcs-neo4j, does CVE `[CVE-####-#####]` and ATT&CK technique `[T####]` connect through the causal chain? Show the CWE and CAPEC hops explicitly." |
| Incident response | "Using kgcs-neo4j, which platforms (vendor/product) does CVE `[CVE-####-#####]` affect? I need to cross-check against our asset inventory." |
| Any role | "Using kgcs-neo4j, run get_neo4j_schema and tell me what's changed since the last time I checked — new labels, new relationship types." |

---

## Guardrails to keep in mind every time

- **Cite the hops.** Any KGCS-grounded answer should name the edges it walked
  (`CAUSED_BY`, `IMPLEMENTS`, `DETECTED_BY`, …). If Claude gives you a conclusion
  without the path, ask for the path.
- **No shortcut edges — ever.** There is no `CVE → Technique` edge in this graph
  and there never will be (ADR-level rule, not a current gap). Every connection goes
  through CWE and CAPEC. Reverse traversal along the real edges is fine; skipping a
  hop is not.
- **Empty ≠ safe.** A query returning zero rows (like §1.2 or the CAR set in §2.3)
  means the graph has no curated link *yet*, not that no risk exists. Say so
  explicitly in your findings rather than treating silence as reassurance.
- **KGCS is read-only, and it's the global layer.** It will never tell you if a
  technique fired in *your* environment or whether *your* host is patched — that's
  Splunk, your SOAR, your EDR, and Nessus. KGCS tells you what an ID means and what
  it causally implies; your tools tell you what's true on your network right now.
- **CVSS versions never merge.** If you see 2.0, 3.0/3.1, and 4.0 scores for the same
  CVE, report them separately — don't average or pick "the highest" without saying
  which version it's from.
