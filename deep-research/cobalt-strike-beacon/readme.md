Initial prompt:
`Role: Seasoned threat hunter, detection engineer, and cybersecurity analyst Task: Perform deep research to identify Cobalt Strike beacons in EDR and Web Proxy data. Prioritize You are a prompt engineer. Optimize this prompt for OpenAI Deep Research to get the most comprehensive, accurate, and well-structured results: "Role: seasoned threat hunter, detection engineer, and cybersecurity analyst Task: Perform deep research to identify Cobalt Strike beacons in EDR and Web Proxy data. Prioritize data within the last 12 months and from reputable vendors, industry reports, and academic papers."`

Response:
`Role:
You are a seasoned threat hunter, detection engineer, and cybersecurity analyst with deep expertise in endpoint detection (EDR), network telemetry, and web proxy logs (e.g., Zscaler, Secure Web Gateway).


Objective:
Conduct comprehensive, multi-source deep research to identify how Cobalt Strike Beacon activity can be detected across:
1. Endpoint Detection & Response (EDR) telemetry
2. Web proxy / network traffic logs (HTTP, HTTPS, DNS)


Scope & Priorities:
- Prioritize sources from the last 12 months (2025–present)
- Focus on high-quality sources:
  - Security vendors (e.g., Mandiant, Microsoft, CrowdStrike, Palo Alto, Elastic, Vectra)
  - Threat intelligence reports
  - Incident response case studies
  - Academic research papers
  - Open-source detection engineering content (Sigma, YARA, GitHub, blogs from reputable researchers)
- Include real-world adversary usage (APT + ransomware groups)


Research Requirements:
1. Cobalt Strike Beacon Tradecraft
   - Modern beacon behaviors (HTTP/S, DNS, SMB, named pipes)
   - Malleable C2 profiles and evasion techniques (jitter, sleep, domain fronting, protocol mimicry)
   - Fileless execution and in-memory techniques (e.g., reflective DLL injection) :contentReference[oaicite:0]{index=0}
   - Post-exploitation behaviors (lateral movement, credential access, persistence)


2. Detection Opportunities (EDR Focus)
   - Process injection, process hollowing, and parent-child anomalies
   - Suspicious use of LOLBins (powershell.exe, rundll32.exe, wmic, etc.)
   - Memory artifacts and reflective loading patterns
   - Named pipe usage patterns associated with Beacon
   - Command-line anomalies and low-frequency behaviors (LFO / long-tail)
   - Behavioral vs signature-based detection approaches


3. Detection Opportunities (Web Proxy / Network Focus)
   - Beaconing patterns (interval + jitter analysis)
   - HTTP/S anomalies:
     - User-agent inconsistencies
     - URI patterns and metadata anomalies
     - Abnormal header structures
   - TLS fingerprinting (JA3/JA4), certificate anomalies
   - DNS anomalies (DGA-like behavior, unusual responses)
   - Long-tail / rare domain analysis
   - Detection of C2 over legitimate platforms (e.g., cloud/CDN abuse)


4. Correlation Across Data Sources
   - Techniques that combine EDR + proxy telemetry for stronger detection
   - Mapping endpoint activity to outbound C2 traffic
   - Multi-signal detection strategies (behavioral chaining)


5. Detection Engineering Artifacts
   - Example Sigma rules, YARA rules, or detection logic
   - Sample queries (KQL, Splunk SPL, SQL, Elastic, or generic pseudocode)
   - Heuristics that can be operationalized in SIEM/XDR
   - Detection gaps and false positive considerations


6. Evasion Techniques & Countermeasures
   - How attackers modify Beacon configs to evade detection :contentReference[oaicite:1]{index=1}
   - Domain fronting, encrypted C2, protocol blending
   - Defensive strategies to overcome these evasions


7. Emerging Trends
   - Shift to alternate C2 frameworks (e.g., Sliver, Havoc) and impact on detection :contentReference[oaicite:2]{index=2}
   - Use of AI/ML in detection pipelines
   - Changes in attacker tradecraft post-2024 law enforcement disruption


Output Format:


Provide a structured report with the following sections:


1. Executive Summary (concise, actionable insights)
2. Cobalt Strike Beacon Tradecraft Overview
3. EDR Detection Techniques (with examples)
4. Web Proxy / Network Detection Techniques (with examples)
5. Cross-Telemetry Correlation Strategies
6. Detection Engineering Playbook
   - Queries
   - Rules
   - Heuristics
7. Evasion Techniques vs Detection Countermeasures
8. Key Takeaways for Threat Hunters
9. References (clearly cited, categorized by source type)


Style Guidelines:
- Be highly technical but clear and structured
- Avoid generic explanations—focus on actionable detection insights
- Prefer real-world examples over theory
- Highlight “what actually works in practice” vs “theoretical detection”
`
