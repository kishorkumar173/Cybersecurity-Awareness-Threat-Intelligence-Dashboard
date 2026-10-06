# Top 10 Cybersecurity Technical Interview Questions & Answers

### Q1: Can you explain your project and why you built it?
**Answer:**  
"I built the Cybersecurity Awareness & Threat Intelligence Dashboard to solve a fundamental disconnect in cybersecurity operations: technical threat intelligence and employee security awareness usually live in completely different silos. Modern SOCs suffer from alert fatigue because threat feeds are often flooded with stale or uncontextualized IOCs. At the same time, over 80% of breaches happen at the human layer through phishing or credential theft. 

My project unifies these two pillars. On the technical side, it collects, validates, enriches, and scores over 2,250 threat records across 10 security vectors, clustering repeated sightings to reduce SOC alert noise and mapping techniques to MITRE ATT&CK. On the human defense side, it converts active threat trends into 15 micro-learning modules and a 32-scenario interactive assessment that generates tailored remedial learning paths. Everything was designed purely for defensive security using RFC-compliant synthetic data with zero live external probing."

---

### Q2: What is the fundamental difference between Risk Score and Confidence Score in threat intelligence?
**Answer:**  
"Risk score represents the potential impact and urgency of an indicator or threat event—how severe it could be if authentic. Confidence score, on the other hand, measures our analytical certainty in the data—how reliable the reporting source is and how much corroborated evidence exists. 

For example, an unconfirmed tip from an anonymous forum about a remote code execution zero-day might have a Risk Score of 90, but a Confidence Score of 25 because the source is unverified. Conversely, an internal SOC sighting of a low-level adware beacon confirmed by multiple sensors might have a Risk Score of 30, but a Confidence Score of 95. Separating these two metrics prevents false escalations while ensuring high-risk possibilities aren't silently discarded."

---

### Q3: Why did you emphasize that 'an IOC match is not an automatic confirmed compromise'?
**Answer:**  
"Because Indicators of Compromise (like IP addresses, domains, or hashes) represent historical artifacts, not absolute proof of malicious intent. An IP address could belong to a shared content delivery network (CDN) or a cloud proxy that hosts thousands of legitimate websites alongside one malicious test page. Domains can expire and get re-registered by benign entities. An IOC match is merely an *observation*—it requires correlation with internal host telemetry, user context, and traffic behavior before an analyst can escalate it to a confirmed security incident."

---

### Q4: How does your system validate indicators, and why did you restrict IPs and domains to documentation ranges?
**Answer:**  
"I built a defensive IOC validation engine that strictly tests syntactic structure rather than attempting active network probing. It validates RFC 5737 IPv4 addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), RFC 3849 IPv6 addresses, FQDNs, URLs, cryptographic hashes (MD5, SHA-1, SHA-256), and CVE IDs using regular expressions and network parsing. 

I restricted all indicators to documentation ranges to adhere strictly to ethical defensive security standards. An analyst tool should never risk probing or weaponizing external infrastructure; indicators are analyzed solely as passive telemetry."

---

### Q5: How did you implement threat and alert correlation, and how does it combat SOC alert fatigue?
**Answer:**  
"Alert fatigue occurs when a SOC analyst is bombarded with hundreds of identical alerts for the same underlying activity—for example, a single workstation beaconing to an IP every 5 seconds generating 100 individual tickets. 

My correlation engine implements two layers:
1. **Threat Clustering:** It groups threat records sharing the same campaign ID or category within an observation window into a correlated threat cluster.
2. **Alert Deduplication:** It aggregates repeated sightings of the same indicator into a single consolidated alert ticket with an incrementing sighting counter (e.g., 1 alert with `observation_count = 100`). This preserves the full telemetry history while keeping the analyst triage queue manageable."

---

### Q6: How do you map indicators to the MITRE ATT&CK framework?
**Answer:**  
"An IOC tells us *what* artifact was observed (e.g., a specific domain), whereas MITRE ATT&CK describes *how* and *why* an adversary operates. In my platform, threat records are mapped to ATT&CK tactics (the adversary's objective, like Initial Access or Credential Access) and specific techniques (like T1566.002 Spearphishing Link or T1110.003 Password Spraying) only when there is sufficient behavioral context. If an indicator lacks contextual evidence, the system explicitly leaves it unmapped to prevent speculative or misleading analyst attribution."

---

### Q7: Why should CVSS scores not be the sole factor when prioritizing software vulnerabilities?
**Answer:**  
"CVSS provides an intrinsic measure of technical severity under hypothetical conditions, but it lacks operational context. A vulnerability with a Critical CVSS of 9.8 residing on an isolated, non-routable lab testing machine poses far lower immediate risk to the business than a High CVSS of 7.5 vulnerability sitting on an internet-facing production single sign-on (SSO) gateway with active public exploit scripts available. 

In my project, I built a contextual prioritization formula that weights CVSS by asset criticality, internet-facing exposure, and known exploitation telemetry to assign realistic remediation SLAs (such as 24-hour emergency patches vs. routine patch cycles)."

---

### Q8: What role does threat enrichment play, and how did you keep it safe in an offline environment?
**Answer:**  
"Enrichment adds critical context to raw indicators—such as first-seen and last-seen timestamps, historical sighting counts across internal logs, associated threat campaigns, and source reliability ratings. 

To keep the platform safe and functional without external API dependencies or outbound internet access, my enrichment engine queries our indexed local relational SQLite database. When an analyst searches an IP or hash, the system queries local telemetry to return aggregated sighting frequency and defensive triage actions without ever touching external networks."

---

### Q9: Can you explain the Tier-1 SOC analyst investigation workflow built into your dashboard?
**Answer:**  
"When a high-risk indicator is detected, the workflow follows a structured triage path:
1. **Queue Review:** The analyst identifies prioritized alerts in the SOC queue.
2. **Dossier Inspection:** The analyst opens the Threat Detail view to review the normalized indicator, confidence score, and associated MITRE ATT&CK techniques.
3. **Passive Context Verification:** The analyst checks internal telemetry and correlation clusters to see if other endpoints have reported sightings.
4. **Action & Documentation:** The analyst updates the threat status (Monitoring, Closed, or False Positive), appends an investigation note with technical justification, and flags relevant awareness topics if human deception was involved."

---

### Q10: How does the awareness scoring and quiz system integrate back into enterprise security operations?
**Answer:**  
"The awareness quiz tests users across 32 realistic enterprise scenarios covering 10 threat vectors like phishing, MFA fatigue, and safe browsing. Rather than serving as a punitive score, the engine computes a granular percentage breakdown per risk category. 

If an employee or department scores low on Phishing (e.g., 40%) but high on Passwords (90%), the system automatically generates targeted micro-learning recommendations for the Phishing module. This creates a data-driven feedback loop where the SOC's real-world intelligence directly informs and reinforces continuous employee defense."
