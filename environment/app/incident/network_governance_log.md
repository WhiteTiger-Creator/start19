# Planning governance log

How the policy compiler is *meant* to behave -- the recovery of the truncated rule base, how an
object group resolves, which rule the device applies when more than one matches, what makes a rule
inert, what counts as shadowing and how the policy closes -- was settled incrementally by the
network change advisory board, and those decisions live in the review entries below, not in any
single summary. Several stages deliberately DEVIATE from the intuitive reading: object groups
resolve transitively rather than one level deep, the FIRST matching rule in sequence governs rather
than the most specific one, a shadowed rule is reported but never removed from the policy, a rule
whose object group resolves to no address at all is inert rather than a wildcard, and the closing
deny is emitted explicitly rather than left implied. The February draft proposals were revisited
during the 2026-05 controls review and several were reversed; where a draft or interim conflicts
with a later decision, the later dated decision governs. `/app/docs/policy_contract.json` is the
output contract only.


- 2026-02-24: Operations noted dropped configuration pushes from the object-group catalogue service in window 2007. Raised with the platform owner; the policy parameters were not touched.

- 2026-02-07: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2007. The push backlog was cleared with no change raised.

> **Recovery draft proposal (2026-02-07 - #NET-9020)** Rosa: rebuild the truncated rule base by concatenating the pre-migration snapshot with the configuration journal and keeping the last row seen for each rule; a restored rule is re-read from the snapshot *(Superseded -- reversed in the 2026-05 controls review.)*

- 2026-02-16: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2015. Session-table drift reviewed; no policy change requested.

- 2026-02-13: Change advisory stand-up recorded a routine note against the configuration push agent for window 2013. The push backlog was cleared with no change raised.

> **Recovery draft proposal (2026-02-14 - #NET-9026)** Anders: an object group's members are literal prefixes; a member naming another group is carried through to the device as written and is not expanded here *(Superseded -- reversed in the 2026-05 controls review.)*

- 2026-02-07: Controls review of the configuration push agent in window 2018 closed with no action; the standing thresholds were reconfirmed as they are.

> **Recovery draft proposal (2026-02-21 - #NET-9032)** Marek: where more than one rule matches a packet the device applies the MOST SPECIFIC of them, so a rule a broader earlier rule already covers is redundant and is removed from the compiled policy *(Superseded -- reversed in the 2026-05 controls review.)*

- 2026-02-01: Controls review of the policy orchestrator in window 2030 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-02-20: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2034. The push backlog was cleared with no change raised.

- 2026-02-27: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2036. The push backlog was cleared with no change raised.

- 2026-02-15: Operations noted dropped configuration pushes from the north-south inspection cluster in window 2025. Raised with the platform owner; the policy parameters were not touched.

- 2026-02-13: Duty network engineer logged a routine observation for the policy orchestrator during review window 2032. Session-table drift reviewed; no policy change requested.

- 2026-02-14: Operations noted dropped configuration pushes from the configuration push agent in window 2036. Raised with the platform owner; the policy parameters were not touched.

- 2026-02-06: Change advisory stand-up recorded a routine note against the configuration push agent for window 2027. The push backlog was cleared with no change raised.

- 2026-02-24: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2031. The push backlog was cleared with no change raised.

- 2026-02-07: Controls review of the edge firewall pair in window 2029 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-02-17: Change advisory stand-up recorded a routine note against the configuration push agent for window 2023. The push backlog was cleared with no change raised.

- 2026-02-26: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2025. The push backlog was cleared with no change raised.

- 2026-02-12: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2034. The push backlog was cleared with no change raised.

- 2026-02-25: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2035. The push backlog was cleared with no change raised.

- 2026-02-06: Operations noted dropped configuration pushes from the north-south inspection cluster in window 2031. Raised with the platform owner; the policy parameters were not touched.

- 2026-02-16: Controls review of the north-south inspection cluster in window 2024 closed with no action; the standing thresholds were reconfirmed as they are.

> **Interim decision (2026-03-06 - #NET-9038)** Priya: a rule whose object group resolves to no address is treated as an unrestricted wildcard on that side, an empty group placing no constraint on the match *(Revised -- see the 2026-05 controls review.)*

- 2026-03-24: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2047. The push backlog was cleared with no change raised.

- 2026-03-17: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2051. The push backlog was cleared with no change raised.

- 2026-03-11: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2054. The push backlog was cleared with no change raised.

- 2026-03-22: Operations noted dropped configuration pushes from the policy orchestrator in window 2053. Raised with the platform owner; the policy parameters were not touched.

- 2026-03-19: Duty network engineer logged a routine observation for the north-south inspection cluster during review window 2042. Session-table drift reviewed; no policy change requested.

- 2026-03-25: Operations noted dropped configuration pushes from the configuration push agent in window 2044. Raised with the platform owner; the policy parameters were not touched.

- 2026-03-17: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2056. The push backlog was cleared with no change raised.

- 2026-03-07: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2049. The push backlog was cleared with no change raised.

- 2026-03-13: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2041. The push backlog was cleared with no change raised.

- 2026-03-13: Operations noted dropped configuration pushes from the configuration push agent in window 2044. Raised with the platform owner; the policy parameters were not touched.

- 2026-03-06: Duty network engineer logged a routine observation for the edge firewall pair during review window 2045. Session-table drift reviewed; no policy change requested.

- 2026-03-12: Controls review of the north-south inspection cluster in window 2052 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-03-26: Operations noted dropped configuration pushes from the configuration push agent in window 2058. Raised with the platform owner; the policy parameters were not touched.

> **Interim decision (2026-03-12 - #NET-9044)** Anders: the closing deny is a property of the device and is left implied; the compiled policy carries only the operator's own rules *(Revised -- see the 2026-05 controls review.)*

- 2026-03-26: Operations noted dropped configuration pushes from the configuration push agent in window 2063. Raised with the platform owner; the policy parameters were not touched.

- 2026-03-11: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2072. Session-table drift reviewed; no policy change requested.

- 2026-03-13: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2077. The push backlog was cleared with no change raised.

- 2026-03-01: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2069. Session-table drift reviewed; no policy change requested.

- 2026-03-06: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2061. Session-table drift reviewed; no policy change requested.

- 2026-03-14: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2077. The push backlog was cleared with no change raised.

- 2026-03-07: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2070. Session-table drift reviewed; no policy change requested.

- 2026-03-17: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2067. The push backlog was cleared with no change raised.

- 2026-03-27: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2079. The push backlog was cleared with no change raised.

- 2026-03-17: Change advisory stand-up recorded a routine note against the configuration push agent for window 2070. The push backlog was cleared with no change raised.

- 2026-03-21: Duty network engineer logged a routine observation for the policy orchestrator during review window 2073. Session-table drift reviewed; no policy change requested.

- 2026-03-03: Operations noted dropped configuration pushes from the object-group catalogue service in window 2080. Raised with the platform owner; the policy parameters were not touched.

- 2026-03-17: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2075. The push backlog was cleared with no change raised.

- 2026-04-20: Controls review of the policy orchestrator in window 2111 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-04-16: Controls review of the configuration push agent in window 2086 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-04-21: Duty network engineer logged a routine observation for the north-south inspection cluster during review window 2110. Session-table drift reviewed; no policy change requested.

- 2026-04-01: Duty network engineer logged a routine observation for the north-south inspection cluster during review window 2098. Session-table drift reviewed; no policy change requested.

- 2026-04-13: Controls review of the object-group catalogue service in window 2114 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-04-04: Operations noted dropped configuration pushes from the policy orchestrator in window 2083. Raised with the platform owner; the policy parameters were not touched.

- 2026-04-19: Controls review of the object-group catalogue service in window 2112 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-04-15: Operations noted dropped configuration pushes from the object-group catalogue service in window 2119. Raised with the platform owner; the policy parameters were not touched.

- 2026-04-23: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2086. The push backlog was cleared with no change raised.

- 2026-04-05: Duty network engineer logged a routine observation for the configuration push agent during review window 2107. Session-table drift reviewed; no policy change requested.

- 2026-04-04: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2098. The push backlog was cleared with no change raised.

- 2026-04-04: Duty network engineer logged a routine observation for the policy orchestrator during review window 2084. Session-table drift reviewed; no policy change requested.

- 2026-04-09: Controls review of the object-group catalogue service in window 2120 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-04-18: Controls review of the policy orchestrator in window 2095 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-04-22: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2120. The push backlog was cleared with no change raised.

- 2026-04-26: Operations noted dropped configuration pushes from the north-south inspection cluster in window 2087. Raised with the platform owner; the policy parameters were not touched.

- 2026-04-25: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2118. The push backlog was cleared with no change raised.

- 2026-04-21: Controls review of the edge firewall pair in window 2083 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-04-24: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2103. The push backlog was cleared with no change raised.

- 2026-04-09: Change advisory stand-up recorded a routine note against the configuration push agent for window 2112. The push backlog was cleared with no change raised.

- 2026-04-08: Controls review of the edge firewall pair in window 2090 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-05-16: Duty network engineer logged a routine observation for the configuration push agent during review window 2124. Session-table drift reviewed; no policy change requested.

- 2026-05-07: Controls review of the configuration push agent in window 2123 closed with no action; the standing thresholds were reconfirmed as they are.

> **Governance decision (2026-05-04 - #NET-9150)** Priya: Input paths, final. The object-group catalogue and the firewall policy are always read from their fixed absolute paths under /app/data; `--input` selects the rule base only. Both `--input` and `--output-dir` keep their documented defaults.

> **Governance decision (2026-05-06 - #NET-9170)** Yusuf: Rule-base recovery, final (supersedes #NET-9020). Start from the pre-migration snapshot and replay the configuration journal in ascending `seq`, never in file order, keying each change on the rule it names. An `amend` overwrites the named field in place. A `retract` takes the rule out, but the migrator keeps it as it stood at that moment. A `restore` returns a retracted rule EXACTLY as it then stood: an amendment posted before the retraction survives, and one posted while it was out is lost. A change naming a rule the snapshot never carried is ignored.

> **Governance decision (2026-05-08 - #NET-9174)** Yusuf: Object-group resolution, final (supersedes #NET-9026; deviates from the literal-members reading). A group resolves to the set of prefixes reachable from it, expanding a member that names another group TRANSITIVELY rather than one level deep. Each group is entered once on a given resolution, so a catalogue that nests two groups into each other terminates instead of recurring. A member naming a group the catalogue does not carry contributes nothing. The resolved set is deduplicated and ordered ascending by network address, then by prefix length. A rule side written as a literal prefix resolves to that prefix alone.

> **Governance decision (2026-05-09 - #NET-9178)** Yusuf: Recovered shape, final. The rebuilt rule base is a JSON array ascending by sequence and then rule id, and each row carries the nine rule fields with both sides already resolved -- the migrator's bookkeeping (`seq`, `kind`, `posted_by`) never survives the replay.

> **Governance decision (2026-05-13 - #NET-9182)** Lena: Match order, final (supersedes #NET-9032; deviates from the most-specific reading). The device takes the FIRST rule in ascending sequence that matches a packet, whatever its prefix length. It follows that a rule an earlier rule already covers can never fire -- but it is REPORTED as shadowed and left where it stands. The compiled policy is the operator's rule base in sequence, not a minimised set, because removing a rule changes the sequence the operator reads back.

> **Governance decision (2026-05-16 - #NET-9186)** Marek: Shadowing, final. A rule is shadowed only where a SINGLE earlier live rule already matches every packet it matches: that rule's protocol is `any` or the same protocol, every one of its source prefixes sits inside one of that rule's source prefixes, the same holds of the destination, and its port range sits inside that rule's port range. The union of several earlier rules never establishes shadowing. Only the policy's max_shadow_lookback immediately preceding live rules are examined, and the first such rule found, scanning backwards, is the one recorded.

> **Governance decision (2026-05-19 - #NET-9190)** Marek: Inert rules, final (revises #NET-9038; deviates from the wildcard interim). A rule the operator left disabled, and a rule either side of which resolves to NO address at all, is inert: it never matches a packet and it never shadows a later rule. An empty object group is an empty set, not a wildcard. An inert rule leaves the compiled policy and is queued as `inert`.

> **Governance decision (2026-05-22 - #NET-9192)** Priya: Port handling, final. A port range is clamped to the policy's port_ceiling before any coverage question is asked of it, and a low port left above the clamped high is brought down to it.

> **Governance decision (2026-05-25 - #NET-9194)** Lena: Closing deny, final (revises #NET-9044; deviates from the implied reading). The compiled policy always ends with an explicit rule denying every protocol from every address to every address across the whole port range, carried at the policy's default_deny_sequence under the rule id FW-DEFAULT. It is emitted even where the cap has already been reached and it never counts against the cap.

> **Governance decision (2026-05-28 - #NET-9196)** Lena: Exception queue, final. The queue carries the inert rules and every rule the cap displaced, emitted by reason and then by rule id.

> **Governance decision (2026-05-30 - #NET-9198)** Yusuf: Policy size, final. The compiled policy is capped at the policy's max_rules, counted over the operator's own rules alone; the rules past the cap, taken in sequence order, leave the policy and are queued as `over_cap`. The shadowing verdict is settled BEFORE the cap is applied, so the reported shadowed count covers every live rule an earlier rule already matches, whether or not the cap keeps that rule in the policy.

- 2026-05-13: Duty network engineer logged a routine observation for the configuration push agent during review window 2140. Session-table drift reviewed; no policy change requested.

- 2026-05-12: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2148. The push backlog was cleared with no change raised.

- 2026-05-10: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2147. The push backlog was cleared with no change raised.

- 2026-05-12: Duty network engineer logged a routine observation for the edge firewall pair during review window 2159. Session-table drift reviewed; no policy change requested.

- 2026-05-11: Operations noted dropped configuration pushes from the north-south inspection cluster in window 2128. Raised with the platform owner; the policy parameters were not touched.

- 2026-05-21: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2150. The push backlog was cleared with no change raised.

- 2026-05-09: Operations noted dropped configuration pushes from the edge firewall pair in window 2132. Raised with the platform owner; the policy parameters were not touched.

- 2026-05-01: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2142. Session-table drift reviewed; no policy change requested.

- 2026-05-24: Controls review of the object-group catalogue service in window 2137 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-05-18: Operations noted dropped configuration pushes from the configuration push agent in window 2158. Raised with the platform owner; the policy parameters were not touched.

- 2026-05-14: Duty network engineer logged a routine observation for the north-south inspection cluster during review window 2150. Session-table drift reviewed; no policy change requested.

- 2026-05-11: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2128. The push backlog was cleared with no change raised.

- 2026-05-06: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2160. The push backlog was cleared with no change raised.

- 2026-05-20: Duty network engineer logged a routine observation for the north-south inspection cluster during review window 2136. Session-table drift reviewed; no policy change requested.

- 2026-05-21: Duty network engineer logged a routine observation for the policy orchestrator during review window 2138. Session-table drift reviewed; no policy change requested.

- 2026-05-25: Duty network engineer logged a routine observation for the configuration push agent during review window 2135. Session-table drift reviewed; no policy change requested.

- 2026-05-25: Operations noted dropped configuration pushes from the configuration push agent in window 2157. Raised with the platform owner; the policy parameters were not touched.

- 2026-06-18: Duty network engineer logged a routine observation for the policy orchestrator during review window 2164. Session-table drift reviewed; no policy change requested.

> **Governance decision (2026-06-02 - #NET-9210)** Priya: Firewall policy baseline, read from /app/data/firewall_policy.json at that fixed absolute path. Any field the policy file omits keeps its baseline: max_rules = 420; port_ceiling = 65535; max_shadow_lookback = 120; default_deny_sequence = 999000.

- 2026-06-26: Controls review of the configuration push agent in window 2180 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-06-15: Operations noted dropped configuration pushes from the object-group catalogue service in window 2182. Raised with the platform owner; the policy parameters were not touched.

- 2026-06-22: Operations noted dropped configuration pushes from the north-south inspection cluster in window 2187. Raised with the platform owner; the policy parameters were not touched.

- 2026-06-11: Controls review of the configuration push agent in window 2190 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-06-20: Controls review of the object-group catalogue service in window 2198 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-06-22: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2201. Session-table drift reviewed; no policy change requested.

- 2026-06-22: Operations noted dropped configuration pushes from the edge firewall pair in window 2200. Raised with the platform owner; the policy parameters were not touched.

- 2026-06-17: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2202. The push backlog was cleared with no change raised.

- 2026-06-23: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2210. The push backlog was cleared with no change raised.

- 2026-06-18: Change advisory stand-up recorded a routine note against the policy orchestrator for window 2205. The push backlog was cleared with no change raised.

- 2026-06-05: Operations noted dropped configuration pushes from the policy orchestrator in window 2192. Raised with the platform owner; the policy parameters were not touched.

- 2026-06-13: Duty network engineer logged a routine observation for the object-group catalogue service during review window 2168. Session-table drift reviewed; no policy change requested.

- 2026-06-04: Controls review of the configuration push agent in window 2187 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-06-21: Controls review of the policy orchestrator in window 2194 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-06-06: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2212. The push backlog was cleared with no change raised.

- 2026-06-10: Operations noted dropped configuration pushes from the edge firewall pair in window 2182. Raised with the platform owner; the policy parameters were not touched.

- 2026-06-06: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2193. The push backlog was cleared with no change raised.

- 2026-06-21: Controls review of the configuration push agent in window 2210 closed with no action; the standing thresholds were reconfirmed as they are.

- 2026-06-15: Change advisory stand-up recorded a routine note against the north-south inspection cluster for window 2211. The push backlog was cleared with no change raised.

- 2026-06-18: Change advisory stand-up recorded a routine note against the object-group catalogue service for window 2193. The push backlog was cleared with no change raised.

- 2026-06-01: Change advisory stand-up recorded a routine note against the edge firewall pair for window 2204. The push backlog was cleared with no change raised.

- 2026-06-01: Duty network engineer logged a routine observation for the north-south inspection cluster during review window 2185. Session-table drift reviewed; no policy change requested.

- 2026-06-01: Change advisory stand-up recorded a routine note against the configuration push agent for window 2190. The push backlog was cleared with no change raised.
