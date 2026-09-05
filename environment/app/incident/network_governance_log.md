# Planning governance log

How the policy compiler is *meant* to behave -- the recovery of the truncated rule base, how an object group resolves, which rule the device applies when more than one matches, what makes a rule inert, what counts as shadowing and how the policy closes -- was settled incrementally by the network change advisory board, and those decisions live in the review entries below, not in any single summary. Where two entries speak to the same stage, the later dated decision governs. `/app/docs/policy_contract.json` is the output contract only.
The duty engineer closed a housekeeping item on the nightly config export. The nightly integrity sweep over the rule base completed clean. The item was closed at the same meeting.
The change board tidied a stale link in the operator runbook. A segment owner's contact record was refreshed at their own request. The desk signed it off with no change to any published figure.
The service-desk lead recorded a maintenance note against the management host. An out-of-office reply bounced a notification back into the queue.


- 2026-02-24: The firewall desk answered a query about a prior change window. The published change calendar was reissued with the freeze dates corrected. The thread was archived and nothing was carried forward.

- 2026-02-07: The documentation owner signed off the week's rule-base sampling with nothing outstanding. One field arrived null where the collector normally sends an empty string. The owner acknowledged it at the weekly slot.

> **Board minute (2026-02-07 - #NET-9020)** Rosa: rebuild the truncated rule base by concatenating the pre-migration snapshot with the configuration journal and keeping the last row seen for each rule; a restored rule is re-read from the snapshot.

- 2026-02-16: An on-call engineer summarised a call with the appliance vendor. One segment reported a rule fewer than the week before, all of it expected.

- 2026-02-13: The capacity planner revisited a control the auditors had asked about. Two tickets covering the same request were merged. It was noted for the record.

> **Board minute (2026-02-14 - #NET-9026)** Anders: an object group's members are literal prefixes; a member naming another group is carried through to the device as written and is not expanded here.

- 2026-02-07: The platform team logged a correction request from a segment owner. A failover rehearsal completed inside its window with nothing to note. It was filed with no parameter change.

> **Board minute (2026-02-21 - #NET-9032)** Marek: where more than one rule matches a packet the device applies the MOST SPECIFIC of them, so a rule a broader earlier rule already covers is redundant and is removed from the compiled policy.

- 2026-02-01: The escalation desk wrote up an overnight page that had cleared itself. The rule count sat a little above the running mean, entirely from a backfill.

- 2026-02-20: The audit lead carried a minor point forward to the next shift. The overnight batch finished ahead of its usual window for the third night running. The desk signed it off at the same meeting.

- 2026-02-27: The address-management team published the change calendar for the coming quarter. A late change request arrived from one segment and was queued before the cut. The entry was left as it stands with no change to any published figure.

- 2026-02-15: A shift handover acknowledged an object-group enquiry and filed it. The weekly configuration export came back a few kilobytes larger than usual.

- 2026-02-13: A district supervisor reviewed an access request that had been sitting open. The hit-count variance sat inside tolerance and no adjustment was raised. The owner acknowledged it and nothing was carried forward.

- 2026-02-14: The network operations desk picked up a small discrepancy in a device log. One collector fell behind for a few minutes and caught up without gaps. It was recorded at the weekly slot.

- 2026-02-06: The security review group closed a housekeeping item on the nightly config export. The clock on a test appliance had drifted and was resynchronised.

- 2026-02-24: The duty engineer tidied a stale link in the operator runbook. The quarterly capacity figure landed within a percent of the forecast. It was filed for the record.

- 2026-02-07: The change board recorded a maintenance note against the management host. One rule appeared twice in the export after a mid-cycle correction. The item was closed with no parameter change.

- 2026-02-17: The service-desk lead answered a query about a prior change window. A report was regenerated after someone opened it mid-write.

- 2026-02-26: The firewall desk signed off the week's rule-base sampling with nothing outstanding. A stale credential was rotated on schedule rather than in response to anything. The entry was left as it stands at the same meeting.

- 2026-02-12: The documentation owner summarised a call with the appliance vendor. An export ran twice because an operator retried a step that had succeeded. The thread was archived with no change to any published figure.

- 2026-02-25: An on-call engineer revisited a control the auditors had asked about. The object-group register gained an entry and lost one in the same cycle.

- 2026-02-06: The capacity planner logged a correction request from a segment owner. A scheduled reload moved by twenty minutes and nobody noticed downstream. It was recorded and nothing was carried forward.

- 2026-02-16: The platform team wrote up an overnight page that had cleared itself. Storage on the staging host was extended after the export outgrew its allocation. It was noted at the weekly slot.

> **Board minute (2026-03-06 - #NET-9050)** Lena: the span reported against a rule is the size of the UNION of its source prefixes, so an address that sits inside two of them is counted once and a prefix nested in another adds nothing.

> **Board minute (2026-03-06 - #NET-9038)** Priya: a rule whose object group resolves to no address is treated as an unrestricted wildcard on that side, an empty group placing no constraint on the match.

- 2026-03-24: The escalation desk carried a minor point forward to the next shift. A question raised on the floor was withdrawn once the entry was reread.

- 2026-03-17: The audit lead published the change calendar for the coming quarter. A dashboard tile rendered blank until the browser cache was cleared. The item was closed for the record.

- 2026-03-11: The address-management team acknowledged an object-group enquiry and filed it. A typo in a reference record was corrected before the push started. The desk signed it off with no parameter change.

- 2026-03-22: A shift handover reviewed an access request that had been sitting open. A device reported a transient CPU spike during the config push and settled.

- 2026-03-19: A district supervisor picked up a small discrepancy in a device log. The vendor's status page showed a brief degradation that did not reach us. The thread was archived at the same meeting.

- 2026-03-25: The network operations desk closed a housekeeping item on the nightly config export. The nightly integrity sweep over the rule base completed clean. The owner acknowledged it with no change to any published figure.

- 2026-03-17: The security review group tidied a stale link in the operator runbook. A segment owner's contact record was refreshed at their own request.

- 2026-03-07: The duty engineer recorded a maintenance note against the management host. An out-of-office reply bounced a notification back into the queue. It was noted and nothing was carried forward.

- 2026-03-13: The change board answered a query about a prior change window. The published change calendar was reissued with the freeze dates corrected. It was filed at the weekly slot.

- 2026-03-13: The service-desk lead signed off the week's rule-base sampling with nothing outstanding. One field arrived null where the collector normally sends an empty string.

- 2026-03-06: The firewall desk summarised a call with the appliance vendor. One segment reported a rule fewer than the week before, all of it expected. The desk signed it off for the record.

- 2026-03-12: The documentation owner revisited a control the auditors had asked about. Two tickets covering the same request were merged. The entry was left as it stands with no parameter change.

- 2026-03-26: An on-call engineer logged a correction request from a segment owner. A failover rehearsal completed inside its window with nothing to note.

> **Board minute (2026-03-12 - #NET-9056)** Rosa: the address total in the summary covers every row the compiled policy carries, the closing deny included, since the total is read off the policy as installed.

> **Board minute (2026-03-20 - #NET-9068)** Marek: where the policy runs past its size limit the surplus is taken off the end in sequence order, the newest rules going first. The operator adds at the bottom, so the bottom is what the operator can most easily re-add.

> **Board minute (2026-03-12 - #NET-9044)** Anders: the closing deny is a property of the device and is left implied; the compiled policy carries only the operator's own rules.

- 2026-03-26: The capacity planner wrote up an overnight page that had cleared itself. The rule count sat a little above the running mean, entirely from a backfill. The owner acknowledged it at the same meeting.

- 2026-03-11: The platform team carried a minor point forward to the next shift. The overnight batch finished ahead of its usual window for the third night running. It was recorded with no change to any published figure.

- 2026-03-13: The escalation desk published the change calendar for the coming quarter. A late change request arrived from one segment and was queued before the cut.

- 2026-03-01: The audit lead acknowledged an object-group enquiry and filed it. The weekly configuration export came back a few kilobytes larger than usual. It was filed and nothing was carried forward.

- 2026-03-06: The address-management team reviewed an access request that had been sitting open. The hit-count variance sat inside tolerance and no adjustment was raised. The item was closed at the weekly slot.

- 2026-03-14: A shift handover picked up a small discrepancy in a device log. One collector fell behind for a few minutes and caught up without gaps.

- 2026-03-07: A district supervisor closed a housekeeping item on the nightly config export. The clock on a test appliance had drifted and was resynchronised. The entry was left as it stands for the record.

- 2026-03-17: The network operations desk tidied a stale link in the operator runbook. The quarterly capacity figure landed within a percent of the forecast. The thread was archived with no parameter change.

- 2026-03-27: The security review group recorded a maintenance note against the management host. One rule appeared twice in the export after a mid-cycle correction.

- 2026-03-17: The duty engineer answered a query about a prior change window. A report was regenerated after someone opened it mid-write. It was recorded at the same meeting.

- 2026-03-21: The change board signed off the week's rule-base sampling with nothing outstanding. A stale credential was rotated on schedule rather than in response to anything. It was noted with no change to any published figure.

- 2026-03-03: The service-desk lead summarised a call with the appliance vendor. An export ran twice because an operator retried a step that had succeeded.

- 2026-03-17: The firewall desk revisited a control the auditors had asked about. The object-group register gained an entry and lost one in the same cycle. The item was closed and nothing was carried forward.

- 2026-04-20: The documentation owner logged a correction request from a segment owner. A scheduled reload moved by twenty minutes and nobody noticed downstream. The desk signed it off at the weekly slot.

- 2026-04-16: An on-call engineer wrote up an overnight page that had cleared itself. Storage on the staging host was extended after the export outgrew its allocation.

- 2026-04-21: The capacity planner carried a minor point forward to the next shift. A question raised on the floor was withdrawn once the entry was reread. The thread was archived for the record.

- 2026-04-01: The platform team published the change calendar for the coming quarter. A dashboard tile rendered blank until the browser cache was cleared. The owner acknowledged it with no parameter change.

- 2026-04-13: The escalation desk acknowledged an object-group enquiry and filed it. A typo in a reference record was corrected before the push started.

- 2026-04-04: The audit lead reviewed an access request that had been sitting open. A device reported a transient CPU spike during the config push and settled. It was noted at the same meeting.

- 2026-04-19: The address-management team picked up a small discrepancy in a device log. The vendor's status page showed a brief degradation that did not reach us. It was filed with no change to any published figure.

- 2026-04-15: A shift handover closed a housekeeping item on the nightly config export. The nightly integrity sweep over the rule base completed clean.

- 2026-04-23: A district supervisor tidied a stale link in the operator runbook. A segment owner's contact record was refreshed at their own request. The desk signed it off and nothing was carried forward.

- 2026-04-05: The network operations desk recorded a maintenance note against the management host. An out-of-office reply bounced a notification back into the queue. The entry was left as it stands at the weekly slot.

- 2026-04-04: The security review group answered a query about a prior change window. The published change calendar was reissued with the freeze dates corrected.

- 2026-04-04: The duty engineer signed off the week's rule-base sampling with nothing outstanding. One field arrived null where the collector normally sends an empty string. The owner acknowledged it for the record.

- 2026-04-09: The change board summarised a call with the appliance vendor. One segment reported a rule fewer than the week before, all of it expected. It was recorded with no parameter change.

- 2026-04-18: The service-desk lead revisited a control the auditors had asked about. Two tickets covering the same request were merged.

- 2026-04-22: The firewall desk logged a correction request from a segment owner. A failover rehearsal completed inside its window with nothing to note. It was filed at the same meeting.

- 2026-04-26: The documentation owner wrote up an overnight page that had cleared itself. The rule count sat a little above the running mean, entirely from a backfill. The item was closed with no change to any published figure.

- 2026-04-25: An on-call engineer carried a minor point forward to the next shift. The overnight batch finished ahead of its usual window for the third night running.

- 2026-04-21: The capacity planner published the change calendar for the coming quarter. A late change request arrived from one segment and was queued before the cut. The entry was left as it stands and nothing was carried forward.

- 2026-04-24: The platform team acknowledged an object-group enquiry and filed it. The weekly configuration export came back a few kilobytes larger than usual. The thread was archived at the weekly slot.

- 2026-04-09: The escalation desk reviewed an access request that had been sitting open. The hit-count variance sat inside tolerance and no adjustment was raised.

- 2026-04-08: The audit lead picked up a small discrepancy in a device log. One collector fell behind for a few minutes and caught up without gaps. It was recorded for the record.

- 2026-05-16: The address-management team closed a housekeeping item on the nightly config export. The clock on a test appliance had drifted and was resynchronised. It was noted with no parameter change.

- 2026-05-07: A shift handover tidied a stale link in the operator runbook. The quarterly capacity figure landed within a percent of the forecast.

> **Board minute (2026-05-04 - #NET-9150)** Priya: Input paths, final. The object-group catalogue and the firewall policy are always read from their fixed absolute paths under /app/data; `--input` selects the rule base only. Both `--input` and `--output-dir` keep their documented defaults.

> **Board minute (2026-05-06 - #NET-9170)** Yusuf: Rule-base recovery, final. Start from the pre-migration snapshot and replay the configuration journal in ascending `seq`, never in file order, keying each change on the rule it names. An `amend` overwrites the named field in place. A `retract` takes the rule out, but the migrator keeps it as it stood at that moment. A `restore` returns a retracted rule EXACTLY as it then stood: an amendment posted before the retraction survives, and one posted while it was out is lost. A change naming a rule the snapshot never carried is ignored.

> **Board minute (2026-05-08 - #NET-9174)** Yusuf: Object-group resolution, final. A group resolves to the set of prefixes reachable from it, expanding a member that names another group TRANSITIVELY rather than one level deep. Each group is entered once on a given resolution, so a catalogue that nests two groups into each other terminates instead of recurring. A member naming a group the catalogue does not carry contributes nothing. The resolved set is deduplicated and ordered ascending by network address, then by prefix length. A rule side written as a literal prefix resolves to that prefix alone.

> **Board minute (2026-05-09 - #NET-9178)** Yusuf: Recovered shape, final. The rebuilt rule base is a JSON array ascending by sequence and then rule id, and each row carries the nine rule fields with both sides already resolved -- the migrator's bookkeeping (`seq`, `kind`, `posted_by`) never survives the replay.

> **Board minute (2026-05-13 - #NET-9182)** Lena: Match order, final. The device takes the FIRST rule in ascending sequence that matches a packet, whatever its prefix length. It follows that a rule an earlier rule already covers can never fire -- but it is REPORTED as shadowed and left where it stands. The compiled policy is the operator's rule base in sequence, not a minimised set, because removing a rule changes the sequence the operator reads back.

> **Board minute (2026-05-16 - #NET-9186)** Marek: Shadowing, final. A rule is shadowed only where a SINGLE earlier live rule already matches every packet it matches: that rule's protocol is `any` or the same protocol, every one of its source prefixes sits inside one of that rule's source prefixes, the same holds of the destination, and its port range sits inside that rule's port range. The union of several earlier rules never establishes shadowing. Only the policy's max_shadow_lookback immediately preceding live rules are examined, and the first such rule found, scanning backwards, is the one recorded.

> **Board minute (2026-05-19 - #NET-9190)** Marek: Inert rules, final. A rule the operator left disabled, and a rule either side of which resolves to NO address at all, is inert: it never matches a packet and it never shadows a later rule. An empty object group is an empty set, not a wildcard. An inert rule leaves the compiled policy and is queued as `inert`.

> **Board minute (2026-05-22 - #NET-9192)** Priya: Port handling, final. A port range is clamped to the policy's port_ceiling before any coverage question is asked of it, and a low port left above the clamped high is brought down to it.

> **Board minute (2026-05-25 - #NET-9194)** Lena: Closing deny, final. The compiled policy always ends with an explicit rule denying every protocol from every address to every address across the whole port range, carried at the policy's default_deny_sequence under the rule id FW-DEFAULT. It is emitted even where the cap has already been reached and it never counts against the cap.

> **Board minute (2026-05-28 - #NET-9196)** Lena: Exception queue, final. The queue carries the inert rules and every rule the cap displaced, emitted by reason and then by rule id.

> **Board minute (2026-05-30 - #NET-9198)** Yusuf: Policy size, final. The compiled policy is capped at the policy's max_rules, counted over the operator's own rules alone; the rules past the cap, taken in sequence order, leave the policy and are queued as `over_cap`. The shadowing verdict is settled BEFORE the cap is applied, so the reported shadowed count covers every live rule an earlier rule already matches, whether or not the cap keeps that rule in the policy.

- 2026-05-13: A district supervisor recorded a maintenance note against the management host. One rule appeared twice in the export after a mid-cycle correction. The item was closed at the same meeting.

- 2026-05-12: The network operations desk answered a query about a prior change window. A report was regenerated after someone opened it mid-write. The desk signed it off with no change to any published figure.

- 2026-05-10: The security review group signed off the week's rule-base sampling with nothing outstanding. A stale credential was rotated on schedule rather than in response to anything.

- 2026-05-12: The duty engineer summarised a call with the appliance vendor. An export ran twice because an operator retried a step that had succeeded. The thread was archived and nothing was carried forward.

- 2026-05-11: The change board revisited a control the auditors had asked about. The object-group register gained an entry and lost one in the same cycle. The owner acknowledged it at the weekly slot.

- 2026-05-21: The service-desk lead logged a correction request from a segment owner. A scheduled reload moved by twenty minutes and nobody noticed downstream.

- 2026-05-09: The firewall desk wrote up an overnight page that had cleared itself. Storage on the staging host was extended after the export outgrew its allocation. It was noted for the record.

- 2026-05-01: The documentation owner carried a minor point forward to the next shift. A question raised on the floor was withdrawn once the entry was reread. It was filed with no parameter change.

- 2026-05-24: An on-call engineer published the change calendar for the coming quarter. A dashboard tile rendered blank until the browser cache was cleared.

- 2026-05-18: The capacity planner acknowledged an object-group enquiry and filed it. A typo in a reference record was corrected before the push started. The desk signed it off at the same meeting.

- 2026-05-14: The platform team reviewed an access request that had been sitting open. A device reported a transient CPU spike during the config push and settled. The entry was left as it stands with no change to any published figure.

- 2026-05-11: The escalation desk picked up a small discrepancy in a device log. The vendor's status page showed a brief degradation that did not reach us.

- 2026-05-06: The audit lead closed a housekeeping item on the nightly config export. The nightly integrity sweep over the rule base completed clean. The owner acknowledged it and nothing was carried forward.

- 2026-05-20: The address-management team tidied a stale link in the operator runbook. A segment owner's contact record was refreshed at their own request. It was recorded at the weekly slot.

- 2026-05-21: A shift handover recorded a maintenance note against the management host. An out-of-office reply bounced a notification back into the queue.

- 2026-05-25: A district supervisor answered a query about a prior change window. The published change calendar was reissued with the freeze dates corrected. It was filed for the record.

- 2026-05-25: The network operations desk signed off the week's rule-base sampling with nothing outstanding. One field arrived null where the collector normally sends an empty string. The item was closed with no parameter change.

- 2026-06-18: The security review group summarised a call with the appliance vendor. One segment reported a rule fewer than the week before, all of it expected.

> **Board minute (2026-06-02 - #NET-9210)** Priya: Firewall policy baseline, read from /app/data/firewall_policy.json at that fixed absolute path. Any field the policy file omits keeps its baseline: max_rules = 420; port_ceiling = 65535; max_shadow_lookback = 120; default_deny_sequence = 999000.

> **Board minute (2026-06-04 - #NET-9214)** Lena: Address span, final. The span carried on a compiled rule is the sum of the sizes of the prefixes in its resolved source set, each prefix counted in full and on its own. Two prefixes that overlap, and a prefix nested inside another, are counted TWICE between them: the figure is what the rule asks the device to cover, not how many distinct addresses that comes to. The board took the union reading out because a nested pair made the reported span fall as an operator widened a rule, and the audit reads the figure as a measure of reach.

> **Board minute (2026-06-06 - #NET-9218)** Rosa: Summary population, final. total_source_addresses covers the operator's own rules alone and the closing FW-DEFAULT deny is left out of it, the whole address space being an artefact of the close rather than anything an operator asked for. The deny is still a row of the compiled policy and still counts in compiled_count and in deny_count; it is the address total, and only the address total, that passes over it.

> **Board minute (2026-06-08 - #NET-9222)** Marek: Cap accounting, final (revises what #NET-9198's cap COUNTS; the rest of that minute stands). The limit is on the rules the device will actually evaluate. A rule reported shadowed is one an earlier rule always matches first, so it is never evaluated and costs nothing against max_rules: it rides along inside the cap and stays in the policy where it sits, as #NET-9182 requires of it. The policy therefore closes at the point where the max_rules-th UNSHADOWED rule has been admitted, taken in sequence order, and everything from there on -- shadowed or not -- leaves the policy and is queued as `over_cap` in that same order. What stays is still an unbroken run of the rule base from the top, so a policy may carry more rows than max_rules and be inside it, and no rule it keeps ever names a shadower the cap took away. The closing deny counts against nothing, as before, and the shadow verdict is still settled before any of this, so `shadowed_count` covers every live rule an earlier rule already matched whether or not the cap kept it.

- 2026-06-26: The duty engineer revisited a control the auditors had asked about. Two tickets covering the same request were merged. The entry was left as it stands at the same meeting.

- 2026-06-15: The change board logged a correction request from a segment owner. A failover rehearsal completed inside its window with nothing to note. The thread was archived with no change to any published figure.

- 2026-06-22: The service-desk lead wrote up an overnight page that had cleared itself. The rule count sat a little above the running mean, entirely from a backfill.

- 2026-06-11: The firewall desk carried a minor point forward to the next shift. The overnight batch finished ahead of its usual window for the third night running. It was recorded and nothing was carried forward.

- 2026-06-20: The documentation owner published the change calendar for the coming quarter. A late change request arrived from one segment and was queued before the cut. It was noted at the weekly slot.

- 2026-06-22: An on-call engineer acknowledged an object-group enquiry and filed it. The weekly configuration export came back a few kilobytes larger than usual.

- 2026-06-22: The capacity planner reviewed an access request that had been sitting open. The hit-count variance sat inside tolerance and no adjustment was raised. The item was closed for the record.

- 2026-06-17: The platform team picked up a small discrepancy in a device log. One collector fell behind for a few minutes and caught up without gaps. The desk signed it off with no parameter change.

- 2026-06-23: The escalation desk closed a housekeeping item on the nightly config export. The clock on a test appliance had drifted and was resynchronised.

- 2026-06-18: The audit lead tidied a stale link in the operator runbook. The quarterly capacity figure landed within a percent of the forecast. The thread was archived at the same meeting.

- 2026-06-05: The address-management team recorded a maintenance note against the management host. One rule appeared twice in the export after a mid-cycle correction. The owner acknowledged it with no change to any published figure.

- 2026-06-13: A shift handover answered a query about a prior change window. A report was regenerated after someone opened it mid-write.

- 2026-06-04: A district supervisor signed off the week's rule-base sampling with nothing outstanding. A stale credential was rotated on schedule rather than in response to anything. It was noted and nothing was carried forward.

- 2026-06-21: The network operations desk summarised a call with the appliance vendor. An export ran twice because an operator retried a step that had succeeded. It was filed at the weekly slot.

- 2026-06-06: The security review group revisited a control the auditors had asked about. The object-group register gained an entry and lost one in the same cycle.

- 2026-06-10: The duty engineer logged a correction request from a segment owner. A scheduled reload moved by twenty minutes and nobody noticed downstream. The desk signed it off for the record.

- 2026-06-06: The change board wrote up an overnight page that had cleared itself. Storage on the staging host was extended after the export outgrew its allocation. The entry was left as it stands with no parameter change.

- 2026-06-21: The service-desk lead carried a minor point forward to the next shift. A question raised on the floor was withdrawn once the entry was reread.

- 2026-06-15: The firewall desk published the change calendar for the coming quarter. A dashboard tile rendered blank until the browser cache was cleared. The owner acknowledged it at the same meeting.

- 2026-06-18: The documentation owner acknowledged an object-group enquiry and filed it. A typo in a reference record was corrected before the push started. It was recorded with no change to any published figure.

- 2026-06-01: An on-call engineer reviewed an access request that had been sitting open. A device reported a transient CPU spike during the config push and settled.

- 2026-06-01: The capacity planner picked up a small discrepancy in a device log. The vendor's status page showed a brief degradation that did not reach us. It was filed and nothing was carried forward.

- 2026-06-01: The platform team closed a housekeeping item on the nightly config export. The nightly integrity sweep over the rule base completed clean. The item was closed at the weekly slot.
