// Stage two of the reference: the corrected policy compiler.
//
// Every governing value is traced to its final dated entry in
// /app/incident/network_governance_log.md; policy_contract.json supplies the
// output contract only and no derivation rule.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type resolvedRule struct {
	RuleID           string   `json:"rule_id"`
	Sequence         int      `json:"sequence"`
	Action           string   `json:"action"`
	Protocol         string   `json:"protocol"`
	SourceCIDRs      []string `json:"source_cidrs"`
	DestinationCIDRs []string `json:"destination_cidrs"`
	PortLow          int      `json:"port_low"`
	PortHigh         int      `json:"port_high"`
	Enabled          bool     `json:"enabled"`
}

type policy struct {
	Default map[string]int64 `json:"default"`
}

type compiledRule struct {
	RuleID           string   `json:"rule_id"`
	Sequence         int      `json:"sequence"`
	Action           string   `json:"action"`
	Protocol         string   `json:"protocol"`
	SourceCIDRs      []string `json:"source_cidrs"`
	DestinationCIDRs []string `json:"destination_cidrs"`
	PortLow          int      `json:"port_low"`
	PortHigh         int      `json:"port_high"`
	Shadowed         bool     `json:"shadowed"`
	ShadowedBy       string   `json:"shadowed_by"`
	AddressSpan      int64    `json:"address_span"`
}

type queueRow struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

type prefix struct {
	base uint32
	plen int
}

func readJSON(path string, into any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeJSON(path string, value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseCIDR(text string) (prefix, bool) {
	slash := strings.IndexByte(text, '/')
	if slash < 0 {
		return prefix{}, false
	}
	plen, err := strconv.Atoi(text[slash+1:])
	if err != nil || plen < 0 || plen > 32 {
		return prefix{}, false
	}
	parts := strings.Split(text[:slash], ".")
	if len(parts) != 4 {
		return prefix{}, false
	}
	var base uint32
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return prefix{}, false
		}
		base = base<<8 | uint32(n)
	}
	return prefix{base & maskOf(plen), plen}, true
}

func maskOf(plen int) uint32 {
	if plen == 0 {
		return 0
	}
	return 0xFFFFFFFF << uint(32-plen)
}

func parseSet(list []string) []prefix {
	out := make([]prefix, 0, len(list))
	for _, c := range list {
		if p, ok := parseCIDR(c); ok {
			out = append(out, p)
		}
	}
	return out
}

// covers reports whether the outer prefix contains the inner one entirely.
func covers(outer, inner prefix) bool {
	return outer.plen <= inner.plen && inner.base&maskOf(outer.plen) == outer.base
}

// setCovers reports whether every prefix of inner sits inside some single prefix
// of outer. A rule with no address at all covers nothing.
func setCovers(outer, inner []prefix) bool {
	if len(outer) == 0 || len(inner) == 0 {
		return false
	}
	for _, b := range inner {
		found := false
		for _, a := range outer {
			if covers(a, b) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func spanOf(set []prefix) int64 {
	var total int64
	for _, p := range set {
		total += int64(1) << uint(32-p.plen)
	}
	return total
}

// The policy is read from its fixed absolute path, and any field the file omits
// keeps its governed baseline. A missing Go map key is zero, not the baseline,
// so the fallback has to be explicit.
func policyValue(pol policy, field string, baseline int64) int64 {
	if value, ok := pol.Default[field]; ok {
		return value
	}
	return baseline
}

func main() {
	input := flag.String("input", "/app/data/policy_rules.json", "resolved rule base")
	outputDir := flag.String("output-dir", "/app/output", "output directory")
	flag.Parse()

	var rules []resolvedRule
	var pol policy
	// #NET-9150: the firewall policy is always read from its fixed absolute path;
	// --input selects the rule base only.
	readJSON("/app/data/firewall_policy.json", &pol)
	readJSON(*input, &rules)

	maxRules := int(policyValue(pol, "max_rules", 420))
	portCeiling := int(policyValue(pol, "port_ceiling", 65535))
	lookback := int(policyValue(pol, "max_shadow_lookback", 120))
	denySequence := int(policyValue(pol, "default_deny_sequence", 999000))

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Sequence != rules[j].Sequence {
			return rules[i].Sequence < rules[j].Sequence
		}
		return rules[i].RuleID < rules[j].RuleID
	})

	type live struct {
		rule  resolvedRule
		src   []prefix
		dst   []prefix
		lo    int
		hi    int
	}

	compiled := make([]compiledRule, 0, len(rules))
	queue := make([]queueRow, 0)
	kept := make([]live, 0, len(rules))
	enabledCount, inertCount, shadowedCount := 0, 0, 0

	for _, r := range rules {
		if r.Enabled {
			enabledCount++
		}
		src := parseSet(r.SourceCIDRs)
		dst := parseSet(r.DestinationCIDRs)
		// #NET-9190: a rule the migration left disabled, and a rule either side of
		// which resolves to no address at all, is INERT. It never matches a packet
		// and it never shadows a later rule -- an empty object group is not a
		// wildcard.
		if !r.Enabled || len(src) == 0 || len(dst) == 0 {
			inertCount++
			queue = append(queue, queueRow{r.RuleID, "inert"})
			continue
		}
		// #NET-9192: a port range is clamped to the policy's ceiling before any
		// coverage question is asked of it.
		lo, hi := r.PortLow, r.PortHigh
		if hi > portCeiling {
			hi = portCeiling
		}
		if lo > hi {
			lo = hi
		}

		// #NET-9186: a rule is shadowed when a SINGLE earlier rule already matches
		// every packet it matches -- same or wider protocol, every source prefix
		// inside one of that rule's source prefixes, the same of the destination, and
		// a port range no narrower. Only the policy's max_shadow_lookback immediately
		// preceding live rules are examined.
		shadowedBy := ""
		start := len(kept) - lookback
		if start < 0 {
			start = 0
		}
		for i := len(kept) - 1; i >= start; i-- {
			a := kept[i]
			if a.rule.Protocol != "any" && a.rule.Protocol != r.Protocol {
				continue
			}
			if a.lo > lo || hi > a.hi {
				continue
			}
			if !setCovers(a.src, src) || !setCovers(a.dst, dst) {
				continue
			}
			shadowedBy = a.rule.RuleID
			break
		}
		if shadowedBy != "" {
			shadowedCount++
		}
		// #NET-9182: the device takes the FIRST rule in sequence that matches, so a
		// shadowed rule is reported but never removed -- the compiled policy is the
		// operator's rule base in sequence, not a minimised set.
		compiled = append(compiled, compiledRule{
			RuleID: r.RuleID, Sequence: r.Sequence, Action: r.Action, Protocol: r.Protocol,
			SourceCIDRs: r.SourceCIDRs, DestinationCIDRs: r.DestinationCIDRs,
			PortLow: lo, PortHigh: hi, Shadowed: shadowedBy != "", ShadowedBy: shadowedBy,
			AddressSpan: spanOf(src),
		})
		kept = append(kept, live{r, src, dst, lo, hi})
	}

	// #NET-9198: the compiled policy is capped at the policy's max_rules; everything
	// past the cap leaves the policy and is queued in sequence order.
	if maxRules > 0 && len(compiled) > maxRules {
		for _, row := range compiled[maxRules:] {
			queue = append(queue, queueRow{row.RuleID, "over_cap"})
		}
		compiled = compiled[:maxRules]
	}

	permitCount, denyCount := 0, 0
	var totalAddresses int64
	for _, row := range compiled {
		if row.Action == "permit" {
			permitCount++
		} else {
			denyCount++
		}
		totalAddresses += row.AddressSpan
	}

	// #NET-9194: the policy always closes with an explicit deny of everything, at
	// the policy's default_deny_sequence. It is emitted even where the cap has
	// already been reached and never counts against the cap.
	compiled = append(compiled, compiledRule{
		RuleID: "FW-DEFAULT", Sequence: denySequence, Action: "deny", Protocol: "any",
		SourceCIDRs: []string{"0.0.0.0/0"}, DestinationCIDRs: []string{"0.0.0.0/0"},
		PortLow: 0, PortHigh: portCeiling, Shadowed: false, ShadowedBy: "",
		AddressSpan: int64(1) << 32,
	})
	denyCount++

	// #NET-9196: the queue is emitted by reason and then by rule id.
	sort.Slice(queue, func(i, j int) bool {
		if queue[i].Reason != queue[j].Reason {
			return queue[i].Reason < queue[j].Reason
		}
		return queue[i].RuleID < queue[j].RuleID
	})

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	summary := map[string]any{
		"schema_version":                 "fw-policy-v1",
		"rule_count":                     len(rules),
		"enabled_rule_count":             enabledCount,
		"inert_count":                    inertCount,
		"shadowed_count":                 shadowedCount,
		"compiled_count":                 len(compiled),
		"queued_count":                   len(queue),
		"permit_count":                   permitCount,
		"deny_count":                     denyCount,
		"total_source_addresses":         totalAddresses,
		"effective_max_rules":            maxRules,
		"effective_port_ceiling":         portCeiling,
		"effective_shadow_lookback":      lookback,
		"effective_default_deny_sequence": denySequence,
	}
	writeJSON(*outputDir+"/summary.json", summary)
	writeJSON(*outputDir+"/compiled_policy.json", compiled)

	handle, err := os.Create(*outputDir + "/exception_queue.jsonl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer handle.Close()
	enc := json.NewEncoder(handle)
	for _, row := range queue {
		if err := enc.Encode(row); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "compiled %d rules, queued %d\n", len(compiled), len(queue))
}
