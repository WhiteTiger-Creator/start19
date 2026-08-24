// Stage one of the reference: rebuild the rule base the configuration migration
// truncated at /app/data/policy_rules.json.
//
// Governed by #NET-9170 (replay semantics), #NET-9174 (object-group resolution)
// and #NET-9178 (shape and ordering of the result).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type rawRule struct {
	RuleID      string `json:"rule_id"`
	Sequence    int    `json:"sequence"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	PortLow     int    `json:"port_low"`
	PortHigh    int    `json:"port_high"`
	Enabled     bool   `json:"enabled"`
}

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

type change struct {
	Seq    int    `json:"seq"`
	RuleID string `json:"rule_id"`
	Kind   string `json:"kind"`
	Field  string `json:"field"`
	Value  any    `json:"value"`
}

type group struct {
	GroupID string   `json:"group_id"`
	Members []string `json:"members"`
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

func setField(r *rawRule, field string, value any) {
	switch field {
	case "action":
		if s, ok := value.(string); ok {
			r.Action = s
		}
	case "protocol":
		if s, ok := value.(string); ok {
			r.Protocol = s
		}
	case "source":
		if s, ok := value.(string); ok {
			r.Source = s
		}
	case "destination":
		if s, ok := value.(string); ok {
			r.Destination = s
		}
	case "enabled":
		if b, ok := value.(bool); ok {
			r.Enabled = b
		}
	case "port_low":
		if n, ok := value.(float64); ok {
			r.PortLow = int(n)
		}
	case "port_high":
		if n, ok := value.(float64); ok {
			r.PortHigh = int(n)
		}
	}
}

// parseCIDR returns the masked network base and the prefix length.
func parseCIDR(text string) (uint32, int, bool) {
	slash := strings.IndexByte(text, '/')
	if slash < 0 {
		return 0, 0, false
	}
	plen, err := strconv.Atoi(text[slash+1:])
	if err != nil || plen < 0 || plen > 32 {
		return 0, 0, false
	}
	parts := strings.Split(text[:slash], ".")
	if len(parts) != 4 {
		return 0, 0, false
	}
	var base uint32
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return 0, 0, false
		}
		base = base<<8 | uint32(n)
	}
	var mask uint32 = 0xFFFFFFFF
	if plen < 32 {
		mask <<= uint(32 - plen)
	}
	if plen == 0 {
		mask = 0
	}
	return base & mask, plen, true
}

func formatCIDR(base uint32, plen int) string {
	return fmt.Sprintf("%d.%d.%d.%d/%d", base>>24&255, base>>16&255, base>>8&255, base&255, plen)
}

// sortCIDRs orders a resolved set ascending by network address, then prefix length.
func sortCIDRs(list []string) []string {
	sort.Slice(list, func(i, j int) bool {
		bi, pi, _ := parseCIDR(list[i])
		bj, pj, _ := parseCIDR(list[j])
		if bi != bj {
			return bi < bj
		}
		return pi < pj
	})
	return list
}

func main() {
	var snapshot []rawRule
	var journal []change
	var groups []group
	readJSON("/app/data/rule_snapshot_pre_migration.json", &snapshot)
	readJSON("/app/data/config_journal.json", &journal)
	readJSON("/app/data/object_groups.json", &groups)

	byGroup := make(map[string]group, len(groups))
	for _, g := range groups {
		byGroup[g.GroupID] = g
	}

	// #NET-9174: a group's members are literal prefixes and references to other
	// groups, resolved transitively. Each group is entered once on a resolution, so
	// a cycle terminates rather than recurring; a reference to a group the catalogue
	// does not carry contributes nothing. The result is deduplicated and ordered by
	// network address then prefix length.
	var expand func(id string, seen map[string]bool, into map[string]bool)
	expand = func(id string, seen map[string]bool, into map[string]bool) {
		if seen[id] {
			return
		}
		seen[id] = true
		g, ok := byGroup[id]
		if !ok {
			return
		}
		for _, m := range g.Members {
			if strings.HasPrefix(m, "@") {
				expand(strings.TrimPrefix(m, "@"), seen, into)
				continue
			}
			if base, plen, ok := parseCIDR(m); ok {
				into[formatCIDR(base, plen)] = true
			}
		}
	}
	resolve := func(ref string) []string {
		set := map[string]bool{}
		if strings.HasPrefix(ref, "@") {
			expand(strings.TrimPrefix(ref, "@"), map[string]bool{}, set)
		} else if base, plen, ok := parseCIDR(ref); ok {
			set[formatCIDR(base, plen)] = true
		}
		out := make([]string, 0, len(set))
		for c := range set {
			out = append(out, c)
		}
		return sortCIDRs(out)
	}

	live := make(map[string]*rawRule, len(snapshot))
	for i := range snapshot {
		r := snapshot[i]
		live[r.RuleID] = &r
	}
	// #NET-9170: a retraction takes the rule out but the migrator keeps it, so a
	// later restore returns it exactly as it then stood -- an amendment posted
	// before survives, one posted while it was out is lost.
	held := map[string]rawRule{}

	sort.Slice(journal, func(i, j int) bool { return journal[i].Seq < journal[j].Seq })
	for _, c := range journal {
		switch c.Kind {
		case "amend":
			if r, ok := live[c.RuleID]; ok {
				setField(r, c.Field, c.Value)
			}
		case "retract":
			if r, ok := live[c.RuleID]; ok {
				held[c.RuleID] = *r
				delete(live, c.RuleID)
			}
		case "restore":
			if r, ok := held[c.RuleID]; ok {
				restored := r
				live[c.RuleID] = &restored
				delete(held, c.RuleID)
			}
		}
	}

	out := make([]resolvedRule, 0, len(live))
	for _, r := range live {
		out = append(out, resolvedRule{
			RuleID: r.RuleID, Sequence: r.Sequence, Action: r.Action, Protocol: r.Protocol,
			SourceCIDRs: resolve(r.Source), DestinationCIDRs: resolve(r.Destination),
			PortLow: r.PortLow, PortHigh: r.PortHigh, Enabled: r.Enabled,
		})
	}
	// #NET-9178: ascending sequence, then rule id.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sequence != out[j].Sequence {
			return out[i].Sequence < out[j].Sequence
		}
		return out[i].RuleID < out[j].RuleID
	})

	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("/app/data/policy_rules.json", append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "resolved %d rules\n", len(out))
}
