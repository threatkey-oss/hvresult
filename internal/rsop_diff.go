package internal

import (
	"sort"
	"strings"

	mdtf "github.com/fbiville/markdown-table-formatter/pkg/markdown"
)

// The differences between two sets of policies.
type RSoPDifferential struct {
	Added   RSoPCapMap
	Removed RSoPCapMap
}

// Whether there are any effective changes.
func (p *RSoPDifferential) Empty() bool {
	if p == nil {
		return true
	}
	return len(p.Added) == 0 && len(p.Removed) == 0
}

// Emits a GitHub-flavored markdown table of changes or the empty string if there are none.
func (p *RSoPDifferential) MarkdownTable() string {
	if p.Empty() {
		return ""
	}
	// emit paths in ascending lexical order, added first and removed second
	var paths []string
	pathHits := map[string]bool{}
	for path := range p.Added {
		paths = append(paths, path)
		pathHits[path] = true
	}
	for path := range p.Removed {
		if !pathHits[path] {
			paths = append(paths, path)
		}
	}
	sort.StringSlice(paths).Sort()
	var (
		builder = mdtf.NewTableFormatterBuilder().
			WithPrettyPrint().
			Build("Path", "Change", "Capability", "Policy / Policies")
		rows = make([][]string, 0, len(paths))
	)
	for _, path := range paths {
		rows = append(rows, getChangesetRows(builder, path, p.Added[path], p.Removed[path])...)
	}
	table, err := builder.Format(rows)
	if err != nil {
		panic(err)
	}
	return table
}

// Returns changeset metrics like the total count of changes.
func (p *RSoPDifferential) Metrics() RSoPDiffMetrics {
	var metrics RSoPDiffMetrics
	for _, added := range p.Added {
		for policy := range added {
			metrics.CapabilityChanges += len(added[policy])
		}
	}
	for _, removed := range p.Removed {
		for policy := range removed {
			metrics.CapabilityChanges += len(removed[policy])
		}
	}
	return metrics
}

type RSoPDiffMetrics struct {
	// Total amount of capabilities modified
	CapabilityChanges int
}

func getChangesetRows(
	builder mdtf.TableFormatter,
	path string,
	added, removed map[Capability][]string,
) [][]string {
	var (
		pathEmitted bool
		rows        [][]string
	)
	emitRows := func(caps map[Capability][]string, added bool) {
		// sort keys
		capKeys := make([]Capability, 0, len(caps))
		for cap := range caps {
			capKeys = append(capKeys, cap)
		}
		sort.Slice(capKeys, func(i, j int) bool {
			return capKeys[i].Less(capKeys[j])
		})
		for _, cap := range capKeys {
			row := make([]string, 0, 4)
			// path
			if pathEmitted {
				row = append(row, "")
			} else {
				row = append(row, path)
				pathEmitted = true
			}
			// change
			if added {
				row = append(row, "➕")
			} else {
				row = append(row, "➖")
			}
			policies := caps[cap]
			row = append(
				row,
				// capability
				string(cap),
				// `pol1`, `pol2`
				strings.Join(policies, "` , `"),
			)
			rows = append(rows, row)
		}
	}
	emitRows(added, true)
	emitRows(removed, false)
	return rows
}

// Generates a differential between 2 policy sets.
func (r RSoPCapMap) Diff(other RSoPCapMap) *RSoPDifferential {
	// deleted
	if len(other) == 0 {
		return &RSoPDifferential{
			Removed: r,
		}
	}
	diff := &RSoPDifferential{
		Added:   make(RSoPCapMap),
		Removed: make(RSoPCapMap),
	}
	for path, caps := range r {
		if otherCaps := other[path]; len(otherCaps) == 0 {
			diff.Removed[path] = caps
		} else {
			// go through our caps and add misses in other to Removed
			for cap, policyNames := range caps {
				if _, exists := otherCaps[cap]; !exists {
					if diff.Removed[path] == nil {
						diff.Removed[path] = map[Capability][]string{cap: policyNames}
					}
					diff.Removed[path][cap] = policyNames
				}
			}
		}
	}
	for path, caps := range other {
		if ourCaps := r[path]; len(ourCaps) == 0 {
			diff.Added[path] = caps
		} else {
			// go through other caps and add misses in ours to Added
			for cap, policyNames := range caps {
				if _, exists := ourCaps[cap]; !exists {
					if diff.Added[path] == nil {
						diff.Added[path] = map[Capability][]string{cap: policyNames}
					}
					diff.Added[path][cap] = policyNames
				}
			}
		}
	}
	// TODO: optimize if this turns out to be some sort of problem
	if len(diff.Added) == 0 {
		diff.Added = nil
	}
	if len(diff.Removed) == 0 {
		diff.Removed = nil
	}
	return diff
}
