package internal_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/threatkey-oss/hvresult/internal"
)

func TestRsopDiff(t *testing.T) {
	t.Run("NoChange", func(t *testing.T) {
		var (
			rsop   = &internal.RSoP{Policies: []*internal.Policy{defaultPolicy}}
			capmap = rsop.GetCapabilityMap()
		)
		pdiff := capmap.Diff(capmap)
		if diff := cmp.Diff(&internal.RSoPDifferential{}, pdiff); diff != "" {
			t.Fatal(diff)
		}
	})
	t.Run("Added", func(t *testing.T) {
		before := &internal.RSoP{
			Policies: []*internal.Policy{
				{
					Name: "before",
					Paths: []internal.PathConfig{
						{
							Path:         "modified",
							Capabilities: []internal.Capability{"create"},
						},
					},
				},
			},
		}
		after := &internal.RSoP{
			Policies: []*internal.Policy{
				{
					Name: "after",
					Paths: []internal.PathConfig{
						{
							Path:         "modified",
							Capabilities: []internal.Capability{"create", "delete"},
						},
						{
							Path:         "new",
							Capabilities: []internal.Capability{"sudo"},
						},
					},
				},
			},
		}
		pdiff := before.GetCapabilityMap().Diff(after.GetCapabilityMap())
		expected := &internal.RSoPDifferential{
			Added: internal.RSoPCapMap{
				"modified": {"delete": {"after"}},
				"new":      {"sudo": {"after"}},
			},
		}
		if diff := cmp.Diff(expected, pdiff); diff != "" {
			t.Fatal(diff)
		}
	})
	t.Run("Removed", func(t *testing.T) {
		before := &internal.RSoP{
			Policies: []*internal.Policy{
				{
					Name: "before",
					Paths: []internal.PathConfig{{
						Path:         "modified",
						Capabilities: []internal.Capability{"create", "list"},
					}},
				},
				{
					Name: "before2",
					Paths: []internal.PathConfig{{
						Path:         "removed",
						Capabilities: []internal.Capability{"sudo", "subscribe"},
					}},
				},
			},
		}
		after := &internal.RSoP{
			Policies: []*internal.Policy{
				{
					Name: "before",
					Paths: []internal.PathConfig{{
						Path:         "modified",
						Capabilities: []internal.Capability{"create"},
					}},
				},
			},
		}
		pdiff := before.GetCapabilityMap().Diff(after.GetCapabilityMap())
		expected := &internal.RSoPDifferential{
			Removed: internal.RSoPCapMap{
				"modified": {"list": {"before"}},
				"removed": {
					"subscribe": {"before2"},
					"sudo":      {"before2"},
				},
			},
		}
		if diff := cmp.Diff(expected, pdiff); diff != "" {
			t.Fatal(diff)
		}
	})
}
