package internal_test

import (
	_ "embed"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/threatkey-oss/hvresult/internal"
)

//go:embed testdata/kitchensink.hcl
var kitchenSinkHCL []byte

// Tests/demonstrates that the HCL tags work as expected.
func TestHCL(t *testing.T) {
	var policy internal.Policy
	err := hclsimple.Decode("kitchensink.hcl", kitchenSinkHCL, nil, &policy)
	if err != nil {
		t.Fatal(err)
	}
	// remove OtherFields because we do not care
	for i := range policy.Paths {
		policy.Paths[i].Other = nil
	}
	if diff := cmp.Diff(policy, internal.Policy{
		Paths: []internal.PathConfig{
			{
				Path:         "secret/restricted",
				Capabilities: []internal.Capability{internal.Create},
			},
			{
				Path:         "auth/approle/role/my-role/secret-id",
				Capabilities: []internal.Capability{internal.Create, internal.Update},
			},
		},
	}); diff != "" {
		t.Fatal(diff)
	}
}
