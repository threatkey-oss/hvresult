package internal_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	vault "github.com/hashicorp/vault/api"
	"github.com/threatkey-oss/hvresult/internal"
	"github.com/threatkey-oss/hvresult/internal/testcluster"
)

var (
	// this will probably change as Vault versions change but ehhhhhhh just edit it
	defaultPolicy = &internal.Policy{
		Name: "default",
		Paths: []internal.PathConfig{
			{
				Path:         "auth/token/lookup-self",
				Capabilities: []internal.Capability{internal.Read},
			},
			{
				Path:         "auth/token/renew-self",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "auth/token/revoke-self",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "cubbyhole/*",
				Capabilities: []internal.Capability{internal.Create, internal.Read, internal.Update, internal.Delete, internal.List},
			},
			{
				Path:         "identity/entity/id/{{identity.entity.id}}",
				Capabilities: []internal.Capability{internal.Read},
			},
			{
				Path:         "identity/entity/name/{{identity.entity.name}}",
				Capabilities: []internal.Capability{internal.Read},
			},
			{
				Path:         "identity/oidc/provider/+/authorize",
				Capabilities: []internal.Capability{internal.Read, internal.Update},
			},
			{
				Path:         "sys/capabilities-self",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/control-group/request",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/internal/ui/resultant-acl",
				Capabilities: []internal.Capability{internal.Read},
			},
			{
				Path:         "sys/leases/lookup",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/leases/renew",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/renew",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/tools/hash",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/tools/hash/*",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/wrapping/lookup",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/wrapping/unwrap",
				Capabilities: []internal.Capability{internal.Update},
			},
			{
				Path:         "sys/wrapping/wrap",
				Capabilities: []internal.Capability{internal.Update},
			},
		},
	}
)

var (
	CmpIgnoreOtherPath = cmp.FilterPath(func(p cmp.Path) bool {
		return p.String() == "Paths.Other"
	}, cmp.Ignore())
)

func TestProviderNoCache(t *testing.T) {
	ctx := context.Background()
	client := testcluster.NewTestCluster(t)
	pp, err := internal.NewReadthroughPolicyProvider("", client)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := pp.GetPolicy(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(policy, defaultPolicy, CmpIgnoreOtherPath); diff != "" {
		t.Fatal(diff)
	}
	// basic test of policy loading using the token auth mount
	t.Run("Token", func(t *testing.T) {
		t.Parallel()
		mustSecret := mustT[*vault.Secret](t)
		const policyName = "list-token-roles"
		// create a policy
		err := client.Sys().PutPolicy(policyName, `path "auth/token/roles" {
			capabilities = ["list"]
		}`)
		if err != nil {
			t.Fatal(err)
		}
		// create a token
		s := mustSecret(client.Auth().Token().Create(&vault.TokenCreateRequest{
			Policies: []string{policyName},
		}))
		pp.GetRSoP(ctx, s.Auth.ClientToken)
	})
}

// calls t.Fatal() on error
func mustT[T any](t *testing.T) func(T, error) T {
	return func(value T, err error) T {
		if err != nil {
			t.Fatal(t)
		}
		return value
	}
}
