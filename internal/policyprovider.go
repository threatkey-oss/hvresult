package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/hashicorp/hcl/v2/hclsimple"
	vault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

var (
	ErrVaultClientRequired = errors.New("vault client required but not provided")
)

type PolicyProvider interface {
	// Reads and parses a policy.
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	// Generate a Resultant Set of Policy (RSoP) for a token, token accessor, or path to a Vault role definition.
	GetRSoP(ctx context.Context, principalThing string) (*RSoP, error)
}

// ReadthroughPolicyProvider is a readthrough cache of Vault policies.
type ReadthroughPolicyProvider struct {
	offlinePath string
	client      *vault.Client
}

// Reads a policy from Vault or the cache path.
func (p *ReadthroughPolicyProvider) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	if p.offlinePath != "" {
		policy, err := p.getOfflinePolicy(name)
		if err != nil || policy != nil {
			return policy, err
		}
	}
	if p.client == nil {
		return nil, fmt.Errorf("no Vault client specified, policy not found")
	}
	policyData, err := p.client.Sys().GetPolicyWithContext(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("error reading policy from Vault: %w", err)
	}
	policy, err := ParsePolicy(policyData, name)
	if err != nil {
		return nil, err
	}
	if p.offlinePath != "" {
		// TODO: good way to handle errors caching policies
		_ = p.cachePolicy(name, policyData)
	}
	return policy, nil
}

func (p *ReadthroughPolicyProvider) getOfflinePolicy(name string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Join(p.offlinePath, name))
	if err != nil {
		return nil, fmt.Errorf("error reading cached policy: %w", err)
	}
	var policy *Policy
	if err = hclsimple.Decode(name, data, nil, &policy); err != nil {
		return nil, fmt.Errorf("error decoding cached policy: %w", err)
	}
	return policy, nil
}

func (p *ReadthroughPolicyProvider) cachePolicy(name, data string) error {
	return os.WriteFile(filepath.Join(p.offlinePath, name), []byte(data), 0o640)
}

type logicalPolicyData struct {
	Policies      []string `mapstructure:"policies"`
	TokenPolicies []string `mapstructure:"token_policies"`
}

func (p *ReadthroughPolicyProvider) GetRSoP(ctx context.Context, authThing string) (*RSoP, error) {
	if p.client == nil {
		return nil, ErrVaultClientRequired
	}
	ak, err := GuessAuthKind(authThing)
	if err != nil {
		return nil, err
	}
	var policyNames []string
	switch ak {
	case Token:
		var s *vault.Secret
		// if this happens to be our own token, then lookup self
		if authThing == p.client.Token() {
			s, err = p.client.Auth().Token().LookupSelfWithContext(ctx)
			if err != nil {
				return nil, fmt.Errorf("error looking up self: %w", err)
			}
		} else {
			// errors out without sudo/root
			s, err = p.client.Auth().Token().LookupWithContext(ctx, authThing)
			if err != nil {
				return nil, fmt.Errorf("error looking up token: %w", err)
			}
		}
		var data logicalPolicyData
		if err := mapstructure.Decode(s.Data, &data); err != nil {
			return nil, fmt.Errorf("error decoding token lookup data: %w", err)
		}
		policyNames = data.Policies
	case TokenAccessor:
		s, err := p.client.Auth().Token().LookupAccessorWithContext(ctx, authThing)
		if err != nil {
			return nil, fmt.Errorf("error looking up token accessor: %w", err)
		}
		policyNames = s.Auth.Policies
	case RolePathMaybe:
		s, err := p.client.Logical().ReadWithContext(ctx, authThing)
		if err != nil {
			return nil, fmt.Errorf("error reading guessed role path: %w", err)
		}
		if s.Data == nil || s.Data["token_policies"] == nil {
			return nil, fmt.Errorf(".data.token_policies not present in guessed role path")
		}
		var data logicalPolicyData
		if err := mapstructure.Decode(s.Data, &data); err != nil {
			return nil, fmt.Errorf("error decoding guessed role path data: %w", err)
		}
		policyNames = data.TokenPolicies
	default:
		return nil, fmt.Errorf("unhandled AuthKind: %s (%d)", ak.String(), ak)
	}
	policies := make([]*Policy, len(policyNames))
	for i, name := range policyNames {
		policies[i], err = p.GetPolicy(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("error getting policy '%s': %w", name, err)
		}
		policies[i].Name = name
	}
	// sort
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})
	return &RSoP{Policies: policies}, nil
}

// ReadthroughPolicyProvider is a readthrough cache of Vault policies.
func NewReadthroughPolicyProvider(offlinePath string, client *vault.Client) (PolicyProvider, error) {
	pp := &ReadthroughPolicyProvider{
		offlinePath: offlinePath,
		client:      client,
	}
	return pp, nil
}
