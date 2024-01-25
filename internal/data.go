package internal

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/rs/zerolog"
)

// Policy represents a Vault policy document.
type Policy struct {
	// The name of the policy in Vault - this attribute is not in the document.
	Name string `hcl:",optional"`
	// All of the path {} declarations. These should be sorted by PathConfig.Path, ascending.
	Paths []PathConfig `hcl:"path,block"`
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler.
func (p Policy) MarshalZerologObject(e *zerolog.Event) {
	e.Str("Name", p.Name)
	arr := zerolog.Arr()
	for _, p := range p.Paths {
		arr.Object(p)
	}
	e.Array("Paths", arr)
}

// PathConfig represents a Vault path block
type PathConfig struct {
	Path         string       `hcl:"path,label"`
	Capabilities []Capability `hcl:"capabilities"`

	// Captures other arguments we don't care about yet.
	// https://github.com/hashicorp/vault/blob/9bb4f9e996eb6d35617a0624f2c1232e25d75f3c/vault/policy.go#L129-L147
	Other hcl.Body `hcl:",remain"`
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler.
func (p PathConfig) MarshalZerologObject(e *zerolog.Event) {
	e.Str("Path", p.Path)
	e.Any("Capabilities", p.Capabilities)
}

// ParsePolicy creates a Policy object and sorts by path.
func ParsePolicy(policyData, name string) (*Policy, error) {
	var policy Policy
	if err := hclsimple.Decode(name+".hcl", []byte(policyData), nil, &policy); err != nil {
		return nil, fmt.Errorf("error parsing policy HCL: %w", err)
	}
	// sort by path
	sort.Slice(policy.Paths, func(i, j int) bool {
		return policy.Paths[i].Path < policy.Paths[j].Path
	})
	policy.Name = name
	return &policy, nil
}

type ControlGroup struct {
	TTL     any
	Factors map[string]any
}

// Capabilities declare what a token can do to a path.
//
// https://developer.hashicorp.com/vault/docs/concepts/policies#capabilities
type Capability string

const (
	Create    Capability = "create"
	Read      Capability = "read"
	Update    Capability = "update"
	Delete    Capability = "delete"
	List      Capability = "list"
	Sudo      Capability = "sudo"
	Deny      Capability = "deny"
	Subscribe Capability = "subscribe"
)

// For use with `sort.Slice()`.
func (c Capability) Less(other Capability) bool {
	switch c {
	case Create:
		return other != Create
	case Read:
		return contains(other, Update, Delete, List, Sudo, Deny, Subscribe)
	case Update:
		return contains(other, Delete, List, Sudo, Deny, Subscribe)
	case Delete:
		return contains(other, List, Sudo, Deny, Subscribe)
	case List:
		return contains(other, Sudo, Deny, Subscribe)
	case Sudo:
		return contains(other, Deny, Subscribe)
	case Deny, Subscribe:
		return other != Subscribe
	}
	panic(fmt.Sprintf("unsupported comparison capability: '%s'", other))
}

func contains[T comparable](needle T, haystack ...T) bool {
	for _, item := range haystack {
		if needle == item {
			return true
		}
	}
	return false
}

var (
	_ zerolog.LogObjectMarshaler = Policy{}
	_ zerolog.LogObjectMarshaler = PathConfig{}
)
