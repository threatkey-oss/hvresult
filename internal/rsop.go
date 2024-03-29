package internal

import (
	"bytes"
	"strings"
	"text/template"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/rs/zerolog"
)

// Resultant Set of Policy, or "what a token can do".
//
// This struct is basically a container for functions that operate on a slice of Policy objects.
type RSoP struct {
	// Policies should be a slice sorted by Policy.Name.
	Policies []*Policy

	// generated by GetCapabilityMap
	// preemptions map[string]CapabilityPreemption
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler.
func (r *RSoP) MarshalZerologObject(e *zerolog.Event) {
	arr := zerolog.Arr()
	for _, p := range r.Policies {
		arr.Object(p)
	}
	e.Array("Policies", arr)
}

// GetCapabilityMap generates a map of path -> capability -> policies that grant it.
//
// It essentially inverts each Policy.
func (r *RSoP) GetCapabilityMap() RSoPCapMap {
	capmap := make(map[string]map[Capability][]string)
	// 1st pass: slam them all into the data structure
	for i := range r.Policies {
		policy := r.Policies[i]
		for j := range policy.Paths {
			path := policy.Paths[j]
			if capmap[path.Path] == nil {
				capmap[path.Path] = make(map[Capability][]string)
			}
			for k := range path.Capabilities {
				cap := path.Capabilities[k]
				capmap[path.Path][cap] = append(capmap[path.Path][cap], policy.Name)
			}
		}
	}
	// 2nd pass: effect deny by deleting other declarations
	for path, caps := range capmap {
		if len(caps) > 1 {
			if deniers := caps[Deny]; len(deniers) > 0 {
				// TODO: catalog preempted
				capmap[path] = map[Capability][]string{
					Deny: deniers,
				}
			}
		}
	}
	return capmap
}

const rsopPolicyTemplateRaw = `
{{- range $path, $capabilities := .}}
path "{{ $path }}" {
	capabilities = [
	{{- range $cap, $policies := $capabilities }}
		"{{ $cap }}", # from: {{ join $policies ", " -}}
	{{ end }}
	]
}
{{ end }}`

var (
	rsopPolicyTemplate = template.Must(
		template.New("policyPath").
			Funcs(template.FuncMap{"join": join}).
			Parse(strings.TrimSpace(rsopPolicyTemplateRaw)),
	)
)

// used in the template above
func join(elems []string, sep string) string {
	return strings.Join(elems, sep)
}

// A map of path -> capabilities -> policies that grant it.
type RSoPCapMap map[string]map[Capability][]string

// Emits as HCL with inline comments of the responsible policies.
func (r RSoPCapMap) HCL() string {
	var buf bytes.Buffer
	buf.WriteString("# generated by hvresult\n")
	if err := rsopPolicyTemplate.Execute(&buf, r); err != nil {
		panic(err)
	}
	formatted := hclwrite.Format(buf.Bytes())
	return string(formatted)
}

var (
	_ zerolog.LogObjectMarshaler = &RSoP{}
)
