package gitops_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/threatkey-oss/hvresult/internal/gitops"
)

// tests
func TestGenerateCapMap(t *testing.T) {
	// tests generation with git repository changes
	t.Run("GitRepository", func(t *testing.T) {
		tempGitDir, err := os.MkdirTemp("", "hvresult-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(tempGitDir) })
		// write an auth role and a policy
		var (
			authGCPRolesPath   = filepath.Join(tempGitDir, "auth", "gcp", "roles")
			sysPoliciesAclPath = filepath.Join(tempGitDir, "sys", "policies", "acl")
		)
		if err := os.MkdirAll(authGCPRolesPath, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(sysPoliciesAclPath, 0o750); err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(
			filepath.Join(authGCPRolesPath, "test"),
			generateRoleData(),
			0o640,
		)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(
			filepath.Join(sysPoliciesAclPath, "test"),
			generatePolicyACLData(),
			0o640,
		)
		if err != nil {
			t.Fatal(err)
		}
		git := gitops.Git{tempGitDir}
		must := mustT[string](t)
		must(git.CombinedOutput("init"))
		must(git.CombinedOutput("config", "user.email", "go-test@localhost"))
		must(git.CombinedOutput("config", "user.name", "Go Test"))
		must(git.CombinedOutput("config", "commit.gpgsign", "false"))
		must(git.CombinedOutput("add", "."))
		must(git.CombinedOutput("commit", "-m", "init"))
		// change branch
		must(git.CombinedOutput("checkout", "-b", "change"))
		// change the policy
		err = os.WriteFile(
			filepath.Join(sysPoliciesAclPath, "test"),
			generatePolicyACLData(),
			0o640,
		)
		if err != nil {
			t.Fatal(err)
		}
		must(git.CombinedOutput("add", "."))
		must(git.CombinedOutput("commit", "-m", "init"))
		changes, _, err := gitops.GetChangedFiles(
			context.Background(),
			tempGitDir,
			"",
		)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]gitops.ChangedFile{{
			Path:     filepath.Join("sys", "policies", "acl", "test"),
			Mutation: gitops.Change,
			Policy:   true,
		}}, changes); diff != "" {
			t.Fatal(diff)
		}
	})
}

func mustT[T any](t *testing.T) func(T, error) T {
	t.Helper()
	return func(thing T, err error) T {
		if err != nil {
			t.Log(thing)
			t.Fatal(err)
		}
		return thing
	}
}

func generateRoleData() []byte {
	var buf bytes.Buffer
	fmt.Fprintf(
		&buf,
		`{
			"token_policies": ["test-role-%d"]
		}`,
		time.Now().UnixMicro(),
	)
	return buf.Bytes()
}

func generatePolicyACLData() []byte {
	var buf bytes.Buffer
	fmt.Fprintf(
		&buf,
		`path "test/path/%d" {
			capabilities = ["read"]
		}`,
		time.Now().UnixMicro(),
	)
	return buf.Bytes()
}
