package testcluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type devClusterInfo struct {
	Nodes []struct {
		ApiAddress string `json:"api_address"`
	}
	RootToken string `json:"root_token"`
}

var mutex sync.Mutex

// Creates a test cluster using whatever `vault` binary it finds in $PATH.
func NewTestCluster(t *testing.T) *vault.Client {
	t.Helper()
	if !mutex.TryLock() {
		t.Log("waiting in line for NewTestCluster mutex")
		mutex.Lock()
	}
	tempDir, err := os.MkdirTemp("", "vtd-*")
	if err != nil {
		t.Fatalf("error creating temporary directory: %v", err)
	}
	t.Cleanup(func() {
		mutex.Unlock()
		os.RemoveAll(tempDir)
	})
	clusterJsonPath := filepath.Join(tempDir, "test-cluster.json")
	cmd := exec.Command("vault", "server", "-dev", "-dev-cluster-json="+clusterJsonPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("error starting vault: %v", err)
	}
	// TODO: any handling whatsoever if the command fails
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil {
			fmt.Printf("error killing vault server: %v", err)
		}
	})
	// wait for test-cluster.json to exist
	for i := 0; i < 100; i++ {
		data, err := os.ReadFile(clusterJsonPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				time.Sleep(time.Millisecond * 100)
				continue
			} else {
				t.Fatal(err)
			}
		}
		var clusterInfo devClusterInfo
		if err := json.Unmarshal(data, &clusterInfo); err != nil {
			t.Fatalf("error unmarshalling dev cluster info: %v", err)
		}
		cfg := vault.DefaultConfig()
		cfg.Address = clusterInfo.Nodes[0].ApiAddress
		client, err := vault.NewClient(cfg)
		if err != nil {
			t.Fatalf("error calling vault.NewClient: %v", err)
		}
		client.SetToken(clusterInfo.RootToken)
		return client
	}
	t.Fatal("timed out waiting for Vault dev server to start")
	return nil
}
