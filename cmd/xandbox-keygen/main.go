package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/123123213weqw/Xandbox/internal/access"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	tenant := flag.String("tenant", "", "tenant ID (required)")
	quota := flag.Int("max-instances", 4, "tenant instance quota, including reclamation")
	tokenFile := flag.String("token-file", "", "new private client token file (required)")
	configFile := flag.String("config-file", "", "new server digest configuration file (required)")
	flag.Parse()
	if *tokenFile == "" || *configFile == "" || *tokenFile == *configFile || flag.NArg() != 0 {
		return fmt.Errorf("usage: xandbox-keygen -tenant NAME -token-file NEW_PATH -config-file NEW_PATH [-max-instances 4]")
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	token := "xb_" + base64.RawURLEncoding.EncodeToString(entropy[:])
	digest := sha256.Sum256([]byte(token))
	config := access.Config{Version: 1, Keys: []access.Key{{
		TokenSHA256: hex.EncodeToString(digest[:]), TenantID: *tenant, MaxInstances: *quota,
	}}}
	if _, err := access.New(config); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(*tokenFile, []byte(token+"\n")); err != nil {
		return err
	}
	if err := writeNew(*configFile, append(data, '\n')); err != nil {
		os.Remove(*tokenFile)
		return err
	}
	fmt.Println("Created private token and digest-only authentication configuration; existing files were not overwritten.")
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
