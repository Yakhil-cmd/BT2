### Title
Bootstrap Private Key Files Written with World-Readable Permissions (0644), No Permission Check on Load - (File: `utils/io/write.go`)

---

### Summary

The Flow bootstrap tooling writes all sensitive private key material — node staking/networking keys, machine account private keys, secrets DB encryption keys, and random beacon private keys — to disk using `0644` (world-readable) file permissions. No permission check is performed when these files are loaded at node startup. Any unprivileged local user on the same host can read the key material and use it to impersonate the node on the p2p network or control the node's on-chain machine account.

---

### Finding Description

`utils/io/write.go` defines the central `WriteFile` function used throughout the bootstrap pipeline:

```go
err = os.WriteFile(path, data, 0644)
```

`0644` grants read access to group and world. This function is called by `WriteJSON` (same file), which is the write path for every private key file produced during bootstrapping.

`cmd/util/cmd/common/utils.go` has an identical issue in its own `WriteText`:

```go
err = os.WriteFile(path, data, 0644)
```

`WriteJSON` in the same file delegates to `WriteText`, so both JSON and raw-byte private key files are affected.

The affected key files written with `0644`:

| Key file | Written via |
|---|---|
| `<nodeID>.node-info.priv.json` (staking + networking keys) | `common.WriteJSON` → `common.WriteText` |
| `<nodeID>.secrets-encryption.key` (secrets DB AES-256 key) | `common.WriteText` |
| `<nodeID>.node-machine-account-key.priv.json` | `common.WriteJSON` → `common.WriteText` |
| `<nodeID>.random-beacon.priv.json` | `utils/io.WriteJSON` → `utils/io.WriteFile` |

The contrast with correctly-handled keys is clear: `cmd/bootstrap/cmd/observer_network_key.go` uses `0600` for the observer networking key, and `cmd/bootstrap/cmd/access_keygen.go` uses `0600` for TLS keys. The main bootstrap key files are the outliers.

When the node starts, `cmd/scaffold.go` calls `LoadPrivateNodeInfo`, `loadSecretsEncryptionKey`, and `LoadNetworkPrivateKey` — none of which check the file's permission bits before reading.

---

### Impact Explanation

An unprivileged local user on the same host (or anyone with access to a backup of the bootstrap directory) can read:

- **Networking private key** → impersonate the node on the Flow p2p network, forge authenticated network messages, disrupt the node's peer identity.
- **Machine account private key** → submit on-chain transactions from the node's machine account (used by Collection and Consensus nodes for protocol-level submissions).
- **Secrets DB encryption key** → decrypt the secrets database, which contains the random beacon private key. Possession of the random beacon private key allows the attacker to produce fraudulent threshold-signature shares for that node's epoch.

The secrets DB encryption key path is the most severe: it is a symmetric AES-256 key stored in a world-readable plaintext file, and it protects the random beacon private key that underpins consensus safety.

---

### Likelihood Explanation

Any multi-user Linux/macOS system running a Flow node is affected by default. The `0644` mode is the standard `os.WriteFile` default and requires no misconfiguration by the operator. Backup systems (rsync, tar, cloud snapshots) that preserve file contents but not ACLs will expose the key material to anyone with access to the backup. The bootstrap directory is explicitly documented as a required artifact that must be retained across restarts, increasing the attack surface window.

---

### Recommendation

- Change `os.WriteFile(path, data, 0644)` to `os.WriteFile(path, data, 0600)` in both `utils/io/write.go` and `cmd/util/cmd/common/utils.go` for all private key and secret material writes.
- At node startup, check the permission bits of each loaded private key file (analogous to OpenSSH's private key permission check) and refuse to start — or at minimum emit a fatal warning — if the file is group- or world-readable.
- Audit the parent directory permissions (`0755` in `os.MkdirAll`) for directories that contain only private key files; `0700` is appropriate.

---

### Proof of Concept

```bash
# After running: go run ./cmd/bootstrap key --role=consensus ...
$ ls -la ./bootstrap/private-root-information/private-node-info_<nodeID>/
-rw-r--r-- 1 operator operator  ... <nodeID>.node-info.priv.json
-rw-r--r-- 1 operator operator  ... <nodeID>.secrets-encryption.key

# Any local user can read the secrets DB encryption key:
$ cat ./bootstrap/private-root-information/private-node-info_<nodeID>/<nodeID>.secrets-encryption.key
<hex-encoded AES-256 key>

# And the staking + networking private keys:
$ cat ./bootstrap/private-root-information/private-node-info_<nodeID>/<nodeID>.node-info.priv.json
{ "Role": "consensus", "NetworkPrivKey": "...", "StakingPrivKey": "..." }
```

The root cause is `os.WriteFile(path, data, 0644)` in `utils/io/write.go` and `cmd/util/cmd/common/utils.go`, called unconditionally for all private key material with no subsequent permission check on load. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** utils/io/write.go (L14-26)
```go
func WriteFile(path string, data []byte) error {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return fmt.Errorf("could not create output dir: %w", err)
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("could not write file: %w", err)
	}

	return nil
}
```

**File:** cmd/util/cmd/common/utils.go (L76-89)
```go
func WriteText(path string, out string, data []byte) error {
	path = filepath.Join(out, path)

	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return fmt.Errorf("could not create output dir: %w", err)
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("could not write file: %w", err)
	}
	return nil
}
```

**File:** cmd/bootstrap/cmd/key.go (L103-115)
```go
	privKeyPath := fmt.Sprintf(model.PathNodeInfoPriv, nodeInfo.NodeID)
	err = common.WriteJSON(privKeyPath, flagOutdir, private)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to write json")
	}
	log.Info().Msgf("wrote file %s/%s", flagOutdir, privKeyPath)

	secretsKeyPath := fmt.Sprintf(model.PathSecretsEncryptionKey, nodeInfo.NodeID)
	err = common.WriteText(secretsKeyPath, flagOutdir, secretsDBKey)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to write file")
	}
	log.Info().Msgf("wrote file %s/%s", flagOutdir, secretsKeyPath)
```

**File:** cmd/bootstrap/cmd/observer_network_key.go (L74-74)
```go
	err = os.WriteFile(flagOutputFile, output, 0600)
```

**File:** cmd/bootstrap/cmd/access_keygen.go (L84-87)
```go
	err = os.WriteFile(flagOutputKeyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}), 0600)
```

**File:** cmd/bootstrap/utils/key_generation.go (L266-284)
```go
// WriteSecretsDBEncryptionKeyFiles writes secret db encryption keys to private
// node info directory.
func WriteSecretsDBEncryptionKeyFiles(nodeInfos []bootstrap.NodeInfo, write WriteFileFunc) error {

	for _, nodeInfo := range nodeInfos {

		// generate an encryption key for the node
		encryptionKey, err := GenerateSecretsDBEncryptionKey()
		if err != nil {
			return err
		}

		path := fmt.Sprintf(bootstrap.PathSecretsEncryptionKey, nodeInfo.NodeID)
		err = write(path, encryptionKey)
		if err != nil {
			return err
		}
	}
	return nil
```

**File:** cmd/utils.go (L77-86)
```go
// loadSecretsEncryptionKey loads the encryption key for the secrets database.
// If the file does not exist, returns os.ErrNotExist.
func loadSecretsEncryptionKey(dir string, myID flow.Identifier) ([]byte, error) {
	path := filepath.Join(dir, fmt.Sprintf(bootstrap.PathSecretsEncryptionKey, myID))
	data, err := io.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read secrets db encryption key (path=%s): %w", path, err)
	}
	return data, nil
}
```
