### Title
Node Private Key Files Written to Disk Unencrypted with World-Readable Permissions — (`File: cmd/util/cmd/common/utils.go`)

### Summary

The Flow bootstrap tooling writes all node private key material — staking keys, networking keys, random beacon keys, machine account keys, and the secrets-database encryption key — to the filesystem as plaintext (hex-encoded JSON) with `0644` file permissions. Any local user on the bootstrapping machine can read these files and steal the keys without any privilege escalation.

### Finding Description

`common.WriteText` and `common.WriteJSON` are the shared write primitives used by every bootstrap command that emits private key files. Both ultimately call `os.WriteFile(path, data, 0644)`. [1](#0-0) 

`0644` grants read access to the owning group **and** to all other users on the system (`others` read bit). The following sensitive files are all written through this path:

| File | Content | Written by |
|---|---|---|
| `node-info.priv.json` | Staking + networking private keys | `keyCmdRun` → `common.WriteJSON` |
| `random-beacon.priv.json` | Random beacon private key | `runBeaconKG` → `common.WriteJSON` |
| `secretsdb-key` | AES-256 secrets-DB encryption key | `keyCmdRun` → `common.WriteText` |
| `node-machine-account-key.priv.json` | Machine account private key | `keyCmdRun` → `common.WriteJSON` | [2](#0-1) [3](#0-2) 

The keys are stored as plaintext hex strings inside JSON — no encryption at rest is applied to the files themselves. The `secretsdb-key` is the AES-256 key that protects the secrets Badger database at runtime; it is itself stored unencrypted. [4](#0-3) 

By contrast, the observer networking key is correctly written with `0600` (owner-only): [5](#0-4) 

This inconsistency confirms the `0644` permission on the other files is unintentional.

### Impact Explanation

- **Random beacon key theft** (`random-beacon.priv.json`): The random beacon private key is a BLS key share used in the threshold signature scheme that produces the on-chain random source for each epoch. Stealing it allows an attacker to compute the node's contribution to the beacon, enabling prediction or manipulation of the epoch random source, which affects leader election, collector cluster assignment, and any Cadence contract that consumes `revertibleRandom()`.
- **Staking key theft** (`node-info.priv.json`): Allows the attacker to sign staking transactions on behalf of the node, including unstaking and withdrawing staked FLOW.
- **Networking key theft** (`node-info.priv.json`): Allows the attacker to impersonate the node on the libp2p network, injecting or suppressing messages.
- **Secrets-DB key theft** (`secretsdb-key`): The secrets database stores the runtime copy of the random beacon private key. Stealing the AES-256 key allows offline decryption of the entire secrets database.
- **Machine account key theft** (`node-machine-account-key.priv.json`): Allows draining the machine account's FLOW balance and submitting fraudulent protocol transactions.

### Likelihood Explanation

The bootstrapping tool is routinely run on shared infrastructure (CI servers, jump hosts, cloud VMs with multiple users). A `0644` file is readable by any process running as a different user on the same host — including unprivileged processes, monitoring agents, or a co-tenant in a multi-user environment. No exploit code is required; a simple `cat` of the file suffices. The attacker needs only local read access to the bootstrap output directory, which is a realistic assumption for shared machines.

### Recommendation

1. Change `os.WriteFile(path, data, 0644)` to `os.WriteFile(path, data, 0600)` in `common.WriteText` so that all files written through this path are owner-read-only by default.
2. Apply the same fix to `utils/io/write.go:WriteFile` and `utils/io/write.go:WriteText`, which also use `0644` and are used by other bootstrap paths.
3. Consider encrypting the private key files at rest (e.g., with a passphrase-derived key or hardware-backed key), analogous to how the secrets database itself is AES-256 encrypted at runtime. [6](#0-5) 

### Proof of Concept

```bash
# Operator runs bootstrap on a shared machine
go run ./cmd/bootstrap key --address "node.example.com:3569" --role "consensus" -o /tmp/bootstrap-out

# Any local user on the same machine can read the private key:
cat /tmp/bootstrap-out/private-root-information/private-node-info_<NodeID>/node-info.priv.json
# Output: {"Role":"consensus","Address":"...","NodeID":"...","NetworkPrivKey":"<hex>","StakingPrivKey":"<hex>"}

cat /tmp/bootstrap-out/private-root-information/private-node-info_<NodeID>/secretsdb-key
# Output: <32 bytes of AES-256 key in plaintext>

# Verify permissions
ls -la /tmp/bootstrap-out/private-root-information/private-node-info_<NodeID>/
# -rw-r--r-- node-info.priv.json        ← readable by all users
# -rw-r--r-- secretsdb-key              ← readable by all users
# -rw-r--r-- random-beacon.priv.json    ← readable by all users
``` [7](#0-6) [8](#0-7)

### Citations

**File:** cmd/util/cmd/common/utils.go (L67-89)
```go
func WriteJSON(path string, out string, data any) error {
	bz, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal json: %w", err)
	}

	return WriteText(path, out, bz)
}

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

**File:** cmd/bootstrap/cmd/key.go (L96-115)
```go
	// write files
	err = common.WriteText(model.PathNodeID, flagOutdir, []byte(nodeInfo.NodeID.String()))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to write file")
	}
	log.Info().Msgf("wrote file %s/%s", flagOutdir, model.PathNodeID)

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

**File:** cmd/bootstrap/cmd/dkg.go (L39-43)
```go
		err = common.WriteJSON(fmt.Sprintf(model.PathRandomBeaconPriv, nodeID), flagOutdir, encKey)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to write json")
		}
		log.Info().Msgf("wrote file %s/%s", flagOutdir, fmt.Sprintf(model.PathRandomBeaconPriv, nodeID))
```

**File:** model/bootstrap/filenames.go (L36-50)
```go
	FilenameRandomBeaconPriv         = "random-beacon.priv.json"
	FilenameSecretsEncryptionKey     = "secretsdb-key"
	PathPrivNodeInfoPrefix           = "node-info.priv."
	FilenameRootBlockVotePrefix      = "root-block-vote."
	FilenameClusterBlockVotePrefix   = "root-cluster-block-vote."
	PathRootDKGData                  = filepath.Join(DirPrivateRoot, "root-dkg-data.priv.json")
	PathNodeInfoPriv                 = filepath.Join(DirPrivateRoot, "private-node-info_%v", "node-info.priv.json")                 // %v will be replaced by NodeID
	PathNodeMachineAccountPrivateKey = filepath.Join(DirPrivateRoot, "private-node-info_%v", "node-machine-account-key.priv.json")  // %v will be replaced by NodeID
	PathNodeMachineAccountInfoPriv   = filepath.Join(DirPrivateRoot, "private-node-info_%v", "node-machine-account-info.priv.json") // %v will be replaced by NodeID
	PathRandomBeaconPriv             = filepath.Join(DirPrivateRoot, "private-node-info_%v", FilenameRandomBeaconPriv)              // %v will be replaced by NodeID
	PathNodeRootBlockVote            = filepath.Join(DirPrivateRoot, "private-node-info_%v", "root-block-vote.json")
	PathNodeRootClusterBlockVote     = filepath.Join(DirPrivateRoot, "private-node-info_%v", "root-cluster-block-vote.json") // %v will be replaced by NodeID
	FilenameRootBlockVote            = FilenameRootBlockVotePrefix + "%v.json"
	FilenameRootClusterBlockVote     = FilenameClusterBlockVotePrefix + "%v.json"
	PathSecretsEncryptionKey         = filepath.Join(DirPrivateRoot, "private-node-info_%v", FilenameSecretsEncryptionKey) // %v will be replaced by NodeID
```

**File:** cmd/bootstrap/cmd/observer_network_key.go (L73-75)
```go
	// write to file
	err = os.WriteFile(flagOutputFile, output, 0600)
	if err != nil {
```

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
