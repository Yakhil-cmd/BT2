### Title
Validator Nodekey Written with World-Readable Permissions (`os.ModePerm` / 0o777) — (`File: cmd/kgen/main.go`)

---

### Summary

The `kgen` key-generation tool writes the raw hex-encoded ECDSA validator nodekey to disk with `os.ModePerm` (0o777), making it world-readable and world-writable by every local user. The companion `node_info.json` file, which also embeds the nodekey, is written with the same insecure permission. Any unprivileged local user can read the nodekey in the window between file creation and any later manual permission hardening, or simply read it at any time afterward.

---

### Finding Description

In `cmd/kgen/main.go`, the function `writeNodeKeyInfoToFile` writes two files:

```go
// cmd/kgen/main.go:103-116
nodeKeyFilePath := path.Join(parentPath, "nodekey")
if err = os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm); err != nil {
    return err
}
...
validatorInfoFilePath := path.Join(parentPath, "node_info.json")
if err = os.WriteFile(validatorInfoFilePath, []byte(str), os.ModePerm); err != nil {
    return err
}
```

`os.ModePerm` is `0o777`. Both files are created world-readable and world-writable from the moment of creation. The `nodekey` variable is the raw hex-encoded secp256k1 private key of the validator. [1](#0-0) 

The `validatorInfo` struct that is marshalled into `node_info.json` explicitly includes the `Nodekey` field: [2](#0-1) 

By contrast, the newer `cmd/kcn/genkeys.go` `writeFile` helper correctly uses caller-supplied permissions (e.g., `0o600`) for every secret file it creates: [3](#0-2) 

The `accounts/keystore` package also correctly uses `os.CreateTemp` (which assigns mode `0600`) followed by an atomic rename, never exposing key material at a world-readable path: [4](#0-3) 

`kgen` does neither: it calls `os.WriteFile` with `os.ModePerm` directly, with no subsequent `chmod`.

---

### Impact Explanation

The nodekey is the validator's secp256k1 private key. In Kaia's Istanbul BFT:

- The validator's on-chain identity (registered in the AddressBook / KIP-113 system contracts) is the Ethereum address derived from this key.
- The key is used to sign P2P handshakes, block proposals, and IBFT consensus messages (PREPREPARE / PREPARE / COMMIT).

An attacker who obtains the nodekey can:

1. **Impersonate the validator** in P2P, causing the legitimate node to be eclipsed or forked off.
2. **Sign consensus messages** as the legitimate validator, enabling equivocation (double-signing), which can cause consensus divergence on honest nodes.
3. **Propose and sign blocks** as the legitimate validator, enabling unauthorized block production.

This satisfies the allowed impact gate: *"validator privilege escalation that changes protected chain state"* and *"invalid block/proof acceptance or consensus divergence on honest nodes."*

---

### Likelihood Explanation

- The `kgen` tool is the documented way to generate a Kaia validator nodekey (`kgen --file --ip ... --port ...`).
- The resulting `keys/nodekey` file is created world-readable (`0o777`) on every invocation.
- Any unprivileged local user (e.g., another service account, a compromised CI runner, a shared-host tenant) can `cat keys/nodekey` immediately after generation.
- No race window is required: the file remains world-readable indefinitely unless the operator manually corrects permissions.
- The `node_info.json` file provides a second, equally accessible copy of the same key material.

---

### Recommendation

Replace `os.ModePerm` with `0o600` (owner read/write only) in both `os.WriteFile` calls inside `writeNodeKeyInfoToFile`:

```go
// Before (insecure)
os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm)
os.WriteFile(validatorInfoFilePath, []byte(str), os.ModePerm)

// After (secure)
os.WriteFile(nodeKeyFilePath, []byte(nodekey), 0o600)
os.WriteFile(validatorInfoFilePath, []byte(str), 0o600)
```

Additionally, consider removing the `Nodekey` field from `validatorInfo` / `node_info.json` entirely, since the address and NodeInfo (enode URL) are sufficient for node registration and the raw private key should never appear in a JSON file.

---

### Proof of Concept

```bash
# Terminal 1 (validator operator)
kgen --file --ip 1.2.3.4 --port 32323
# Creates keys/nodekey with permissions 0o777

# Terminal 2 (unprivileged attacker on the same host)
cat keys/nodekey
# Prints the raw hex private key, e.g.:
# 8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63

# Attacker reconstructs the private key and signs IBFT messages as the validator
```

The file is readable without any race condition because `os.WriteFile` with `os.ModePerm` creates the file world-readable from the first byte written, and the permission is never subsequently restricted. [5](#0-4)

### Citations

**File:** cmd/kgen/main.go (L39-43)
```go
type validatorInfo struct {
	Address  common.Address
	Nodekey  string
	NodeInfo string
}
```

**File:** cmd/kgen/main.go (L96-119)
```go
func writeNodeKeyInfoToFile(validator *validatorInfo, parentDir string, nodekey string) error {
	parentPath := path.Join("", parentDir)
	err := os.MkdirAll(parentPath, os.ModePerm)
	if err != nil {
		return err
	}

	nodeKeyFilePath := path.Join(parentPath, "nodekey")
	if err = os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm); err != nil {
		return err
	}
	fmt.Println("Created : ", nodeKeyFilePath)

	str, err := json.MarshalIndent(validator, "", "\t")
	if err != nil {
		return err
	}
	validatorInfoFilePath := path.Join(parentPath, "node_info.json")
	if err = os.WriteFile(validatorInfoFilePath, []byte(str), os.ModePerm); err != nil {
		return err
	}

	fmt.Println("Created : ", validatorInfoFilePath)
	return nil
```

**File:** cmd/kcn/genkeys.go (L55-60)
```go
func writeFile(path, content string, perm os.FileMode) error {
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
```

**File:** accounts/keystore/key.go (L276-296)
```go
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), err
}

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
```
