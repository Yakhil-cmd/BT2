### Title
Plaintext Validator Node Key Written with World-Readable Permissions (`os.ModePerm`) — (File: `cmd/kgen/main.go`)

---

### Summary

The `kgen` key-generation tool writes the plaintext hex-encoded ECDSA validator node private key — and a JSON file that embeds it verbatim — to disk using `os.ModePerm` (`0o777`). Any local user on the same host can read the key and impersonate the validator, sign state transitions, or disrupt consensus.

---

### Finding Description

`cmd/kgen/main.go` exposes `writeNodeKeyInfoToFile`, called when the operator runs `kgen --file`:

```go
// cmd/kgen/main.go L96-L120
func writeNodeKeyInfoToFile(validator *validatorInfo, parentDir string, nodekey string) error {
    parentPath := path.Join("", parentDir)
    err := os.MkdirAll(parentPath, os.ModePerm)          // 0o777 directory
    ...
    nodeKeyFilePath := path.Join(parentPath, "nodekey")
    if err = os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm); err != nil {  // 0o777 plaintext key
        return err
    }
    ...
    validatorInfoFilePath := path.Join(parentPath, "node_info.json")
    if err = os.WriteFile(validatorInfoFilePath, []byte(str), os.ModePerm); err != nil { // 0o777 JSON with Nodekey field
        return err
    }
```

`os.ModePerm` is `0o777` — world-readable, world-writable, world-executable. The `validatorInfo` struct serialised into `node_info.json` contains the `Nodekey` field, which is the raw hex private key:

```go
type validatorInfo struct {
    Address  common.Address
    Nodekey  string   // plaintext hex ECDSA private key
    NodeInfo string
}
```

Two files are therefore world-readable and contain the plaintext private key:
- `keys/nodekey` — raw hex
- `keys/node_info.json` — JSON with `"Nodekey": "<hex>"` field

The rest of the codebase correctly uses restrictive permissions for secret material. `crypto.SaveECDSA` uses `0o600`. `cmd/kcn/genkeys.go` uses `0o600` for every secret file. `cmd/utils/nodecmd/accountcmd.go` uses `0o600`. Only `cmd/kgen/main.go` uses `os.ModePerm`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

The `nodekey` is the ECDSA private key that:
1. Establishes the validator's P2P identity (`nodeId`)
2. Signs state transitions gated by `onlyNodeId` in system contracts (per `cmd/kcn/README.md`)
3. Is used to derive the BLS key when no explicit `bls-nodekey` is present (`node/config.go:BlsNodeKey`)

An attacker who reads the world-readable `keys/nodekey` or `keys/node_info.json` file can:
- Impersonate the validator node in P2P, hijacking its network identity
- Sign state transitions as the legitimate validator, enabling equivocation or invalid-block injection
- Derive the BLS consensus key (since `BlsNodeKey()` falls back to `bls.GenerateKey(crypto.FromECDSA(nodeKey))` when no separate BLS key file exists)

This constitutes **validator privilege escalation that changes protected chain state**. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

- **Trigger**: Any unprivileged local user on the validator host, or any process running under a different UID (e.g., a compromised service, a shared CI/CD runner, a container with a shared volume), can `cat keys/nodekey` or `cat keys/node_info.json` immediately after `kgen --file` is run.
- **No special privileges required**: The file is world-readable by construction.
- **Production path**: `kgen --file` is the documented key-generation workflow for Kaia validator onboarding.
- **Compounding factor**: `node_info.json` embeds the key in a structured JSON field, making automated extraction trivial.

---

### Recommendation

Replace `os.ModePerm` with `0o600` (owner read/write only) for both `os.MkdirAll` (use `0o700`) and `os.WriteFile` calls in `writeNodeKeyInfoToFile`:

```go
// Before (vulnerable)
os.MkdirAll(parentPath, os.ModePerm)
os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm)
os.WriteFile(validatorInfoFilePath, []byte(str), os.ModePerm)

// After (fixed)
os.MkdirAll(parentPath, 0o700)
os.WriteFile(nodeKeyFilePath, []byte(nodekey), 0o600)
os.WriteFile(validatorInfoFilePath, []byte(str), 0o600)
```

Additionally, consider whether `node_info.json` should embed the plaintext private key at all. The `Nodekey` field could be omitted from the JSON output and kept only in the separate `nodekey` file. [7](#0-6) 

---

### Proof of Concept

```bash
# Operator generates validator keys
$ kgen --file
Created :  keys/nodekey
Created :  keys/node_info.json

# Attacker (any local user) reads the plaintext private key
$ cat keys/nodekey
a3f1c2d4e5b6...   # 64-char hex ECDSA private key, no password required

$ cat keys/node_info.json
{
    "Address": "0x...",
    "Nodekey": "a3f1c2d4e5b6...",   # same plaintext key in JSON
    "NodeInfo": "kni://..."
}

# Verify world-readable permissions
$ ls -la keys/
-rwxrwxrwx  nodekey        # 0o777
-rwxrwxrwx  node_info.json # 0o777

# Attacker imports key and impersonates validator
$ kcn account import --datadir /tmp/attacker keys/nodekey
```

The attacker now holds the validator's ECDSA private key in plaintext, can sign state transitions as the legitimate validator, and — if no separate `bls-nodekey` file exists on the victim node — can also derive the BLS consensus key used for Randao/vrank participation. [8](#0-7) [9](#0-8)

### Citations

**File:** cmd/kgen/main.go (L39-43)
```go
type validatorInfo struct {
	Address  common.Address
	Nodekey  string
	NodeInfo string
}
```

**File:** cmd/kgen/main.go (L96-120)
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
}
```

**File:** cmd/kgen/main.go (L137-163)
```go
// genNodeKey creates a validator which is printed as json format or is stored into files(nodekey, validator).
func genNodeKey(ctx *cli.Context) error {
	pk, nk, addr, err := generateNodeInfoContents()
	if err != nil {
		return err
	}
	ip := ctx.String(ipFlag.Name)
	if net.ParseIP(ip).To4() == nil {
		return fmt.Errorf("IP address is not valid")
	}
	port := ctx.Uint(portFlag.Name)
	if port > 65535 {
		return fmt.Errorf("invalid port number")
	}
	nodeinfo := makeNodeInfo(addr, nk, pk, ip, uint16(port))
	if ctx.Bool(fileFlag.Name) {
		if err := writeNodeKeyInfoToFile(nodeinfo, dirKeys, nk); err != nil {
			return err
		}
	} else {
		str, err := json.MarshalIndent(nodeinfo, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(string(str))
	}
	return nil
```

**File:** crypto/crypto.go (L206-211)
```go
// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return os.WriteFile(file, []byte(k), 0o600)
}
```

**File:** cmd/kcn/genkeys.go (L139-144)
```go
	if err := writeFile(nodekeyHexPath, hex.EncodeToString(crypto.FromECDSA(nodeKey)), 0o600); err != nil {
		return err
	}

	// BLS -> raw hex in klay/, EIP-2335 keystore (+ .pass), and public pub/pop hex.
	if err := writeFile(blsNodekeyHexPath, hex.EncodeToString(blsKey.Marshal()), 0o600); err != nil {
```

**File:** node/config.go (L394-420)
```go
func (c *Config) BlsNodeKey() bls.SecretKey {
	// Manually set via flags --bls-nodekey or --bls-nodekeyhex
	if c.BlsKey != nil {
		return c.BlsKey
	}

	// Load from default location under datadir
	path := c.ResolvePath(DatadirBlsSecretKey)
	if key, err := bls.LoadKey(path); err == nil {
		return key
	}

	// No persistent key found, derive from NodeKey and store it
	key, err := bls.GenerateKey(crypto.FromECDSA(c.NodeKey()))
	if err != nil {
		logger.Crit("Failed to derive bls-nodekey from nodekey", "err", err)
	}
	instanceDir := filepath.Join(c.DataDir, c.name())
	if err := os.MkdirAll(instanceDir, 0o700); err != nil {
		logger.Crit("Failed to make dir to persist bls node key", "err", err)
	}
	keyfile := c.ResolvePath(DatadirBlsSecretKey)
	if err := bls.SaveKey(keyfile, key); err != nil {
		logger.Crit("Failed to persist bls node key", "err", err)
	}
	logger.Warn("Derived bls-nodekey from nodekey")
	return key
```

**File:** cmd/kcn/README.md (L89-89)
```markdown
| `nodekey` | node identity (p2p) + createNode `nodeId`; signs state transitions (onlyNodeId) |
```
