### Title
Validator Node Private Key Written to Filesystem in Plaintext with World-Readable Permissions - (`cmd/kgen/main.go`)

### Summary

The `kgen` key-generation tool writes the validator ECDSA node private key (`nodekey`) to disk as an unencrypted hex string with `os.ModePerm` (0o777 — world-readable/writable). The same private key is also embedded inside `node_info.json` (also written with `os.ModePerm`). Any local user or process on the machine can read the file and steal the key. The `homi` setup tool (`cmd/homi/setup/cmd.go`) repeats the same pattern for every CN/PN validator key it generates.

### Finding Description

`cmd/kgen/main.go` `writeNodeKeyInfoToFile()` writes the raw hex private key to two files with no encryption and no access restriction:

```go
// cmd/kgen/main.go L103-L114
nodeKeyFilePath := path.Join(parentPath, "nodekey")
if err = os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm); err != nil {
    return err
}
// ...
str, err := json.MarshalIndent(validator, "", "\t")   // validator.Nodekey = private key hex
// ...
if err = os.WriteFile(validatorInfoFilePath, []byte(str), os.ModePerm); err != nil {
    return err
}
```

`os.ModePerm` is `0o777`. The `validatorInfo` struct embeds the raw private key string in the `Nodekey` field, so `node_info.json` also leaks it. [1](#0-0) 

`cmd/homi/setup/cmd.go` `writeValidatorsAndNodesToFile()` repeats the same pattern for every CN/PN validator:

```go
// cmd/homi/setup/cmd.go L1360-1361
nodeKeyFilePath := path.Join(parentPath, "nodekey"+strconv.Itoa(i+1))
os.WriteFile(nodeKeyFilePath, []byte(nodekeys[i]), os.ModePerm)
``` [2](#0-1) 

`writeCNInfoKey()` and `writePNInfoKey()` also call `WriteFile([]byte(nodeKeys[i]), parentDir, "nodekey")` with the global `WriteFile` helper that uses `os.ModePerm`: [3](#0-2) [4](#0-3) 

By contrast, the newer `kcn valops generate-keys` command correctly uses `0o600` for the same nodekey file: [5](#0-4) 

### Impact Explanation

The nodekey is the validator's primary ECDSA identity key. Per the README and codebase:

- It is the `nodeId` used in `createNode` (validator registration).
- It is the key that must sign all `onlyNodeId`-gated validator state transitions: `ready-candidate`, `ready-validator`, `pause`, `resume`, `exit`, `offboard`.
- It controls the validator's participation in consensus (Istanbul BFT proposer/voter selection). [6](#0-5) 

An attacker who steals the nodekey can:
1. Impersonate the validator in P2P.
2. Submit signed `onlyNodeId` transactions to manipulate the validator's on-chain state (e.g., force-exit the validator from the active set, redirect reward address, or re-register with attacker-controlled parameters).
3. Disrupt consensus by removing an honest validator from the active set.

This is a **validator privilege escalation** that directly changes protected chain state and asset ownership (reward routing).

### Likelihood Explanation

`kgen` is a production key-generation tool run by node operators on shared or multi-user machines. `os.ModePerm` (0o777) makes the nodekey file readable by every user and every process on the host. Any co-tenant, cron job, log collector, or monitoring agent with filesystem access can read the key without any privilege escalation. The `node_info.json` file doubles the exposure by embedding the same private key in a JSON structure that is even more likely to be copied, backed up, or transmitted.

### Recommendation

1. Replace `os.ModePerm` with `0o600` in all key-writing calls in `cmd/kgen/main.go` and `cmd/homi/setup/cmd.go`.
2. Remove the `Nodekey` field from the `validatorInfo` struct (or zero it before marshalling to `node_info.json`) so the private key is never embedded in the JSON output file.
3. Consider encrypting the nodekey at rest (as `kcn valops generate-keys` already does via the v3 keystore + `.pass` pattern) and only writing the raw hex form with `0o400` (read-only by owner).

### Proof of Concept

```bash
# Operator generates keys on a shared machine
kgen --file --ip 1.2.3.4 --port 32323

# Attacker (any local user) reads the world-readable file
cat keys/nodekey          # prints raw ECDSA private key hex
cat keys/node_info.json   # also contains "Nodekey": "<private key hex>"

# Attacker uses stolen key to sign onlyNodeId validator operations
kcn valops exit --private-key <stolen_hex> --endpoint http://victim-node:8551
# Result: victim validator is force-exited from the active set
```

The same attack applies to every CN/PN nodekey written by `homi setup` via `writeValidatorsAndNodesToFile`, `writeCNInfoKey`, and `writePNInfoKey`. [7](#0-6) [8](#0-7)

### Citations

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

**File:** cmd/homi/setup/cmd.go (L1015-1041)
```go
func writeCNInfoKey(num int, nodeAddrs []common.Address, nodeKeys []string, privKeys []*ecdsa.PrivateKey,
	genesisJsonBytes []byte,
) {
	const DirCommon = "common"
	WriteFile(genesisJsonBytes, DirCommon, "genesis.json")

	validators := makeValidatorsWithIp(num, false, nodeAddrs, nodeKeys, privKeys, []string{CNIpNetwork})
	staticNodesJsonBytes, _ := json.MarshalIndent(filterNodeInfo(validators), "", "\t")
	WriteFile(staticNodesJsonBytes, DirCommon, "static-nodes.json")

	for i, v := range validators {
		parentDir := fmt.Sprintf("cn%02d", i+1)
		WriteFile([]byte(nodeKeys[i]), parentDir, "nodekey")
		str, _ := json.MarshalIndent(v, "", "\t")
		WriteFile([]byte(str), parentDir, "validator")
	}
}

func writePNInfoKey(num int) {
	privKeys, nodeKeys, nodeAddrs := istcommon.GenerateKeys(num)
	validators := makeValidatorsWithIp(num, false, nodeAddrs, nodeKeys, privKeys, []string{PNIpNetwork1, PNIpNetwork2})
	for i, v := range validators {
		parentDir := fmt.Sprintf("pn%02d", i+1)
		WriteFile([]byte(nodeKeys[i]), parentDir, "nodekey")
		str, _ := json.MarshalIndent(v, "", "\t")
		WriteFile([]byte(str), parentDir, "validator")
	}
```

**File:** cmd/homi/setup/cmd.go (L1355-1368)
```go
func writeValidatorsAndNodesToFile(validators []*ValidatorInfo, parentDir string, nodekeys []string) {
	parentPath := path.Join(outputPath, parentDir)
	os.MkdirAll(parentPath, os.ModePerm)

	for i, v := range validators {
		nodeKeyFilePath := path.Join(parentPath, "nodekey"+strconv.Itoa(i+1))
		os.WriteFile(nodeKeyFilePath, []byte(nodekeys[i]), os.ModePerm)
		fmt.Println("Created : ", nodeKeyFilePath)

		str, _ := json.MarshalIndent(v, "", "\t")
		validatorInfoFilePath := path.Join(parentPath, "validator"+strconv.Itoa(i+1))
		os.WriteFile(validatorInfoFilePath, []byte(str), os.ModePerm)
		fmt.Println("Created : ", validatorInfoFilePath)
	}
```

**File:** cmd/homi/setup/cmd.go (L1389-1394)
```go
func WriteFile(content []byte, parentFolder string, fileName string) {
	filePath := path.Join(outputPath, parentFolder, fileName)
	os.MkdirAll(path.Dir(filePath), os.ModePerm)
	os.WriteFile(filePath, content, os.ModePerm)
	fmt.Println("Created : ", filePath)
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

**File:** cmd/kcn/README.md (L86-97)
```markdown

| Key | Role |
|-----|------|
| `nodekey` | node identity (p2p) + createNode `nodeId`; signs state transitions (onlyNodeId) |
| `bls-nodekey` | consensus BLS (randao/vrank) + createNode `blsInfo` (pub/pop) |
| `manager` | deploys CnStaking, stakes, and sends createNode (becomes NodeInfo.manager); holds ≥ 5M KAIA |
| `cnstaking-owner` | owner of the deployed CnStaking |
| `voter` | createNode `voterAddress` (on-chain governance) |
| `reward` | createNode `rewardAddress` (unused when PublicDelegation is enabled) |
| `mev-reward` | reward recipient for the auction (MEV) contract; not a createNode argument |

ECDSA keys are encrypted as Web3 Secret Storage **v3** keystores; the BLS key as an **EIP-2335** keystore. Each keystore's password is a random value written to the adjacent `.pass` file. `nodekey`/`bls-nodekey` are also kept as raw hex because the node loads them directly; `bls-pub`/`bls-pop` are public values for createNode.
```
