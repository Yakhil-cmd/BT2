### Title
Validator Node Key Written with World-Readable/Writable Permissions Enables Unauthorized Validator State Transitions — (`cmd/kgen/main.go`, `cmd/homi/setup/cmd.go`)

---

### Summary

The `kgen` and `homi` tools write validator ECDSA private keys (raw hex, unencrypted) and keystore passwords to disk using `os.ModePerm` (0o777), making them readable and writable by every user on the system. An attacker with local access can read the nodekey and directly call privileged `onlyNodeId` operations on AddressBookV2 — including `exit`, `offboard`, `pause`, and `resume` — without any brute-force step, removing the validator from the network and disrupting its staking position and block-reward stream.

---

### Finding Description

**`cmd/kgen/main.go` — `writeNodeKeyInfoToFile`**

The `kgen` tool is the production CLI used by Kaia validators to generate their node identity key. When invoked with `--file`, it calls `writeNodeKeyInfoToFile`, which writes the raw hex-encoded ECDSA private key to disk with `os.ModePerm` (0o777):

```go
nodeKeyFilePath := path.Join(parentPath, "nodekey")
if err = os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm); err != nil {
    return err
}
```

The parent directory is also created with `os.ModePerm`:

```go
err := os.MkdirAll(parentPath, os.ModePerm)
``` [1](#0-0) 

This is a **raw, unencrypted** private key — not a password-protected keystore — written with permissions that allow any local user to read and overwrite it.

**`cmd/homi/setup/cmd.go` — `WriteFile`, `writeValidatorsAndNodesToFile`, `writeTestKeys`**

The `homi gen` tool (used for TypeLocal, TypeRemote, and TypeDeploy network setups) routes all sensitive output through `WriteFile`, which unconditionally uses `os.ModePerm`:

```go
func WriteFile(content []byte, parentFolder string, fileName string) {
    filePath := path.Join(outputPath, parentFolder, fileName)
    os.MkdirAll(path.Dir(filePath), os.ModePerm)
    os.WriteFile(filePath, content, os.ModePerm)
    ...
}
``` [2](#0-1) 

This function is called to write:
- `nodekey1`, `nodekey2`, … — raw hex private keys for each validator
- `passwd1`, `passwd2`, … — **plaintext keystore passwords**
- `keystore1`, `keystore2`, … — encrypted keystore JSON files [3](#0-2) [4](#0-3) 

`writeValidatorsAndNodesToFile` and `writeTestKeys` also call `os.WriteFile` directly with `os.ModePerm`: [5](#0-4) [6](#0-5) 

**Contrast with correctly-permissioned paths elsewhere in the same repo:**

`crypto.SaveECDSA`, `cmd/kcn/genkeys.go`, and `cmd/utils/nodecmd/accountcmd.go` all use `0o600` for secret files: [7](#0-6) [8](#0-7) [9](#0-8) 

The `kgen` and `homi` paths are the only production key-writing paths that deviate from this standard.

---

### Impact Explanation

The `nodekey` is the validator's ECDSA identity key. Per the `kcn valops` documentation, every `onlyNodeId` operation on AddressBookV2 requires `msg.sender == node-id`, i.e., a signature from the nodekey:

- `exit` — removes the validator from the active set
- `offboard` — permanently offboards the validator
- `pause` / `resume` — halts/restores consensus participation
- `ready-candidate` / `ready-validator` / `unready-*` — controls candidacy state [10](#0-9) 

An attacker who reads the world-readable nodekey file can submit any of these transactions on-chain, directly changing the validator's protected state in AddressBookV2 without the operator's knowledge or consent. This constitutes **validator privilege escalation that changes protected chain state** (validator set membership, readiness, and reward eligibility).

For the `homi` path: the world-readable `passwd` files, combined with the co-located world-readable `keystore` files, allow an attacker to decrypt the `manager` keystore. The `manager` key holds ≥ 5 M KAIA and is the account that deployed CnStaking and controls staking operations — enabling **unauthorized transfer of KAIA from system-managed staking funds**.

---

### Likelihood Explanation

- `kgen --file` and `homi gen` are standard operator onboarding steps run on the machine where the validator is being set up.
- Shared build/deployment servers, CI environments, or any multi-user Linux host expose these files to all local users immediately upon creation.
- No brute-force is required: the nodekey is stored as raw hex, and the `passwd` files are plaintext. A single `cat` suffices.
- The attacker needs only a local shell account on the same machine — a realistic threat model for shared infrastructure.

---

### Recommendation

**Short term:** Replace `os.ModePerm` with `0o600` for all secret files in both tools:

```go
// cmd/kgen/main.go
os.WriteFile(nodeKeyFilePath, []byte(nodekey), 0o600)

// cmd/homi/setup/cmd.go — WriteFile for secrets
os.WriteFile(filePath, content, 0o600)
```

Also change the directory creation from `os.ModePerm` to `0o700` so directory listings are not world-readable.

**Long term:** At startup, `node/config.go`'s `NodeKey()` and `BlsNodeKey()` should check the permissions of the loaded key files and emit a fatal error or warning if they are broader than `0o600`, analogous to the long-term recommendation in the original report.

---

### Proof of Concept

```bash
# Step 1: Validator operator generates keys on a shared machine
kgen --file --ip 1.2.3.4 --port 32323
# Creates keys/nodekey with permissions -rwxrwxrwx (0777)

# Step 2: Attacker on the same machine reads the raw private key
STOLEN_KEY=$(cat keys/nodekey)

# Step 3: Attacker calls `exit` on the validator via kcn valops
kcn valops exit \
  --private-key "$STOLEN_KEY" \
  --endpoint http://validator-rpc:8551

# Result: Validator is removed from AddressBookV2's active set,
# loses consensus participation and all future block rewards.
# The operator cannot re-enter without calling ready-candidate/
# ready-validator again — but the attacker can immediately call
# exit again each time, permanently locking the validator out.
```

For the `homi` path:

```bash
# homi gen writes passwd1 (plaintext) and keystore1 (encrypted JSON) both 0777
PASSWD=$(cat output/keys/passwd1)
# Decrypt manager keystore -> extract private key -> drain CnStaking balance
```

### Citations

**File:** cmd/kgen/main.go (L96-106)
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
```

**File:** cmd/homi/setup/cmd.go (L332-342)
```go
func genValidatorKeystore(privKeys []*ecdsa.PrivateKey) {
	path := path.Join(outputPath, DirKeys)
	ks := keystore.NewKeyStore(path, keystore.StandardScryptN, keystore.StandardScryptP)

	for i, pk := range privKeys {
		pwdStr := RandStringRunes(params.PasswordLength)
		account, _ := ks.ImportECDSA(pk, pwdStr)
		genRewardKeystore(account, i)
		WriteFile([]byte(pwdStr), DirKeys, "passwd"+strconv.Itoa(i+1))
	}
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

**File:** cmd/homi/setup/cmd.go (L1375-1378)
```go
	for i, key := range keys {
		testKeyFilePath := path.Join(parentPath, "testkey"+strconv.Itoa(i+1))
		os.WriteFile(testKeyFilePath, []byte(key), os.ModePerm)
		fmt.Println("Created : ", testKeyFilePath)
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

**File:** crypto/crypto.go (L208-210)
```go
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return os.WriteFile(file, []byte(k), 0o600)
```

**File:** cmd/kcn/genkeys.go (L82-85)
```go
	if err := writeFile(filepath.Join(opDir, name+".json"), string(js), 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(opDir, name+".pass"), pw, 0o600)
```

**File:** cmd/utils/nodecmd/accountcmd.go (L454-455)
```go
	b := []byte(hex.EncodeToString(crypto.FromECDSA(priv)))
	writeFile(path, b, 0o600) // Secret file permission.
```

**File:** cmd/kcn/README.md (L39-54)
```markdown
### Node operator role

These commands require `msg.sender == node-id` (the private key **is** the node key).

```
kcn valops ready-candidate
kcn valops unready-candidate
kcn valops ready-validator
kcn valops unready-validator
kcn valops pause
kcn valops resume
kcn valops exit
kcn valops offboard
```

No extra arguments. The node-id is derived from the private key.
```
