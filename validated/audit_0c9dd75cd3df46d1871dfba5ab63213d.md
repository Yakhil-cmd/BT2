### Title
Validator Node Private Keys Written with World-Readable Permissions (`os.ModePerm` / 0777) — (File: `cmd/kgen/main.go`, `cmd/homi/setup/cmd.go`)

---

### Summary

The `kgen` key-generation binary and the `homi` network-setup tool both write raw secp256k1 private key material (nodekeys, keystore passwords) to disk using `os.ModePerm` (0777 / world-readable-writable). Any local user on the same machine can read the generated private keys and impersonate the validator node or drain staked KAIA.

---

### Finding Description

**`cmd/kgen/main.go` — `writeNodeKeyInfoToFile`**

The `kgen` binary is the official Kaia tool for generating a validator's P2P node key. When invoked with `--file`, it writes the raw hex-encoded secp256k1 private key to `keys/nodekey` using `os.ModePerm`:

```go
// cmd/kgen/main.go:104
if err = os.WriteFile(nodeKeyFilePath, []byte(nodekey), os.ModePerm); err != nil {
```

`os.ModePerm` is `0777`, meaning the file is readable and writable by every user on the system (subject only to `umask`, which is often `022`, leaving the file at `0755` — still world-readable). [1](#0-0) 

**`cmd/homi/setup/cmd.go` — `writeValidatorsAndNodesToFile`, `writeTestKeys`, and `WriteFile`**

The `homi setup` tool generates the full validator key set for network bootstrapping. Three separate code paths write private key material with `os.ModePerm`:

1. `writeValidatorsAndNodesToFile` writes raw nodekey hex files for every CN/PN:
```go
// cmd/homi/setup/cmd.go:1361
os.WriteFile(nodeKeyFilePath, []byte(nodekeys[i]), os.ModePerm)
``` [2](#0-1) 

2. `writeTestKeys` writes raw test private keys:
```go
// cmd/homi/setup/cmd.go:1377
os.WriteFile(testKeyFilePath, []byte(key), os.ModePerm)
``` [3](#0-2) 

3. The local `WriteFile` helper (used for keystore password files via `genValidatorKeystore`, and for nodekeys via `writeCNInfoKey`/`writePNInfoKey`) also uses `os.ModePerm`:
```go
// cmd/homi/setup/cmd.go:1392
os.WriteFile(filePath, content, os.ModePerm)
``` [4](#0-3) 

This means `passwd1`, `passwd2`, … (keystore decryption passwords for the `reward`, `voter`, `manager`, `cnstaking-owner` keys) are also written world-readable. [5](#0-4) 

**Contrast with the correctly-implemented paths**: `crypto.SaveECDSA`, `cmd/kcn/genkeys.go`, and `accounts/keystore/key.go` all use `0o600` or `os.CreateTemp` (which defaults to `0600`): [6](#0-5) [7](#0-6) [8](#0-7) 

---

### Impact Explanation

- **Validator key theft → consensus privilege escalation**: The `nodekey` is the validator's secp256k1 identity on the P2P network. Possession of it allows an attacker to impersonate the validator node, inject crafted P2P messages, and disrupt Istanbul BFT consensus on honest nodes.
- **Keystore password theft → asset drain**: The `passwd*` files written by `homi` decrypt the `reward`, `voter`, `manager`, and `cnstaking-owner` keystores. An attacker who reads these files can sign transactions from those accounts, redirecting staking rewards, withdrawing staked KAIA, or casting fraudulent governance votes — all constituting unauthorized transfer or burn of KAIA and bridged assets.

---

### Likelihood Explanation

The trigger requires only local filesystem read access on the machine where `kgen --file` or `homi setup` was run. This is a realistic scenario on shared CI/CD servers, cloud VMs with multiple operator accounts, or any multi-user Linux host. No special privileges are needed; a default `umask` of `022` leaves the files at `0755` (world-readable). The attacker does not need to compromise any cryptographic primitive.

---

### Recommendation

Replace every `os.ModePerm` / `0o644` used for private key or password files with `0o600` (owner read/write only). Directory creation should use `0o700`. Apply the same pattern already used in `crypto.SaveECDSA` and `cmd/kcn/genkeys.go`:

```go
// Correct
os.WriteFile(nodeKeyFilePath, []byte(nodekey), 0o600)
os.MkdirAll(parentPath, 0o700)
```

---

### Proof of Concept

```bash
# On a multi-user Linux host, as user alice:
$ kgen --file
# Generates keys/ directory

$ ls -la keys/nodekey
-rwxr-xr-x 1 alice alice 64 ... keys/nodekey   # 0755 — world-readable

# As user eve (no special privileges):
$ cat /home/alice/keys/nodekey
a3f1...  # raw hex secp256k1 private key

# Eve can now derive alice's validator address and sign P2P handshakes or
# import the key into a wallet to drain any funded account.
```

For `homi`:
```bash
$ homi setup --gen-type local --cn-num 1 ...
$ ls -la keys/passwd1
-rwxr-xr-x 1 alice alice 32 ... keys/passwd1   # 0755 — world-readable
# passwd1 decrypts keys/keystore1 → full control of reward/voter/manager keys
```

### Citations

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

**File:** cmd/homi/setup/cmd.go (L1371-1387)
```go
func writeTestKeys(parentDir string, privKeys []*ecdsa.PrivateKey, keys []string) {
	parentPath := path.Join(outputPath, parentDir)
	os.MkdirAll(parentPath, os.ModePerm)

	for i, key := range keys {
		testKeyFilePath := path.Join(parentPath, "testkey"+strconv.Itoa(i+1))
		os.WriteFile(testKeyFilePath, []byte(key), os.ModePerm)
		fmt.Println("Created : ", testKeyFilePath)

		pk := privKeys[i]
		ksPath := path.Join(parentPath, "keystore"+strconv.Itoa(i+1))
		ks := keystore.NewKeyStore(ksPath, keystore.StandardScryptN, keystore.StandardScryptP)
		pwdStr := RandStringRunes(params.PasswordLength)
		ks.ImportECDSA(pk, pwdStr)
		WriteFile([]byte(pwdStr), path.Join(parentDir, "keystore"+strconv.Itoa(i+1)), crypto.PubkeyToAddress(pk.PublicKey).String())
	}
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

**File:** crypto/crypto.go (L206-211)
```go
// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return os.WriteFile(file, []byte(k), 0o600)
}
```

**File:** cmd/kcn/genkeys.go (L82-86)
```go
	if err := writeFile(filepath.Join(opDir, name+".json"), string(js), 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(opDir, name+".pass"), pw, 0o600)
}
```

**File:** accounts/keystore/key.go (L269-289)
```go
func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0o700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
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
```
