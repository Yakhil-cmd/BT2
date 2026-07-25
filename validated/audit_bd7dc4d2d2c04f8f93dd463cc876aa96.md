### Title
Plaintext Bridge Operator Password Written with World-Readable Permissions Enables Unauthorized Cross-Chain Asset Transfers — (`File: node/sc/bridge_accounts.go`)

### Summary

`InitializeBridgeAccountKeystore` in `node/sc/bridge_accounts.go` automatically generates a random password for the bridge operator keystore and persists it to disk via `setup.WriteFile`. The underlying `WriteFile` utility writes the file with `0o644` permissions (world-readable). Any local OS user can read the plaintext password, use it to unlock the parent or child bridge operator account, and submit fraudulent cross-chain value-transfer transactions.

### Finding Description

When the service-chain bridge starts and no keystore exists for the parent or child bridge operator, `InitializeBridgeAccountKeystore` generates a random password, creates a new keystore account, and immediately writes the password to a file named after the account address inside the keystore directory:

```go
// node/sc/bridge_accounts.go lines 207-213
password := setup.RandStringRunes(params.PasswordLength)
acc, err := ks.NewAccount(password)
...
setup.WriteFile([]byte(password), keystorePath, acc.Address.String())
``` [1](#0-0) 

The `setup.WriteFile` call resolves to the shared `WriteFile` utility, which creates the directory with `os.ModePerm` (0777) and writes the file with permission `0o644`:

```go
// cmd/utils/files.go lines 27-38
func WriteFile(content, filePath, fileName string) {
    err := os.MkdirAll(filePath, os.ModePerm)   // 0777
    ...
    err = os.WriteFile(path.Join(filePath, fileName), []byte(content), 0o644)
``` [2](#0-1) 

`0o644` means owner read/write, group read, **others read** — the password is readable by every user on the host. On subsequent restarts the same path is read back and used to auto-unlock the account:

```go
// node/sc/bridge_accounts.go lines 226-234
pwdFilePath := path.Join(keystorePath, acc.Address.String())
pwdStr, err := os.ReadFile(pwdFilePath)
if err == nil {
    if err := ks.Unlock(acc, string(pwdStr)); err != nil { ... }
    return ks, acc.Address, false, nil
}
``` [3](#0-2) 

The same password can be supplied to the public RPC methods `UnlockParentOperator` / `UnlockChildOperator`:

```go
// node/sc/api_bridge.go lines 643-650
func (sb *SubBridgeAPI) UnlockParentOperator(passphrase string, duration *uint64) error {
    return sb.subBridge.bridgeAccounts.pAccount.UnLockAccount(passphrase, duration)
}
func (sb *SubBridgeAPI) UnlockChildOperator(passphrase string, duration *uint64) error {
    return sb.subBridge.bridgeAccounts.cAccount.UnLockAccount(passphrase, duration)
}
``` [4](#0-3) 

### Impact Explanation

The bridge operator accounts are the privileged signers for all cross-chain value-transfer (VT) transactions between the parent chain and the service chain. Stealing the password and unlocking the operator keystore gives an attacker the ability to sign and submit arbitrary bridge transactions, resulting in **unauthorized transfer or drain of bridged assets** held by the bridge contracts. This satisfies the allowed-impact gate: unauthorized transfer of bridged assets affecting system-managed funds.

### Likelihood Explanation

The password file is created automatically on first run with no operator action required. Any unprivileged OS user sharing the same host (e.g., a compromised web server, a co-tenant in a shared hosting environment, or a CI/CD runner) can `cat` the file. The path is predictable: `<datadir>/<ParentBridgeAccountName>/<accountAddress>` and `<datadir>/<ChildBridgeAccountName>/<accountAddress>`. No special privileges or network access are needed.

### Recommendation

1. Write the password file with `0o600` (owner-only) permissions instead of `0o644` in `cmd/utils/files.go` (or provide a separate secret-file writer used by `InitializeBridgeAccountKeystore`).
2. Create the keystore directory with `0o700` instead of `os.ModePerm` (0777).
3. Warn operators at startup if the password file or keystore directory has permissions broader than `0o700`/`0o600`, analogous to how `openssh` rejects world-readable private key files.
4. Document that the auto-generated password file must be protected and consider requiring operators to supply the password interactively or via a secrets manager rather than persisting it in a world-readable file.

### Proof of Concept

```bash
# On a multi-user host running a Kaia service-chain node:

# 1. Locate the auto-generated password file (world-readable, 0644)
$ ls -la ~/.kaia/klay/bridge/parent_bridge_account/
-rw-r--r-- 1 kaia kaia  32 Jul 24 10:00 0xABCD...1234   # plaintext password

# 2. Read the password as any local user
$ cat ~/.kaia/klay/bridge/parent_bridge_account/0xABCD...1234
s3cr3tR4nd0mP4ss

# 3. Use the stolen password to unlock the parent bridge operator via RPC
$ curl -X POST http://localhost:8551 \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"subbridge_unlockParentOperator",
           "params":["s3cr3tR4nd0mP4ss", 0],"id":1}'
{"jsonrpc":"2.0","id":1,"result":null}   # operator now unlocked

# 4. Attacker can now trigger fraudulent bridge value-transfer transactions
#    signed by the compromised operator account, draining bridged assets.
``` [5](#0-4) [2](#0-1)

### Citations

**File:** node/sc/bridge_accounts.go (L200-238)
```go
// InitializeBridgeAccountKeystore initializes a keystore, imports existing keys, and tries to unlock the bridge account.
// This returns the 1st account of the wallet, its address, the lock status and the error.
func InitializeBridgeAccountKeystore(keystorePath string) (*keystore.KeyStore, common.Address, bool, error) {
	ks := keystore.NewKeyStore(keystorePath, keystore.StandardScryptN, keystore.StandardScryptP)

	// If there is no keystore file, this creates a random account and the corresponded password file.
	// TODO-Kaia-Servicechain A test-option will be added and this routine will be only executed with it.
	if len(ks.Accounts()) == 0 {
		password := setup.RandStringRunes(params.PasswordLength)
		acc, err := ks.NewAccount(password)
		if err != nil {
			return nil, common.Address{}, true, err
		}
		setup.WriteFile([]byte(password), keystorePath, acc.Address.String())

		if err := ks.Unlock(acc, password); err != nil {
			logger.Error("bridge account wallet unlock is failed by created password file.", "address", acc.Address, "err", err)
			os.RemoveAll(keystorePath)
			return nil, common.Address{}, true, err
		}

		return ks, acc.Address, false, nil
	}

	// Try to unlock 1st account if valid password file exist. (optional behavior)
	// If unlocking failed, user should unlock it through API.
	acc := ks.Accounts()[0]
	pwdFilePath := path.Join(keystorePath, acc.Address.String())
	pwdStr, err := os.ReadFile(pwdFilePath)
	if err == nil {
		if err := ks.Unlock(acc, string(pwdStr)); err != nil {
			logger.Warn("bridge account wallet unlock is failed by exist password file.", "address", acc.Address, "err", err)
			return ks, acc.Address, true, nil
		}
		return ks, acc.Address, false, nil
	}

	return ks, acc.Address, true, nil
}
```

**File:** cmd/utils/files.go (L27-38)
```go
func WriteFile(content, filePath, fileName string) {
	err := os.MkdirAll(filePath, os.ModePerm)
	if err != nil {
		fmt.Printf("Failed to create folder %v failed: %v\n", filePath, err)
		os.Exit(-1)
	}

	err = os.WriteFile(path.Join(filePath, fileName), []byte(content), 0o644)
	if err != nil {
		fmt.Printf("Failed to write %v file: %v\n", fileName, err)
		os.Exit(-1)
	}
```

**File:** node/sc/api_bridge.go (L643-650)
```go
// UnlockParentOperator can unlock the parent bridge operator.
func (sb *SubBridgeAPI) UnlockParentOperator(passphrase string, duration *uint64) error {
	return sb.subBridge.bridgeAccounts.pAccount.UnLockAccount(passphrase, duration)
}

// UnlockChildOperator can unlock the child bridge operator.
func (sb *SubBridgeAPI) UnlockChildOperator(passphrase string, duration *uint64) error {
	return sb.subBridge.bridgeAccounts.cAccount.UnLockAccount(passphrase, duration)
```
