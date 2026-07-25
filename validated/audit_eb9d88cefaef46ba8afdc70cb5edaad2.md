### Title
Bridge Operator Keystore Password Written to World-Readable Plaintext File — (`File: node/sc/bridge_accounts.go`)

---

### Summary

`InitializeBridgeAccountKeystore` in `node/sc/bridge_accounts.go` auto-generates a random password for the bridge operator account and persists it to disk in plaintext via `setup.WriteFile`, which uses `os.ModePerm` (0o777 — world-readable/writable). Any local OS user on the service-chain node host can read the password file, decrypt the adjacent keystore JSON, recover the bridge operator private key, and submit fraudulent cross-chain value-transfer transactions.

---

### Finding Description

When a service-chain node starts and no bridge account keystore exists, `InitializeBridgeAccountKeystore` is called for both `parent_bridge_account` and `child_bridge_account`:

```go
// node/sc/bridge_accounts.go:208-213
password := setup.RandStringRunes(params.PasswordLength)
acc, err := ks.NewAccount(password)
...
setup.WriteFile([]byte(password), keystorePath, acc.Address.String())
``` [1](#0-0) 

`setup.WriteFile` writes the file with `os.ModePerm`:

```go
// cmd/homi/setup/cmd.go:1389-1393
func WriteFile(content []byte, parentFolder string, fileName string) {
    filePath := path.Join(outputPath, parentFolder, fileName)
    os.MkdirAll(path.Dir(filePath), os.ModePerm)
    os.WriteFile(filePath, content, os.ModePerm)  // 0o777 — world-readable
``` [2](#0-1) 

On the next startup, the node reads this plaintext file back and auto-unlocks the operator account:

```go
// node/sc/bridge_accounts.go:227-234
pwdFilePath := path.Join(keystorePath, acc.Address.String())
pwdStr, err := os.ReadFile(pwdFilePath)
if err == nil {
    if err := ks.Unlock(acc, string(pwdStr)); err != nil { ...
``` [3](#0-2) 

The keystore JSON (encrypted private key) and the plaintext password file reside in the same directory. Possessing both is sufficient to recover the raw ECDSA private key.

---

### Impact Explanation

The bridge operator accounts (`parent_bridge_account` / `child_bridge_account`) are the privileged signers that call `HandleKLAYTransfer`, `HandleERC20Transfer`, and `HandleERC721Transfer` on the bridge contracts. [4](#0-3) 

An attacker who recovers the operator private key can:
1. Submit fraudulent `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` calls, minting or releasing bridged assets to an arbitrary address.
2. Drain the bridge contract's KAIA/ERC20/ERC721 liquidity pool.
3. Manipulate bridge configuration nonces via `_voteConfiguration`.

This satisfies the allowed impact gate: **unauthorized transfer/mint of KAIA and bridged assets, and bridge privilege escalation changing asset ownership**. [5](#0-4) 

---

### Likelihood Explanation

- This code path executes automatically on first node startup — no operator action required.
- The password file is created with `os.ModePerm` (0o777), making it readable by every local user account on the host.
- The keystore JSON is in the same directory, also created by the same `NewKeyStore` call.
- Any unprivileged local user (e.g., a co-located service, a compromised daemon, or a shared-host tenant) can read both files without elevated privileges.
- The `homi` genesis tool (`genValidatorKeystore`) has the same pattern, writing validator keystore passwords with `os.ModePerm`. [6](#0-5) 

---

### Recommendation

1. **Replace `os.ModePerm` with `0o600`** in `setup.WriteFile` when writing secret material, or provide a separate secret-writing helper that enforces restrictive permissions.
2. **Do not store the keystore password in a file adjacent to the keystore**. If auto-unlock is required, use OS-level secret storage (e.g., a secrets manager, environment variable injection, or a separate secrets directory with tighter ACLs).
3. Align with the pattern already used in `cmd/kcn/genkeys.go`, which correctly writes `.pass` files with `0o600`. [7](#0-6) 

---

### Proof of Concept

```
# On the service-chain node host, as any local user:
$ cat /path/to/datadir/parent_bridge_account/<operator_address>
# → plaintext password printed

# Decrypt the keystore with the recovered password:
$ cat /path/to/datadir/parent_bridge_account/UTC--<timestamp>--<address>
# → encrypted keystore JSON

# Use web3/ethers to decrypt and sign a fraudulent handleKLAYTransfer:
const wallet = ethers.Wallet.fromEncryptedJsonSync(keystoreJSON, plaintextPassword);
await bridgeContract.connect(wallet).handleKLAYTransfer(
    fakeTxHash, victimAddr, attackerAddr, largeAmount, nonce, blockNum, "0x"
);
# → bridged KAIA transferred to attacker
``` [8](#0-7)

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

**File:** cmd/homi/setup/cmd.go (L332-341)
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
```

**File:** cmd/homi/setup/cmd.go (L1389-1393)
```go
func WriteFile(content []byte, parentFolder string, fileName string) {
	filePath := path.Join(outputPath, parentFolder, fileName)
	os.MkdirAll(path.Dir(filePath), os.ModePerm)
	os.WriteFile(filePath, content, os.ModePerm)
	fmt.Println("Created : ", filePath)
```

**File:** node/sc/bridge_manager.go (L332-354)
```go
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	default:
		logger.Error("Got Unknown Token Type ReceivedEvent", "bridge", contractAddr, "nonce", requestNonce, "from", from)
		return nil
	}
```

**File:** contracts/service_chain/bridge/BridgeOperator.sol (L102-116)
```text
    // _voteValueTransfer votes value transfer transaction with the operator.
    function _voteValueTransfer(uint64 _requestNonce)
        internal
        returns(bool)
    {
        require(!closedValueTransferVotes[_requestNonce], "closed vote");

        bytes32 voteKey = keccak256(msg.data);
        if (_voteCommon(VoteType.ValueTransfer, _requestNonce, voteKey)) {
            closedValueTransferVotes[_requestNonce] = true;
            return true;
        }

        return false;
    }
```

**File:** cmd/kcn/genkeys.go (L82-85)
```go
	if err := writeFile(filepath.Join(opDir, name+".json"), string(js), 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(opDir, name+".pass"), pw, 0o600)
```
