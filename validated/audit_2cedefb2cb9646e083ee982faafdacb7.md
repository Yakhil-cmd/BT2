### Title
Missing Signer Authorization in `MsgRegisterEncryptionKey` Allows Any Account to Overwrite Any Validator's Encryption Key — (File: x/e2ee/keeper/keeper.go)

---

### Summary

The `RegisterEncryptionKey` handler in `x/e2ee/keeper/keeper.go` never verifies that the transaction signer matches the `Address` field in `MsgRegisterEncryptionKey`. Any unprivileged account can overwrite any validator's registered X25519 encryption key, corrupting the on-chain e2ee key registry and permanently breaking the encrypted blocklist system for targeted validators.

---

### Finding Description

`Keeper.RegisterEncryptionKey` blindly stores the supplied key at whatever `req.Address` is provided: [1](#0-0) 

The only pre-execution validation is `ValidateBasic()`, which checks bech32 format and X25519 key format — it performs no ownership or authorization check: [2](#0-1) 

There is no check anywhere in the message-handling path that the signer of the transaction equals `req.Address`. The Cosmos SDK does not enforce this automatically; it is the responsibility of the message server. The keeper has no access to the signing context and performs no such check.

---

### Impact Explanation

The e2ee module is the backbone of Cronos's encrypted validator blocklist. Validators register their X25519 public keys on-chain. The admin fetches those keys and uses them to encrypt the blocklist blob, which is then stored on-chain via `MsgStoreBlockList`. Each validator node decrypts the blob using its local private key identity: [3](#0-2) 

If an attacker overwrites validator V's registered key with an attacker-controlled public key, the admin will encrypt the next blocklist update with the attacker's key. Validator V's `age.Decrypt` call will fail with `ErrIncorrectIdentity`. The validator's in-memory blocklist will not be updated (or will be cleared/stale), causing the blocklist enforcement to silently break for that validator. Blocked addresses can then route transactions through that validator's mempool and have them included in blocks.

This satisfies:
- **High**: Bypass of Cronos admin block-list authorization checks.
- **High**: Corruption of e2ee key/message state with direct security impact.

---

### Likelihood Explanation

The attack requires only a single, cheap on-chain transaction from any unprivileged account. No special privileges, leaked keys, or cryptographic breaks are needed. The attacker only needs to know the target validator's bech32 address, which is publicly observable on-chain.

---

### Recommendation

Add an authorization check inside `RegisterEncryptionKey` (or in a dedicated ante/decorator) that asserts the transaction signer equals `req.Address`:

```go
func (k Keeper) RegisterEncryptionKey(
    ctx context.Context,
    req *types.MsgRegisterEncryptionKey,
) (*types.MsgRegisterEncryptionKeyResponse, error) {
    signerAddr := sdk.UnwrapSDKContext(ctx).MsgSigner() // or extract from tx context
    if signerAddr.String() != req.Address {
        return nil, sdkerrors.ErrUnauthorized.Wrap("signer must match address")
    }
    if err := k.registerEncryptionKey(ctx, req.Address, []byte(req.Key)); err != nil {
        return nil, err
    }
    return &types.MsgRegisterEncryptionKeyResponse{}, nil
}
```

This mirrors the pattern already used in `UpdatePermissions` and `StoreBlockList`, which both verify `msg.From` against an authorized address before mutating state. [4](#0-3) 

---

### Proof of Concept

1. Attacker generates a fresh X25519 keypair: `(attacker_priv, attacker_pub)`.
2. Attacker submits `MsgRegisterEncryptionKey{Address: "<validator_bech32>", Key: "<attacker_pub>"}` signed by any account.
3. The keeper stores `attacker_pub` at the validator's address with no authorization check.
4. Admin calls `Keys(addresses=[validator_addr])` — receives `attacker_pub`.
5. Admin encrypts the next blocklist blob with `attacker_pub` and submits `MsgStoreBlockList`.
6. Validator node calls `age.Decrypt(blob, validator_identity)` — fails with `ErrIncorrectIdentity`.
7. `SetBlockList` returns an error; the validator's in-memory blocklist is not updated.
8. Blocked addresses can now submit transactions through this validator without enforcement.

### Citations

**File:** x/e2ee/keeper/keeper.go (L45-53)
```go
func (k Keeper) RegisterEncryptionKey(
	ctx context.Context,
	req *types.MsgRegisterEncryptionKey,
) (*types.MsgRegisterEncryptionKeyResponse, error) {
	if err := k.registerEncryptionKey(ctx, req.Address, []byte(req.Key)); err != nil {
		return nil, err
	}
	return &types.MsgRegisterEncryptionKeyResponse{}, nil
}
```

**File:** x/e2ee/types/msg.go (L13-19)
```go
func (m *MsgRegisterEncryptionKey) ValidateBasic() error {
	// validate bech32 format of Address
	if _, err := sdk.AccAddressFromBech32(m.Address); err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	return ValidateRecipientKey(m.Key)
}
```

**File:** app/proposal.go (L226-229)
```go
	reader, err := age.Decrypt(bytes.NewBuffer(blob), h.Identity)
	if err != nil {
		return err
	}
```

**File:** x/cronos/keeper/msg_server.go (L102-116)
```go
func (k msgServer) UpdatePermissions(goCtx context.Context, msg *types.MsgUpdatePermissions) (*types.MsgUpdatePermissionsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	// if admin is empty, no sender could be equal to it
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
	acc, err := sdk.AccAddressFromBech32(msg.Address)
	if err != nil {
		return nil, err
	}
	k.SetPermissions(ctx, acc, msg.Permissions)

	return &types.MsgUpdatePermissionsResponse{}, nil
}
```
