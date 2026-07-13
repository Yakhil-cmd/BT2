The genesis-path framing in the question requires privileged access (governance or operator control), but the **actual exploitable vulnerability is in the live transaction path** — `RegisterEncryptionKey` has no signer-ownership check, making it reachable by any unprivileged account.

---

### Title
Missing Signer-Ownership Check in `RegisterEncryptionKey` Allows Any Account to Overwrite Any Address's Encryption Key — (`x/e2ee/keeper/keeper.go`)

### Summary
`Keeper.RegisterEncryptionKey` accepts a `MsgRegisterEncryptionKey` containing an arbitrary `Address` field and writes the supplied key to that address's store slot without verifying that the transaction signer is the owner of that address. Any unprivileged account can overwrite any validator's (or user's) encryption key with an attacker-controlled key.

### Finding Description
`RegisterEncryptionKey` (the Msg handler) delegates directly to `registerEncryptionKey` with no ownership check: [1](#0-0) 

`registerEncryptionKey` itself only validates that the address string is a valid bech32 address, then unconditionally overwrites the KV store entry: [2](#0-1) 

`ValidateBasic` on the message only checks address format and key format — it does not check that `Address` matches the transaction signer: [3](#0-2) 

The Cosmos SDK verifies that the transaction carries a valid signature from *some* account, but it does not enforce that the signer matches `req.Address`. That check is the module's responsibility, and it is absent here.

### Impact Explanation
An attacker sends a signed `MsgRegisterEncryptionKey` with `Address = <victim_validator_address>` and `Key = <attacker_age_pubkey>`. After the transaction is included, any message encrypted to the victim validator's address is encrypted to the attacker's key. The attacker can decrypt all such messages; the legitimate validator cannot. This is direct corruption of e2ee key state with security impact, matching the High impact category: *"Corruption of … e2ee key/message state with direct security impact."*

### Likelihood Explanation
The attack requires only a funded account and a single transaction. No special privileges, governance access, or key material beyond the attacker's own signing key are needed. The attack is silent — the victim's key in the store is simply replaced.

### Recommendation
In `RegisterEncryptionKey`, extract the signer from the SDK context and assert it equals `req.Address` before writing:

```go
func (k Keeper) RegisterEncryptionKey(
    ctx context.Context,
    req *types.MsgRegisterEncryptionKey,
) (*types.MsgRegisterEncryptionKeyResponse, error) {
    sdkCtx := sdk.UnwrapSDKContext(ctx)
    signer := sdkCtx.EventManager()... // or retrieve from msg signer list
    if signer != req.Address {
        return nil, sdkerrors.ErrUnauthorized.Wrap("signer must match address")
    }
    ...
}
```

The exact mechanism depends on the SDK version (e.g., `GetSigners()` on the message or the `x/auth` ante-handler signer list), but the invariant must be enforced at the keeper level.

### Proof of Concept
1. Validator V registers their legitimate key: `MsgRegisterEncryptionKey{Address: V_addr, Key: V_pubkey}` — signed by V.
2. Attacker A (any funded account) sends: `MsgRegisterEncryptionKey{Address: V_addr, Key: A_pubkey}` — signed by A.
3. Both transactions are valid and accepted by the chain.
4. Query `Key(V_addr)` — returns `A_pubkey`. V's key is permanently overwritten.
5. Any subsequent `EncryptToValidators` call targeting V encrypts to A's key; A decrypts; V cannot.

---

**Note on the genesis-path claim:** The `InitGenesis` duplicate-entry issue is real at the code level (no deduplication check), but it is **not reachable by an unprivileged attacker** — injecting a crafted `GenesisState` requires governance authority or operator-level state-sync control, both of which are privileged preconditions excluded by the scope rules. The transaction path above is the correct unprivileged attack vector. [4](#0-3)

### Citations

**File:** x/e2ee/keeper/keeper.go (L32-43)
```go
func (k Keeper) registerEncryptionKey(
	ctx context.Context,
	address string,
	key []byte,
) error {
	bz, err := k.addressCodec.StringToBytes(address)
	if err != nil {
		return err
	}
	sdk.UnwrapSDKContext(ctx).KVStore(k.storeKey).Set(types.KeyPrefix(bz), key)
	return nil
}
```

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

**File:** x/e2ee/keeper/keeper.go (L55-65)
```go
func (k Keeper) InitGenesis(
	ctx context.Context,
	state *types.GenesisState,
) error {
	for _, key := range state.Keys {
		if err := k.registerEncryptionKey(ctx, key.Address, []byte(key.Key)); err != nil {
			return err
		}
	}
	return nil
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
