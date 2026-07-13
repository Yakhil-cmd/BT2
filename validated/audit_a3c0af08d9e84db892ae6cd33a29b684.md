Looking at the relevant code:

### Title
Missing Signer Authorization in `MsgRegisterEncryptionKey` Allows Arbitrary Key Overwrite — (`x/e2ee/keeper/keeper.go`, `x/e2ee/types/msg.go`)

---

### Summary

`RegisterEncryptionKey` never checks that the transaction signer matches `req.Address`. Any unprivileged account can overwrite any other account's registered encryption key. `ExportGenesis` then snapshots the corrupted KV store verbatim, and `InitGenesis` re-imports it without re-validation, making the corruption permanent across chain upgrades.

---

### Finding Description

`ValidateBasic` in `msg.go` only validates bech32 format and age key format — it performs no signer-vs-address check: [1](#0-0) 

The keeper's `RegisterEncryptionKey` blindly writes `req.Address → req.Key` into the KV store with no signer comparison: [2](#0-1) 

The internal `registerEncryptionKey` helper simply resolves the address string and calls `KVStore.Set` — no ownership check at any layer: [3](#0-2) 

`ExportGenesis` iterates the raw KV store and emits every `(address, key)` pair as-is, with no re-validation of ownership: [4](#0-3) 

`InitGenesis` re-applies every entry from the exported state by calling the same `registerEncryptionKey` helper: [5](#0-4) 

`GenesisState.Validate()` only checks bech32 format and age key format — it does not verify that the address authorized the key: [6](#0-5) 

---

### Impact Explanation

An unprivileged attacker submits `MsgRegisterEncryptionKey{Address: victim, Key: attacker_pubkey}`. This succeeds immediately. From that point:

- Any party encrypting a message to `victim` (e.g., via the CLI encrypt flow) will look up the registered public key and encrypt to the **attacker's** key instead.
- The attacker can decrypt all such messages.
- On chain export + re-import (upgrade, migration, snapshot restore), `ExportGenesis` snapshots the corrupted mapping and `InitGenesis` re-applies it, making the corruption permanent in the new chain state.
- The victim cannot recover their slot without submitting a corrective transaction — but the attacker can immediately re-overwrite it again, since there is still no signer check.

This is direct corruption of e2ee key/message state. The severity of downstream impact (e.g., decryption of validator-targeted encrypted payloads, sensitive key material sent over e2ee channels) depends on what callers encrypt, but the key-state corruption itself is unconditional and permanent.

---

### Likelihood Explanation

The attack requires only a valid bech32 address and a valid age X25519 public key — both are trivially constructable. No privilege, governance access, or leaked secret is needed. The transaction is a standard `Msg` submission available to any account.

---

### Recommendation

In `RegisterEncryptionKey`, verify that the transaction signer equals `req.Address` before writing to the store. In Cosmos SDK v0.50+, extract the signer from the `sdk.Context` or require the message to implement `sdk.HasValidateBasic` with a signer list, then compare:

```go
func (k Keeper) RegisterEncryptionKey(
    ctx context.Context,
    req *types.MsgRegisterEncryptionKey,
) (*types.MsgRegisterEncryptionKeyResponse, error) {
    signers := sdk.UnwrapSDKContext(ctx).TxSigner() // or equivalent
    if signers.String() != req.Address {
        return nil, sdkerrors.ErrUnauthorized
    }
    // ...
}
```

Alternatively, remove the `Address` field from the message entirely and derive it from the verified transaction signer.

---

### Proof of Concept

```
1. victim registers their key:
   MsgRegisterEncryptionKey{Address: victim_addr, Key: victim_pubkey}

2. attacker overwrites it (no signer check):
   MsgRegisterEncryptionKey{Address: victim_addr, Key: attacker_pubkey}
   → succeeds; KV store now maps victim_addr → attacker_pubkey

3. chain operator runs `gaiad export` → genesis.json
   ExportGenesis emits: {address: victim_addr, key: attacker_pubkey}

4. chain operator runs `gaiad start --genesis genesis.json`
   InitGenesis re-applies: victim_addr → attacker_pubkey

5. query: GET /e2ee/key?address=victim_addr
   → returns attacker_pubkey  ✓

6. attacker can decrypt all future messages encrypted to victim_addr.
   Victim re-registers their key; attacker immediately re-overwrites (step 2).
```

### Citations

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

**File:** x/e2ee/keeper/keeper.go (L67-85)
```go
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	iter := prefix.NewStore(sdkCtx.KVStore(k.storeKey), types.KeyPrefixEncryptionKey).Iterator(nil, nil)
	defer iter.Close()

	var keys []types.EncryptionKeyEntry
	for ; iter.Valid(); iter.Next() {
		address, err := k.addressCodec.BytesToString(iter.Key())
		if err != nil {
			return nil, err
		}
		key := iter.Value()
		keys = append(keys, types.EncryptionKeyEntry{
			Address: address,
			Key:     string(key),
		})
	}
	return &types.GenesisState{Keys: keys}, nil
}
```

**File:** x/e2ee/types/genesis.go (L10-16)
```go
func (gs GenesisState) Validate() error {
	for _, key := range gs.Keys {
		if err := key.Validate(); err != nil {
			return err
		}
	}
	return nil
```
