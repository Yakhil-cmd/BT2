### Title
Unauthenticated `MsgRegisterEncryptionKey` Allows Any Address to Hijack Any Address's Encryption Key — (`x/e2ee/keeper/keeper.go`)

---

### Summary

`Keeper.RegisterEncryptionKey` performs no signer-vs-address authorization check. Any unprivileged account can register or overwrite the encryption key for **any** address, including bridge operators. The `Keeper.Key` query returning `""` (no error) for unregistered addresses is a real oracle that lets an attacker time a front-run, but the missing auth check means the attack succeeds even without timing — the attacker can overwrite a legitimately registered key at any time.

---

### Finding Description

`Keeper.Key` (keeper.go:87-95) calls `KVStore.Get()`, which returns `nil` for a missing entry; `string(nil)` in Go is `""`. The response is therefore `KeyResponse{Key: ""}` with `err == nil` for any unregistered address, making registration state publicly observable. [1](#0-0) 

`Keeper.RegisterEncryptionKey` (keeper.go:45-53) delegates directly to `registerEncryptionKey` (keeper.go:32-43), which only decodes the address and writes to the KV store. There is no check that the transaction signer equals `req.Address`. [2](#0-1) [3](#0-2) 

`MsgRegisterEncryptionKey.ValidateBasic()` (msg.go:13-19) only validates bech32 address format and the age X25519 key format. It does not enforce that the signer owns the address. [4](#0-3) 

`MsgRegisterEncryptionKey` carries only `Address` and `Key` fields; there is no `Signer` field and no middleware enforcing ownership. [5](#0-4) 

---

### Impact Explanation

An attacker who registers their own age X25519 keypair's public key under a bridge operator's address causes all senders who look up that address's public key to encrypt messages with the attacker's key. The attacker can decrypt those messages; the legitimate bridge operator cannot. This is direct corruption of e2ee key/message state with security impact, matching the High tier in scope rules.

Additionally, the attacker can overwrite a legitimately registered key at any time — the oracle just helps them time a pre-registration attack, but post-registration overwrite is equally possible.

---

### Likelihood Explanation

The entrypoint is a standard Cosmos SDK `Msg` transaction, reachable by any unprivileged account with gas. No special privileges, leaked keys, or external assumptions are required. The oracle (empty-string query response) is publicly accessible via gRPC/REST.

---

### Recommendation

In `RegisterEncryptionKey`, verify that the transaction signer matches `req.Address` before writing to the store:

```go
func (k Keeper) RegisterEncryptionKey(
    ctx context.Context,
    req *types.MsgRegisterEncryptionKey,
) (*types.MsgRegisterEncryptionKeyResponse, error) {
    signers := sdk.UnwrapSDKContext(ctx).TxSigner() // or extract from msg signers
    // enforce signers[0] == req.Address
    ...
}
```

Alternatively, add a `Signer` field to `MsgRegisterEncryptionKey` and enforce `Signer == Address` in `ValidateBasic()` and the keeper.

---

### Proof of Concept

```
1. Attacker generates an age X25519 keypair: (attacker_priv, attacker_pub).
2. Attacker queries: GET /e2ee/key/{bridge_operator_address}
   → Response: {"key": ""}  (oracle confirms unregistered)
3. Attacker broadcasts:
   MsgRegisterEncryptionKey{Address: bridge_operator_address, Key: attacker_pub}
   signed by attacker's own account key.
4. Tx succeeds (no signer check).
5. Query again: GET /e2ee/key/{bridge_operator_address}
   → Response: {"key": attacker_pub}
6. Any sender encrypting to bridge_operator_address now uses attacker_pub.
   Attacker decrypts with attacker_priv; bridge operator receives undecryptable ciphertext.
7. Step 3 can be repeated at any time to overwrite a legitimately registered key.
```

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

**File:** x/e2ee/keeper/keeper.go (L87-94)
```go
func (k Keeper) Key(ctx context.Context, req *types.KeyRequest) (*types.KeyResponse, error) {
	bz, err := k.addressCodec.StringToBytes(req.Address)
	if err != nil {
		return nil, err
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	value := sdkCtx.KVStore(k.storeKey).Get(types.KeyPrefix(bz))
	return &types.KeyResponse{Key: string(value)}, nil
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

**File:** x/e2ee/types/tx.pb.go (L32-35)
```go
type MsgRegisterEncryptionKey struct {
	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Key     string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
}
```
