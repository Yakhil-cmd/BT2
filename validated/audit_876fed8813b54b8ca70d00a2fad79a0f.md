Looking at the code, the actual vulnerability is simpler and more direct than the governance/IBC path described in the question. Let me trace it precisely.

**`keeper.RegisterEncryptionKey`** (keeper.go lines 45-53) takes `req.Address` and `req.Key` and writes them to the KV store with zero signer validation: [1](#0-0) 

**`ValidateBasic`** (msg.go lines 13-19) only validates bech32 format and age key format — it never checks that the transaction signer matches `req.Address`: [2](#0-1) 

**`MsgRegisterEncryptionKey`** (tx.pb.go lines 32-35) has separate `Address` and `Key` fields with no enforced relationship to the tx signer: [3](#0-2) 

No governance or IBC wrapping is needed. A regular unprivileged transaction can set `Address` to any address (including module accounts) and `Key` to an attacker-controlled age public key. The keeper writes it unconditionally.

---

### Title
Missing Signer-Address Check Allows Arbitrary Encryption Key Overwrite for Any Account — (`x/e2ee/keeper/keeper.go`)

### Summary
`keeper.RegisterEncryptionKey` writes an attacker-supplied key for an arbitrary `Address` without verifying that the transaction signer owns that address. Any unprivileged user can overwrite the e2ee encryption key for any account, including module accounts and privileged addresses.

### Finding Description
`MsgRegisterEncryptionKey` contains two independent fields: `Address` (the account whose key is being registered) and `Key` (the age X25519 public key). The msg server handler (`keeper.RegisterEncryptionKey`) calls `registerEncryptionKey(ctx, req.Address, []byte(req.Key))` directly without extracting the signer from the context or comparing it to `req.Address`. `ValidateBasic` only checks bech32 validity and age key format. There is no guard anywhere in the message lifecycle that enforces `signer == req.Address`.

### Impact Explanation
An attacker submits a standard `MsgRegisterEncryptionKey` transaction with `Address` set to a bridge module account (or any privileged address) and `Key` set to their own age public key. The keeper overwrites the stored key for that address. Any subsequent encryption of messages/instructions targeting that address will use the attacker's key, allowing full decryption. This is direct corruption of e2ee key state with security impact, matching the High impact category in scope.

### Likelihood Explanation
The attack requires only a valid bech32 address and a valid age X25519 public key — both trivially constructable. No special privileges, governance participation, or IBC access are needed. It is executable by any unprivileged on-chain account in a single transaction.

### Recommendation
In `keeper.RegisterEncryptionKey`, extract the signer from the SDK context and verify it equals `req.Address` before writing:

```go
func (k Keeper) RegisterEncryptionKey(ctx context.Context, req *types.MsgRegisterEncryptionKey) (*types.MsgRegisterEncryptionKeyResponse, error) {
    signers := sdk.UnwrapSDKContext(ctx).TxSigner() // or equivalent signer extraction
    if signers.String() != req.Address {
        return nil, sdkerrors.ErrUnauthorized.Wrap("signer must match address")
    }
    ...
}
```

Alternatively, remove the `Address` field from the message and derive it from the signer directly.

### Proof of Concept
1. Alice (unprivileged) generates an age keypair: `age-keygen`.
2. Alice submits `MsgRegisterEncryptionKey{Address: <bridge_module_account_bech32>, Key: <alice_age_pubkey>}` signed by her own key.
3. The keeper writes Alice's key under the bridge module account address — no error is returned.
4. Query `Key(bridge_module_account)` — it now returns Alice's public key.
5. Any party encrypting to the bridge module account now encrypts to Alice's key; Alice can decrypt all such messages.

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

**File:** x/e2ee/types/tx.pb.go (L32-35)
```go
type MsgRegisterEncryptionKey struct {
	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Key     string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
}
```
