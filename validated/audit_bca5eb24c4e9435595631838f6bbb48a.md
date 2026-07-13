### Title
Unprivileged Overwrite of Any Address's E2EE Encryption Key — (`x/e2ee/keeper/keeper.go`)

### Summary
`RegisterEncryptionKey` stores an encryption key for an arbitrary `req.Address` without verifying that the transaction signer is that address. Any unprivileged user can overwrite any validator's registered public key, corrupting the e2ee key state and permanently preventing that validator from decrypting future blocklist updates.

### Finding Description

The `RegisterEncryptionKey` keeper method unconditionally writes the supplied key for `req.Address`: [1](#0-0) 

There is no check that the transaction signer equals `req.Address`. The inner helper `registerEncryptionKey` simply does a raw KV store write: [2](#0-1) 

The analog to the external report is exact: just as `validateOrderParam` never consulted the `cancelled` mapping it was supposed to gate on, `RegisterEncryptionKey` never consults the signer identity it is supposed to gate on. The state-write path exists; the guard does not.

### Impact Explanation

The e2ee keys are the per-validator public keys used to encrypt the on-chain blocklist blob. The `ProposalHandler.SetBlockList` decrypts the blob with the validator's `age.Identity`; if decryption fails (because the stored public key no longer matches the validator's private key), `SetBlockList` returns an error and the in-memory blocklist is not updated: [3](#0-2) 

An attacker who overwrites a validator's registered key with an attacker-controlled key causes every subsequent `MsgStoreBlockList` to be undecryptable by that validator. The validator's in-memory blocklist freezes at its last successfully decrypted value. The `ProcessProposalHandler` then operates on a stale or empty blocklist: [4](#0-3) 

This is a **High** impact: corruption of e2ee key/message state with direct security impact, and bypass of the block-list authorization mechanism. An attacker who is themselves on the blocklist can corrupt all validators' keys before the blocklist takes effect, permanently preventing the admin from enforcing new blocklist entries against them.

### Likelihood Explanation

The entry point is a standard Cosmos SDK message (`MsgRegisterEncryptionKey`) reachable by any unprivileged account with gas. No special role, leaked key, or validator compromise is required. The attacker only needs to know the target validator's bech32 address (publicly visible on-chain) and submit a well-formed message with `Address = <validator_address>` and `Key = <attacker_key>`.

### Recommendation

Add a signer-equality check at the top of `RegisterEncryptionKey`:

```go
func (k Keeper) RegisterEncryptionKey(
    ctx context.Context,
    req *types.MsgRegisterEncryptionKey,
) (*types.MsgRegisterEncryptionKeyResponse, error) {
    signers, err := signerFromContext(ctx) // extract tx signer
    if err != nil || signers[0] != req.Address {
        return nil, errors.Wrap(sdkerrors.ErrUnauthorized,
            "signer must match the address being registered")
    }
    if err := k.registerEncryptionKey(ctx, req.Address, []byte(req.Key)); err != nil {
        return nil, err
    }
    return &types.MsgRegisterEncryptionKeyResponse{}, nil
}
```

### Proof of Concept

1. Validator V has registered public key `PK_V` via `MsgRegisterEncryptionKey{Address: V, Key: PK_V}`.
2. Attacker A generates a fresh age keypair `(SK_A, PK_A)`.
3. A submits `MsgRegisterEncryptionKey{Address: V, Key: PK_A}` signed by A's own key. The keeper writes `PK_A` at V's address with no error.
4. Admin encrypts a new blocklist (adding A to it) with all registered validator keys — including the now-attacker-controlled `PK_A` for V — and submits `MsgStoreBlockList`.
5. V calls `SetBlockList` with the new blob. `age.Decrypt` fails because V's private key does not match `PK_A`. V's in-memory blocklist is not updated; A remains unblocked from V's perspective.
6. V proposes and processes blocks without filtering A's transactions, effectively bypassing the blocklist for A on V's node. [1](#0-0) [5](#0-4) [6](#0-5)

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

**File:** app/proposal.go (L209-260)
```go
// SetBlockList don't fail if the identity is not set or the block list is empty.
func (h *ProposalHandler) SetBlockList(blob []byte) error {
	if h.Identity == nil {
		return nil
	}

	if bytes.Equal(h.lastBlockList, blob) {
		return nil
	}
	h.lastBlockList = make([]byte, len(blob))
	copy(h.lastBlockList, blob)

	if len(blob) == 0 {
		h.blocklist = make(map[string]struct{})
		return nil
	}

	reader, err := age.Decrypt(bytes.NewBuffer(blob), h.Identity)
	if err != nil {
		return err
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	var blocklist BlockList
	if err := json.Unmarshal(data, &blocklist); err != nil {
		return err
	}

	// convert to map
	m := make(map[string]struct{}, len(blocklist.Addresses))
	for _, s := range blocklist.Addresses {
		addr, err := h.addressCodec.StringToBytes(s)
		if err != nil {
			return fmt.Errorf("invalid bech32 address: %s, err: %w", s, err)
		}
		if IsUnblockable(addr) {
			continue
		}
		encoded, err := h.addressCodec.BytesToString(addr)
		if err != nil {
			return fmt.Errorf("invalid bech32 address: %s, err: %w", s, err)
		}
		m[encoded] = struct{}{}
	}

	h.blocklist = m
	return nil
}
```

**File:** app/proposal.go (L338-353)
```go
func (h *ProposalHandler) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		if len(h.blocklist) == 0 {
			// fast path, accept all txs
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
		}

		for _, txBz := range req.Txs {
			if err := h.ValidateTransaction(nil, txBz); err != nil {
				return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
			}
		}

		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
	}
}
```

**File:** x/cronos/keeper/msg_server.go (L118-126)
```go
func (k msgServer) StoreBlockList(goCtx context.Context, msg *types.MsgStoreBlockList) (*types.MsgStoreBlockListResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
	ctx.KVStore(k.storeKey).Set(types.KeyPrefixBlockList, msg.Blob)
	return &types.MsgStoreBlockListResponse{}, nil
}
```
