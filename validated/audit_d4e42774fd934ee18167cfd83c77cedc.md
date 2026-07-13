### Title
Blocklist Enforcement Bypass via Same-Block Front-Running of `MsgStoreBlockList` — (File: `app/proposal.go`)

---

### Summary

`ProcessProposalHandler` and `PrepareProposal` both enforce the blocklist using an in-memory map (`ProposalHandler.blocklist`) that is only updated **after** a block containing `MsgStoreBlockList` is committed. A malicious address that is about to be blocked can front-run the `MsgStoreBlockList` transaction by submitting a higher-gas-price transaction in the same block, ordered before `MsgStoreBlockList`. Because the in-memory blocklist has not yet been updated when `ProcessProposalHandler` runs, the malicious transaction passes validation and executes successfully, bypassing the intended block-list restriction.

---

### Finding Description

The blocklist enforcement in Cronos is split across two layers:

**Layer 1 — Mempool admission (`BlockAddressesDecorator`):** [1](#0-0) 

`AnteHandle` only runs its blocklist check when `ctx.IsCheckTx()` is true. During `DeliverTx` (block execution), the entire check is skipped. A transaction that was admitted to the mempool before the address was blocked, or that bypasses `CheckTx` entirely (e.g., via a validator's direct inclusion), will never be re-validated by this decorator at execution time.

**Layer 2 — Proposal-time enforcement (`ProposalHandler`):** [2](#0-1) 

Both `PrepareProposal` (via `ExtTxSelector.SelectTxForProposal` → `validateTx`) and `ProcessProposalHandler` call `ValidateTransaction`, which checks the in-memory `h.blocklist` map: [3](#0-2) 

This in-memory map is populated exclusively by `SetBlockList`: [4](#0-3) 

`SetBlockList` is called after a committed block is read — it decrypts the blob that `MsgStoreBlockList` wrote to the KV store: [5](#0-4) 

**The race window:** `ProcessProposalHandler` runs *before* the block is executed (it validates the proposed block). The in-memory `h.blocklist` therefore reflects the state from the *previous* committed block. If `MsgStoreBlockList` is included in block N, the in-memory blocklist is only updated after block N commits — meaning for the entire duration of block N's proposal and processing, the newly blocked address is still absent from `h.blocklist`.

A malicious address that monitors the mempool can:
1. Observe the pending `MsgStoreBlockList` transaction targeting them.
2. Submit their own transaction (e.g., a bridge-out or fund transfer) with a higher gas price.
3. The proposer's `PrepareProposal` selects both transactions, ordering the attacker's tx first (higher priority).
4. `ProcessProposalHandler` on all validators uses the stale in-memory blocklist and accepts the block.
5. The attacker's transaction executes before `MsgStoreBlockList`, successfully bypassing the block.

---

### Impact Explanation

**High — Bypass of block-list authorization checks.**

The blocklist is Cronos's mechanism to prevent sanctioned or malicious addresses from transacting. A successful front-run allows the targeted address to execute an arbitrary transaction (e.g., `MsgConvertVouchers`, IBC `MsgTransferTokens`, EVM transfer, Gravity Bridge `send_to_evm_chain`) in the same block as the blocklist update, before the restriction takes effect. This directly undermines the security guarantee of the blocklist and can result in unauthorized asset movement.

---

### Likelihood Explanation

Moderate. The attacker must monitor the public mempool for `MsgStoreBlockList` transactions and respond within the same block window. This is straightforward for any address running a full node or watching the RPC. The only constraint is that the attacker must outbid the admin's gas price, which is trivially achievable.

---

### Recommendation

`ProcessProposalHandler` and `PrepareProposal` should read the blocklist directly from the committed KV store state (via the Cosmos SDK context) rather than relying on the stale in-memory `h.blocklist`. Alternatively, `MsgStoreBlockList` should be processed in `BeginBlock` (or an equivalent pre-tx hook) so that the blocklist is updated before any user transactions in the same block are validated. A simpler mitigation is to enforce that `MsgStoreBlockList` is always placed as the first transaction in a block by the proposer, and that `ProcessProposalHandler` re-reads the on-chain blob after processing any `MsgStoreBlockList` tx it finds in the proposal.

---

### Proof of Concept

1. Admin broadcasts `MsgStoreBlockList` (blob encrypting `{"addresses": ["crc1attacker..."]}`) to the mempool.
2. Attacker's node observes the pending tx via the public RPC mempool endpoint.
3. Attacker broadcasts `MsgConvertVouchers` (or an EVM transfer) from `crc1attacker...` with `gasPrice` higher than the admin's tx.
4. The block proposer runs `PrepareProposal`: `ExtTxSelector.SelectTxForProposal` calls `ValidateTransaction` for both txs. `h.blocklist` does not yet contain `crc1attacker...` (last committed block predates the admin's tx), so both pass.
5. The attacker's tx is ordered first (higher gas price); `MsgStoreBlockList` is second.
6. All validators run `ProcessProposalHandler` with the same stale `h.blocklist` → block is ACCEPTED.
7. Block executes: attacker's `MsgConvertVouchers` succeeds (funds converted/moved); `MsgStoreBlockList` then writes the new blob to KV store.
8. After commit, `SetBlockList` updates `h.blocklist` — but the attacker has already transacted. [6](#0-5) [7](#0-6)

### Citations

**File:** app/block_address.go (L32-33)
```go
func (bad BlockAddressesDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	if ctx.IsCheckTx() {
```

**File:** app/proposal.go (L76-84)
```go
func (ts *ExtTxSelector) SelectTxForProposal(goCtx context.Context, maxTxBytes, maxBlockGas uint64, memTx sdk.Tx, txBz []byte) bool {
	// returned bool = stop iterating; true once the block is full.
	isFull := func() bool {
		return uint64(ts.totalBytes) >= maxTxBytes || (maxBlockGas > 0 && ts.totalGas >= maxBlockGas)
	}

	if err := ts.validateTx(memTx, txBz); err != nil {
		return isFull() // blocked/invalid: skip, keep scanning
	}
```

**File:** app/proposal.go (L191-196)
```go
type ProposalHandler struct {
	TxDecoder sdk.TxDecoder
	// Identity is nil if it's not a validator node
	Identity      age.Identity
	blocklist     map[string]struct{}
	lastBlockList []byte
```

**File:** app/proposal.go (L210-259)
```go
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
```

**File:** app/proposal.go (L262-293)
```go
func (h *ProposalHandler) ValidateTransaction(tx sdk.Tx, txBz []byte) error {
	if len(h.blocklist) == 0 {
		// fast path, accept all txs
		return nil
	}

	var err error
	if tx == nil {
		tx, err = h.TxDecoder(txBz)
		if err != nil {
			return err
		}
	}

	sigTx, ok := tx.(signing.SigVerifiableTx)
	if !ok {
		return fmt.Errorf("tx of type %T does not implement SigVerifiableTx", tx)
	}

	signers, err := sigTx.GetSigners()
	if err != nil {
		return err
	}
	for _, signer := range signers {
		encoded, err := h.addressCodec.BytesToString(signer)
		if err != nil {
			return fmt.Errorf("invalid bech32 address: %s, err: %w", signer, err)
		}
		if _, ok := h.blocklist[encoded]; ok {
			return fmt.Errorf("signer is blocked: %s", encoded)
		}
	}
```

**File:** app/proposal.go (L338-352)
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
```

**File:** x/cronos/keeper/msg_server.go (L118-125)
```go
func (k msgServer) StoreBlockList(goCtx context.Context, msg *types.MsgStoreBlockList) (*types.MsgStoreBlockListResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	admin := k.Keeper.GetParams(ctx).CronosAdmin
	if admin != msg.From {
		return nil, errors.Wrap(sdkerrors.ErrUnauthorized, "msg sender is not authorized")
	}
	ctx.KVStore(k.storeKey).Set(types.KeyPrefixBlockList, msg.Blob)
	return &types.MsgStoreBlockListResponse{}, nil
```
