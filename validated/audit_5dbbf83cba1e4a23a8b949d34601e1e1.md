### Title
Blocklist Enforcement Bypassed via Intermediate Smart Contract — (`app/proposal.go`, `app/block_address.go`)

### Summary
Cronos enforces its address blocklist only on the **outer transaction envelope** (tx signer and direct `ethTx.To()` destination). An unprivileged attacker can deploy an intermediary contract that receives funds from a non-blocked sender and forwards them to a blocked address via an internal EVM call, bypassing the blocklist entirely.

### Finding Description

The blocklist enforcement in Cronos operates at two points:

**1. `BlockAddressesDecorator.AnteHandle` (mempool admission, CheckTx only)** [1](#0-0) 

This checks only the tx signer and the direct `ethTx.To()` field.

**2. `ProposalHandler.ValidateTransaction` (block proposal)** [2](#0-1) 

Same scope: only the outer tx signer and the direct `ethTx.To()` destination are checked.

Neither check inspects **internal EVM calls** (contract-to-contract calls that occur during EVM execution). The EVM's internal call graph is never traversed.

**Bypass path:**

1. Attacker deploys intermediary contract `C` (address not on blocklist).
2. Attacker (non-blocked EOA `A`) sends a transaction to `C`.
3. `ValidateTransaction` checks: signer `A` — not blocked; `ethTx.To()` = `C` — not blocked. Transaction is admitted to the block.
4. During EVM execution, `C` internally calls `transfer()` / `send()` / `call{value:...}()` to forward ETH or CRC20/CRC21 tokens to blocked address `B`.
5. `B` receives the assets. No blocklist check ever fires on the internal call.

The existing integration test `test_block_list_contract` only validates that a tx whose **direct destination** is a blocked address is filtered: [3](#0-2) 

It does not test the case where the blocked address is reached via an internal call through an unblocked intermediary contract.

### Impact Explanation

This is a **High** impact finding under the allowed scope: **"Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks."**

The blocklist is a compliance/security control (used for sanctions enforcement via the e2ee-encrypted blocklist delivery system). Bypassing it allows a blocked address to receive CRO, IBC vouchers, CRC20, or CRC21 tokens through an intermediary contract, defeating the purpose of the control entirely.

### Likelihood Explanation

Likelihood is **high**. The bypass requires only:
- Deploying a simple forwarding contract (any unprivileged user can do this).
- No special permissions, leaked keys, or cryptographic breaks.
- The intermediary contract can be made to look innocuous (e.g., a DEX, a multisig, a wrapper).

The blocklist check architecture is fundamentally limited to the outer transaction layer and cannot see into EVM execution without a dedicated EVM-level hook.

### Recommendation

Enforce blocklist checks at the EVM execution layer, not only at the transaction admission layer. Options include:

1. **EVM-level hook**: Intercept every `CALL`, `DELEGATECALL`, and `STATICCALL` opcode that transfers value and check both `from` and `to` against the blocklist. Ethermint's `StateDB` interface exposes hooks that can be used for this.
2. **Precompile-level enforcement**: The `BankContract` precompile already calls `checkBlockedAddr` on recipients: [4](#0-3) 
   Extend this pattern to native ETH value transfers at the EVM level.
3. **EVM hooks on `SendToIbc` / `SendToEvmChain`**: The `SendToIbcHandler` resolves `sender` from the event log data (which a contract can forge to be any address): [5](#0-4) 
   Validate the resolved sender against the blocklist before initiating the IBC transfer.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deploy this contract. Its address is NOT on the blocklist.
contract BlocklistBypass {
    // blocked_addr is on the Cronos blocklist
    address payable public blocked_addr;

    constructor(address payable _blocked) {
        blocked_addr = _blocked;
    }

    // Attacker (non-blocked EOA) calls this with ETH.
    // The outer tx: signer=attacker (not blocked), To=this contract (not blocked).
    // ValidateTransaction passes. EVM executes and forwards to blocked_addr.
    function forward() external payable {
        blocked_addr.transfer(msg.value);
    }
}
```

Steps:
1. Admin adds `blocked_addr` to the Cronos blocklist via `MsgStoreBlockList`.
2. Attacker deploys `BlocklistBypass` with `blocked_addr` as constructor argument.
3. Attacker calls `forward{value: 1 ether}()` on the contract.
4. `ValidateTransaction` sees signer=attacker (not blocked), `ethTx.To()`=`BlocklistBypass` (not blocked) — transaction is included in the block.
5. EVM executes `blocked_addr.transfer(msg.value)` — `blocked_addr` receives 1 ETH.
6. Blocklist enforcement is bypassed.

### Citations

**File:** app/block_address.go (L46-55)
```go
		for _, msg := range tx.GetMsgs() {
			msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
			if ok {
				ethTx := msgEthTx.AsTransaction()
				// check the destination address
				if ethTx.To() != nil {
					if _, ok := bad.blockedMap[sdk.AccAddress(ethTx.To().Bytes()).String()]; ok {
						return ctx, fmt.Errorf("destination address is blocked: %s", sdk.AccAddress(ethTx.To().Bytes()).String())
					}
				}
```

**File:** app/proposal.go (L295-308)
```go
	for _, msg := range tx.GetMsgs() {
		msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
		if ok {
			ethTx := msgEthTx.AsTransaction()
			// check the destination address
			if ethTx.To() != nil {
				encoded, err := h.addressCodec.BytesToString(ethTx.To().Bytes())
				if err != nil {
					return fmt.Errorf("invalid bech32 address: %s, err: %w", ethTx.To(), err)
				}
				if _, ok := h.blocklist[encoded]; ok {
					return fmt.Errorf("destination address is blocked: %s", encoded)
				}
			}
```

**File:** integration_tests/test_e2ee.py (L230-259)
```python
def test_block_list_contract(cronos):
    gen_validator_identity(cronos)
    cli = cronos.cosmos_cli()
    user = cli.address("signer2")
    blocked_destination = cli.address("signer1")
    # set blocklist
    encrypt_to_validators(cli, {"addresses": [blocked_destination]})
    tx = {
        "from": to_checksum_address(bech32_to_eth(user)),
        "to": to_checksum_address(bech32_to_eth(blocked_destination)),
        "value": 1,
    }
    base_port = cronos.base_port(0)
    wait_for_port(ports.evmrpc_ws_port(base_port))
    w3 = cronos.w3
    flt = w3.eth.filter("pending")
    assert flt.get_new_entries() == []

    txhash = w3.eth.send_transaction(tx).hex()
    nonce = get_nonce(cli, user)
    # check tx in mempool
    assert HexBytes(txhash) in w3.eth.get_filter_changes(flt.filter_id)

    # clear blocklist
    encrypt_to_validators(cli, {})

    # the blocked tx should be unblocked now
    wait_for_new_blocks(cli, 1)
    assert nonce + 1 == get_nonce(cli, user)
    assert w3.eth.get_filter_changes(flt.filter_id) == []
```

**File:** x/cronos/keeper/precompiles/bank.go (L92-101)
```go
func (bc *BankContract) checkBlockedAddr(addr sdk.AccAddress) error {
	to, err := sdk.AccAddressFromBech32(addr.String())
	if err != nil {
		return err
	}
	if bc.bankKeeper.BlockedAddr(to) {
		return errorsmod.Wrapf(errortypes.ErrUnauthorized, "%s is not allowed to receive funds", to.String())
	}
	return nil
}
```

**File:** x/cronos/keeper/evmhandlers/send_to_ibc.go (L80-83)
```go
	sender := unpacked[0].(common.Address)
	recipient := unpacked[1].(string)
	amount := unpacked[2].(*big.Int)
	return h.handle(ctx, contract, sender, recipient, amount, nil)
```
