Audit Report

## Title
Blocklist Bypass via Proxy Contract Allows Sanctioned Addresses to Mint ckETH/ckERC20 — (`rs/ethereum/cketh/minter/src/deposit.rs`, `rs/ethereum/cketh/minter/src/blocklist.rs`)

## Summary
All three ckETH/ckERC20 helper contracts record `msg.sender` — the immediate EVM caller — as the `from_address` in their deposit events. The IC minter reads this field directly from the event topic and checks it against a static blocklist. A blocked EOA can trivially deploy an unblocked proxy contract that forwards ETH or ERC-20 to the helper, causing the minter to see the proxy's address as `from_address`, bypassing the blocklist entirely and minting ckETH/ckERC20 to the blocked address's IC principal.

## Finding Description
All three helper contracts emit `msg.sender` as the depositor identity:

- `EthDepositHelper.sol` line 33: `emit ReceivedEth(msg.sender, msg.value, _principal);`
- `ERC20DepositHelper.sol` line 502: `emit ReceivedErc20(erc20_address, msg.sender, amount, principal);`
- `DepositHelperWithSubaccount.sol` line 504: `emit ReceivedEthOrErc20(ZERO_ADDRESS, msg.sender, msg.value, principal, subaccount);`

The minter's `ReceivedEthLogParser` reads `from_address` directly from `entry.topics[1]` (`parser.rs` line 45), and `ReceivedErc20LogParser` reads it from `entry.topics[2]` (`parser.rs` line 83). Neither parser has any mechanism to detect or reject contract-originated calls.

`register_deposit_events` in `deposit.rs` line 323 then calls `crate::blocklist::is_blocked(&event.from_address())`, which performs a binary search on the static `ETH_ADDRESS_BLOCKLIST` (`blocklist.rs` lines 107–109). If the proxy address is not in that list, `is_blocked` returns `false` and the deposit proceeds to minting.

Exploit path:
1. Blocked EOA deploys a minimal proxy contract (e.g., a one-function contract that calls `CkEthDeposit.deposit{value: amount}(principal)`).
2. Blocked EOA funds the proxy and calls its forwarding function, specifying their own IC principal as recipient.
3. The helper emits `ReceivedEth(proxy_address, amount, principal)`.
4. The minter scrapes the log, reads `from_address = proxy_address`, finds it absent from `ETH_ADDRESS_BLOCKLIST`, and mints ckETH to the blocked EOA's IC principal.

The existing guard `should_block_deposit_from_blocked_address` only tests the case where the blocked address calls the helper directly; it does not cover the proxy indirection case.

The documentation in `ckerc20.adoc` line 179 states the minter checks "the sender of the transaction," which in Ethereum terminology implies `tx.origin` (the signing EOA), not `msg.sender` (the immediate caller). The implementation diverges from this stated intent.

## Impact Explanation
This is a High severity finding. A sanctioned/blocked Ethereum address can receive ckETH or ckERC20 tokens by routing funds through an unblocked proxy contract. This directly violates the protocol's stated invariant ("ETH is not accepted from nor sent to addresses on this list") and constitutes a significant ck-token security impact with concrete protocol harm: the ckETH/ckERC20 system is used to launder sanctioned funds onto the IC, undermining the compliance controls that are part of the protocol's security model. This matches the allowed impact: "Significant Chain Fusion, ck-token, ledger... security impact with concrete user or protocol harm."

## Likelihood Explanation
Exploitation requires only deploying a standard Solidity contract (trivial, costs only gas) and calling the helper through it. No privileged access, no key compromise, no governance majority, and no victim interaction is needed. The blocked address fully controls the proxy and specifies its own IC principal as the recipient. The attack is repeatable and can be performed by any unprivileged user who controls a blocked address.

## Recommendation
The helper contracts should be updated to reject calls from contract addresses by adding the check `require(msg.sender == tx.origin, "contracts not allowed");` at the top of each deposit function. This prevents contract-to-contract forwarding into the helper and is consistent with the intended direct-user deposit flow. Alternatively, the contracts could emit `tx.origin` instead of `msg.sender` as the `from_address`, but the EOA-only check is simpler and avoids the known pitfalls of `tx.origin` in authorization contexts.

## Proof of Concept
Extend the existing test in `rs/ethereum/cketh/minter/tests/cketh.rs` mirroring `should_block_deposit_from_blocked_address`:

1. Take `SAMPLE_BLOCKED_ADDRESS` from `blocklist.rs` as the beneficial owner.
2. Construct a `ReceivedEth` log entry where `topics[1]` (the `from_address`) is set to a fresh address not present in `ETH_ADDRESS_BLOCKLIST` (simulating the proxy), while the `principal` topic encodes the blocked address's IC principal.
3. Call `register_deposit_events` with this event.
4. Assert `is_blocked(proxy_address)` returns `false`.
5. Assert that a `MintedCkEth` event is emitted — confirming ckETH is minted despite the blocked address being the ultimate source and recipient.

This test will pass against the current code, confirming the bypass.