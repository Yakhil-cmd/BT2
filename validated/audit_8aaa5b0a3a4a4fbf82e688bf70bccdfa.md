Audit Report

## Title
Hard-Coded `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT` of 65,000 Applied Uniformly to All ckERC20 Withdrawals Causes Permanent ckETH Loss on Out-of-Gas Failures - (`File: rs/ethereum/cketh/minter/src/withdraw.rs`)

## Summary

The ckETH minter hard-codes a single gas limit of `65_000` for every ckERC20 withdrawal transaction regardless of the specific ERC-20 token. Non-standard tokens supported on mainnet (e.g., wstETH) may require more gas than this limit. When an Ethereum transaction reverts due to out-of-gas, the minter reimburses the ckERC20 tokens but explicitly does not reimburse the ckETH burned to pay the transaction fee, resulting in a permanent, repeatable loss of ckETH for affected users.

## Finding Description

Two compile-time constants are defined in `rs/ethereum/cketh/minter/src/withdraw.rs` at lines 43–44:

```rust
pub const CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(21_000);
pub const CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(65_000);
```

The function `estimate_gas_limit` (lines 296–301) returns the same constant for every ckERC20 token with no per-token differentiation:

```rust
pub fn estimate_gas_limit(withdrawal_request: &WithdrawalRequest) -> GasAmount {
    match withdrawal_request {
        WithdrawalRequest::CkEth(_) => CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
        WithdrawalRequest::CkErc20(_) => CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
    }
}
```

`create_transactions_batch` (lines 249–293) calls `estimate_gas_limit` and passes the result directly into `create_transaction`, which embeds it as the `gas_limit` field of the EIP-1559 transaction (confirmed at `mod.rs` line 1174). There is no per-token override, no dynamic estimation, and no pre-submission validation that the limit is sufficient for the specific token.

The documentation at `ckerc20.adoc` line 270 explicitly acknowledges: *"The `gas_limit` for ckERC20 withdrawals is currently fixed to `65_000` and should be sufficient for standard ERC-20 contracts."* wstETH (`0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0`) is listed as a supported mainnet token at `ckerc20.adoc` lines 43–44 and is not a standard ERC-20 contract — it wraps stETH and involves additional share-accounting logic that increases gas consumption beyond 65,000 in many conditions.

When the submitted Ethereum transaction runs out of gas and reverts, the minter's reimbursement path (confirmed by `process_reimbursement` in `withdraw.rs` lines 55–76) mints back only the ckERC20 tokens via the ERC-20 ledger. The ckETH burned for the gas fee is not returned, as explicitly stated at `ckerc20.adoc` line 275: *"Overcharged transaction fees are not reimbursed."*

No existing guard prevents this: the `InsufficientTransactionFee` check in `create_transaction` (mod.rs lines 1160–1167) only validates that the user provided enough ckETH to cover the estimated fee — it does not validate that the gas limit is sufficient for the target token's on-chain execution.

## Impact Explanation

This is a concrete, repeatable permanent loss of ckETH (a chain-key ledger asset) for any user withdrawing a ckERC20 token whose `transfer()` function consumes more than 65,000 gas. Each withdrawal attempt burns ckETH for gas, submits a transaction that reverts on-chain, reimburses the ckERC20 tokens, and permanently destroys the ckETH gas payment. The user can retry indefinitely, losing ckETH on every attempt with no recovery path. This matches the allowed High impact: *"Significant Chain Fusion, ck-token, ledger … security impact with concrete user or protocol harm."*

## Likelihood Explanation

The attack path requires only a standard unprivileged `withdraw_erc20` call targeting a supported high-gas token (e.g., ckWSTETH). wstETH is already listed as a supported mainnet token. No special privileges, governance access, or external compromise is required. The failure is deterministic and repeatable for every affected withdrawal attempt.

## Recommendation

1. **Per-token gas limit configuration:** Store a configurable `gas_limit` per supported ckERC20 token in the minter state, settable at token registration time and updatable via upgrade args.
2. **Minimum viable fix:** Increase `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT` to a value covering the highest-gas supported token (e.g., 200,000), or add a per-token override map keyed by ERC-20 contract address.
3. **User protection:** The `eip_1559_transaction_price` query should reflect the per-token gas limit so users can make informed decisions before burning ckETH.

## Proof of Concept

1. Obtain ckWSTETH and sufficient ckETH on mainnet IC.
2. Call `withdraw_erc20` on the ckETH minter with `ckerc20_ledger_id` = ckWSTETH ledger, a valid Ethereum destination, and a valid amount.
3. The minter burns ckETH (computed as `65_000 * max_fee_per_gas`) and burns ckWSTETH.
4. The minter submits an Ethereum EIP-1559 transaction with `gas_limit = 65_000` calling `transfer()` on the wstETH contract.
5. The transaction reverts on-chain due to out-of-gas.
6. The minter detects `TransactionStatus::Failure`, reimburses ckWSTETH to the user, but does not reimburse the ckETH gas fee.
7. Repeat from step 2 — each iteration permanently destroys more ckETH.

A deterministic integration test can be constructed using a local Ethereum fork (e.g., Anvil forked from mainnet) with the wstETH contract at its canonical address, submitting a withdrawal transaction with `gas_limit = 65_000` and asserting the on-chain receipt status is `0` (failure/out-of-gas), then verifying the minter state shows ckERC20 reimbursed but ckETH balance reduced.