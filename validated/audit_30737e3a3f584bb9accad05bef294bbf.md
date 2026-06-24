Audit Report

## Title
Fixed `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT` Causes Permanent Withdrawal Failure and Unrecoverable ckETH Loss for Non-Standard ERC-20 Tokens - (File: `rs/ethereum/cketh/minter/src/withdraw.rs`)

## Summary
The ckETH minter hardcodes a single gas limit of `65_000` for every ckERC20 withdrawal transaction via `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT`, with no per-token override mechanism. For any ERC-20 token whose `transfer` function consumes more than 65,000 gas, every withdrawal transaction will revert on Ethereum with out-of-gas. The ckERC20 tokens are reimbursed on failure, but the ckETH burned to pay the gas fee is permanently consumed, causing repeated financial loss with no recourse.

## Finding Description
In `rs/ethereum/cketh/minter/src/withdraw.rs` at lines 43–44, two constants define gas limits:

```rust
pub const CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(21_000);
pub const CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(65_000);
```

The `estimate_gas_limit` function at lines 296–301 unconditionally returns `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT` for every ckERC20 withdrawal, with no per-token override:

```rust
pub fn estimate_gas_limit(withdrawal_request: &WithdrawalRequest) -> GasAmount {
    match withdrawal_request {
        WithdrawalRequest::CkEth(_) => CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
        WithdrawalRequest::CkErc20(_) => CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
    }
}
```

This `gas_limit` is embedded directly into the EIP-1559 transaction at `rs/ethereum/cketh/minter/src/state/transactions/mod.rs` lines 1169–1183 (`gas_limit` field of `Eip1559TransactionRequest`). The documentation at `rs/ethereum/cketh/docs/ckerc20.adoc` line 270 explicitly acknowledges: *"The `gas_limit` for ckERC20 withdrawals is currently fixed to `65_000` and should be sufficient for standard ERC-20 contracts."* Line 275 of the same file states: *"Overcharged transaction fees are not reimbursed."* On `TransactionStatus::Failure`, the ckERC20 tokens are reimbursed but the ckETH gas fee is not, as confirmed by the documentation and the reimbursement logic. There is no per-token gas limit field in the token state, no governance parameter to adjust it per-token, and no user-facing mechanism to specify a higher limit.

## Impact Explanation
This is a **Medium** impact finding. For any ckERC20 token whose underlying ERC-20 `transfer` function requires more than 65,000 gas (fee-on-transfer tokens, rebasing tokens, tokens with hooks), every withdrawal transaction submitted to Ethereum will revert with out-of-gas. Each failed attempt permanently burns the user's ckETH gas fee with no reimbursement. The ckERC20 tokens are returned, so the user does not lose the token balance, but the bridge exit is permanently broken for that token type and the user loses ckETH on every retry. This fits the allowed impact: *"Significant Chain Fusion, ck-token, ledger... security impact with concrete user or protocol harm."* Severity is Medium rather than High because the loss per transaction is bounded to gas fees, the ckERC20 token balance is recoverable, and governance can deploy a fix.

## Likelihood Explanation
Likelihood is **Low**. Most currently supported ckERC20 tokens (USDC, USDT, WBTC) use well under 65,000 gas for `transfer`. However, the ckERC20 system is explicitly designed to support any ERC-20 token via governance proposals, and tokens with complex transfer logic routinely exceed 65,000 gas. No special attacker capability is required — any user who deposits such a token and attempts withdrawal triggers the loss. The scenario requires a governance proposal to first add a non-standard token, but once added, any user interacting with it is affected.

## Recommendation
1. **Per-token gas limit**: Add a `gas_limit: GasAmount` field to the `CkErc20Token` state struct, set at token registration time via `add_ckerc20_token`, with a default of `65_000` for backward compatibility.
2. **Governance upgrade path**: Expose an upgrade parameter to adjust the gas limit for an existing token if the initial estimate proves insufficient.
3. **On-chain estimation**: Optionally, use `eth_estimateGas` via the EVM RPC canister before submitting the withdrawal transaction to determine the actual gas required, and use that value plus a safety margin as the gas limit.

## Proof of Concept
1. A governance proposal adds a ckERC20 token whose underlying ERC-20 `transfer` function consumes 90,000 gas (e.g., a fee-on-transfer token).
2. A user deposits tokens via the ERC-20 helper contract and receives ckTOKEN on IC.
3. The user calls `withdraw_erc20`; the minter burns ckETH for gas fees and queues the withdrawal.
4. `create_transactions_batch` calls `estimate_gas_limit`, which returns `GasAmount::new(65_000)` unconditionally.
5. The minter submits an EIP-1559 transaction to Ethereum with `gas_limit: 65_000`.
6. The Ethereum transaction reverts with out-of-gas (the token's `transfer` needed 90,000 gas).
7. The minter detects `TransactionStatus::Failure`, reimburses the ckTOKEN, but does **not** reimburse the ckETH gas fee.
8. Every subsequent withdrawal attempt repeats steps 3–7, draining the user's ckETH balance with no possibility of success.
9. A deterministic integration test can be written using the existing `ckerc20.rs` test harness by deploying a mock ERC-20 contract whose `transfer` function consumes >65,000 gas and verifying that the ckETH balance decreases after each failed withdrawal while the ckERC20 balance is restored.