Audit Report

## Title
Fixed Gas Limit for All ckERC20 Withdrawals Causes Permanent ckETH Loss for High-Gas ERC-20 Tokens - (File: rs/ethereum/cketh/minter/src/withdraw.rs)

## Summary
The ckETH minter hardcodes a single gas limit of `65_000` for every ckERC20 withdrawal transaction, regardless of the specific ERC-20 token's actual gas requirements. When a supported ckERC20 token's `transfer()` call requires more than 65,000 gas, the Ethereum transaction fails out-of-gas, the ckERC20 principal is reimbursed, but the ckETH burned upfront to pay the transaction fee is permanently destroyed. The protocol documentation explicitly confirms this behavior: "Overcharged transaction fees are not reimbursed."

## Finding Description
Two constants are defined in `rs/ethereum/cketh/minter/src/withdraw.rs` at lines 43–44:

```rust
pub const CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(21_000);
pub const CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(65_000);
```

The function `estimate_gas_limit` at lines 296–301 returns `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT` for every ckERC20 withdrawal with no per-token differentiation:

```rust
pub fn estimate_gas_limit(withdrawal_request: &WithdrawalRequest) -> GasAmount {
    match withdrawal_request {
        WithdrawalRequest::CkEth(_) => CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
        WithdrawalRequest::CkErc20(_) => CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
    }
}
```

`create_transactions_batch` (lines 249–293) calls `estimate_gas_limit` and passes the result directly into every EIP-1559 transaction. The `withdraw_erc20` endpoint (lines 389–460 of `main.rs`) calls `estimate_erc20_transaction_fee()`, which internally uses `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT` via `eip_1559_transaction_price` (lines 173–189 of `main.rs`), and burns the resulting ckETH amount from the user before the Ethereum transaction is ever submitted.

On Ethereum transaction failure, the reimbursement logic (confirmed by the test `should_reimburse_tokens_when_ckerc20_withdrawal_fails` at line 1643 of `transactions/tests.rs`) creates only a `ReimbursementIndex::CkErc20` entry — returning the ckERC20 tokens — with no corresponding ckETH reimbursement entry. The documentation at line 275 of `rs/ethereum/cketh/docs/ckerc20.adoc` explicitly states: *"Overcharged transaction fees are not reimbursed."*

The exploit path is:
1. An NNS proposal legitimately adds a ckERC20 token whose underlying ERC-20 `transfer()` consumes >65,000 gas (e.g., fee-on-transfer, ERC-777 hooks, rebasing mechanics, or complex storage layouts).
2. An unprivileged user calls `withdraw_erc20` for that token.
3. The minter burns ckETH from the user based on the 65,000-gas fee estimate.
4. The minter burns the ckERC20 tokens and submits an Ethereum transaction with `gas_limit = 65_000`.
5. The Ethereum transaction reverts out-of-gas.
6. The minter reimburses only the ckERC20 tokens.
7. The ckETH burned in step 3 is permanently destroyed — real ETH held by the minter is effectively lost.

No existing guard prevents this: the `validate_ckerc20_active()` check only verifies the feature flag, and the token lookup only verifies the token is supported. Neither checks whether the token's gas requirements are compatible with the hardcoded limit.

## Impact Explanation
This is a **High** severity finding. ckETH is backed 1:1 by real ETH held by the minter canister. Permanent destruction of ckETH without a corresponding successful Ethereum transfer constitutes a concrete, irreversible loss of chain-key assets for affected users. This matches the allowed impact: *"Significant Chain Fusion, ck-token, ledger, Rosetta, boundary/API, XRC, Internet Identity, NNS, SNS, or infrastructure security impact with concrete user or protocol harm."* The per-transaction loss is bounded by the gas fee (65,000 gas × gas price), but the loss is repeatable across all users of the affected token and accumulates with each withdrawal attempt.

## Likelihood Explanation
The precondition — a supported ckERC20 token requiring >65,000 gas — requires an NNS governance proposal. However, this is a legitimate governance action, not a malicious one: the NNS is explicitly designed to add any ERC-20 token, and the protocol documentation acknowledges the 65,000 limit is only "sufficient for standard ERC-20 contracts." Tokens with fee-on-transfer logic, ERC-777 send hooks, or complex storage patterns are common in the ERC-20 ecosystem. Once such a token is added, any unprivileged user holding it can trigger the loss simply by calling `withdraw_erc20` — no special privileges, no social engineering, and no external compromise required. The loss is repeatable for every withdrawal attempt.

## Recommendation
Replace the single global `CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT` constant with a per-token configurable gas limit stored in the `CkErc20Token` state. The `AddCkErc20Token` governance message and `add_ckerc20_token` endpoint should accept an optional `gas_limit` field. The `estimate_gas_limit` function should look up the per-token value, falling back to `65_000` for tokens that do not specify one:

```diff
  pub fn estimate_gas_limit(withdrawal_request: &WithdrawalRequest) -> GasAmount {
      match withdrawal_request {
          WithdrawalRequest::CkEth(_) => CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
-         WithdrawalRequest::CkErc20(_) => CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
+         WithdrawalRequest::CkErc20(r) => r.gas_limit
+             .unwrap_or(CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT),
      }
  }
```

The same per-token value should be used in `eip_1559_transaction_price` so that fee estimates shown to users are accurate.

## Proof of Concept
A deterministic integration test can prove this without mainnet interaction:

1. Instantiate `EthTransactions` with a ckERC20 withdrawal request for a mock token.
2. Call `create_and_record_transaction` using `estimate_gas_limit`, confirming `gas_limit = 65_000`.
3. Simulate a `TransactionReceipt` with `status = Failure` and `gas_used = 65_000` (full gas consumed).
4. Call `record_finalized_transaction` and assert that `reimbursement_requests` contains only a `ReimbursementIndex::CkErc20` entry (ckERC20 tokens returned) and no `ReimbursementIndex::CkEth` entry (ckETH not returned).
5. Assert the ckETH burn amount from step 2 is non-zero and unrecovered.

This mirrors the existing test `should_reimburse_tokens_when_ckerc20_withdrawal_fails` at line 1643 of `rs/ethereum/cketh/minter/src/state/transactions/tests.rs`, which already demonstrates that only ckERC20 tokens are reimbursed on failure — confirming the permanent ckETH loss path.