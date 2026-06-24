Audit Report

## Title
Unsolicited Token Deposits Inflate Treasury Balance, Triggering Stricter Governance Proposal Limits - (File: rs/sns/governance/token_valuation/src/lib.rs)

## Summary

`try_get_balance_valuation_factors` reads the SNS treasury balance live from the ledger via `icrc1_balance_of`. Because the treasury accounts are ordinary ICRC-1 accounts, any unprivileged user can inflate the observed balance by sending tokens directly via `icrc1_transfer`. This inflated balance is used at proposal submission time to classify the treasury into a spending regime, and can push a treasury from the permissive `NoLimit` regime into the more restrictive `Fraction(0.25)` regime, causing previously-valid `TransferSnsTreasuryFunds` and `MintSnsTokens` proposals to be rejected at submission.

## Finding Description

In `rs/sns/governance/token_valuation/src/lib.rs` (L154), `try_get_balance_valuation_factors` fetches the treasury balance live:

```rust
let balance_of_request = icrc1_client.icrc1_balance_of(account);
```

The result is used directly as `valuation_factors.tokens` (L177–181) and returned as a `Valuation`. This `Valuation` is passed to `ProposalsAmountTotalUpperBound::in_tokens` in `rs/sns/governance/proposals_amount_total_limit/src/lib.rs` (L66–114), which classifies the treasury into three regimes via `from_valuation_xdr` (L116–135):

- ≤ 100,000 XDR → `NoLimit`: upper bound = 100% of balance
- ≤ 1,200,000 XDR → `Fraction(0.25)`: upper bound = 25% of balance
- > 1,200,000 XDR → `Xdr(300_000)`: upper bound = fixed 300,000 XDR

The proposal submission path in `rs/sns/governance/src/proposal.rs` (L770–816) calls `treasury_valuation_if_proposal_amount_is_small_enough_or_err`, which calls `assess_treasury_balance` in `rs/sns/governance/src/treasury.rs` (L256–269), which calls `token.assess_balance(...)` → `try_get_balance_valuation_factors`. The resulting `Valuation` is snapshotted into `ProposalData.action_auxiliary` at submission time and reused at execution time (confirmed in `rs/sns/governance/src/governance.rs` L2203–2210 and `rs/sns/governance/src/proposal.rs` L2600–2659).

The SNS token treasury account is `governance_canister_id` + subaccount `compute_distribution_subaccount_bytes(governance_canister_id, TREASURY_SUBACCOUNT_NONCE)` (where `TREASURY_SUBACCOUNT_NONCE = 0`, defined in `rs/sns/governance/src/governance.rs` L178). The ICP treasury account is the governance canister's default account (no subaccount). Both are deterministic, publicly derivable, and accept permissionless ICRC-1 transfers. There is no guard in `try_get_balance_valuation_factors` or anywhere in the proposal validation path that discounts unsolicited deposits.

## Impact Explanation

This is an application-level DoS on SNS governance proposal submission. An attacker can block any `TransferSnsTreasuryFunds` or `MintSnsTokens` proposal that would transfer more than 25% of the (now inflated) treasury balance. For a treasury near the 100,000 XDR boundary, a small donation (e.g., 10,001 XDR worth of tokens) is sufficient to cross the regime boundary and reduce the per-7-day allowance from 100% to 25% of the inflated balance. Time-sensitive governance actions (emergency fund movements, large disbursements) can be blocked indefinitely as long as the attacker continues to top up the treasury. This matches the allowed High impact class: "Application/platform-level DoS... on SNS governance... with concrete user or protocol harm."

## Likelihood Explanation

The attack requires only: (1) holding any amount of the SNS token (or ICP for the ICP treasury), and (2) calling `icrc1_transfer` to the deterministic, publicly known treasury account. No privileged access, key compromise, or social engineering is required. The treasury account address is fully derivable from the governance canister principal. The attacker's tokens are not destroyed — they are donated to the treasury — so the net cost is only the opportunity cost of those tokens. The attack is repeatable and can be sustained indefinitely.

## Recommendation

At proposal submission time, use the minimum of the live ledger balance and a governance-internal baseline (e.g., the balance recorded after the last executed `TransferSnsTreasuryFunds` or `MintSnsTokens` proposal, plus any officially recorded deposits). Alternatively, maintain an internal ledger of treasury inflows that were authorized through governance, and use that figure rather than the raw live balance for regime classification. At minimum, the regime classification should be based on a floor value that cannot be inflated by unsolicited external transfers.

## Proof of Concept

1. Identify an SNS whose treasury XDR value is just below 100,000 XDR (i.e., in the `NoLimit` regime). For example: 90,000 SNS tokens at 1 XDR/token = 90,000 XDR.
2. Derive the treasury subaccount: `compute_distribution_subaccount_bytes(governance_canister_id, 0)`.
3. Call `icrc1_transfer` on the SNS ledger, sending 10,001 SNS tokens to `Account { owner: governance_canister_id, subaccount: Some(treasury_subaccount) }`.
4. The treasury now holds 100,001 tokens (100,001 XDR), crossing into `Fraction(0.25)`. The new 7-day upper bound is `100,001 × 0.25 ≈ 25,000 tokens`.
5. Submit a `TransferSnsTreasuryFunds` proposal for 80,000 tokens. Observe it is rejected at submission with "Amount is too large."
6. To reproduce as an integration test: use PocketIC (as in `rs/nervous_system/integration_tests/tests/sns_lifecycle.rs`) to set up an SNS with a treasury near the 100,000 XDR boundary, perform an `icrc1_transfer` to the treasury subaccount from an unprivileged principal, then attempt to submit a large `TransferSnsTreasuryFunds` proposal and assert it is rejected.