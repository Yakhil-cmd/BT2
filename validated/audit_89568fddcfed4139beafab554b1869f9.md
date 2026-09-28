### Title
`flash_position` callback tokens pushed to the controller outside declared collateral/refund lists are permanently locked — no recovery mechanism exists - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
The controller settles `flash_position` callbacks by measuring balance deltas only for tokens explicitly named in `collaterals` (deposited to the account) or `refund_assets` (returned to `caller`). Any other token the receiver transfers to the controller during the callback — including the borrowed debt asset itself when it is not declared — is neither credited to the account, nor used to repay the minted debt, nor refunded. The controller exposes no sweep/rescue endpoint, so those tokens are permanently locked. This mirrors the H-01 class: funds routed to the contract address with no withdrawal path.

### Finding Description
In `process_flash_position`, after `invoke_receiver` returns, settlement is strictly list-driven:

- `collect_collateral_deposits` iterates only over `collaterals` and deposits each asset's measured delta (`flash_position.rs:325-352`).
- `refund_listed_assets` iterates only over `refund_assets` and refunds each asset's measured delta to `caller` (`flash_position.rs:372-384`).
- `validate_refund_assets` forbids overlap between the two lists and requires refund assets to be listed in the account's spoke (`flash_position.rs:217-256`).

There is no third branch: a positive controller balance delta in any undeclared asset is simply ignored. The endpoint reference confirms this is intentional-but-lossy: "Undeclared callback assets receive neither credit nor refunds. There is no controller sweep endpoint" (`docs/reference/endpoints.md:86`), and INV-STRAT-04 states returned debt "can become declared collateral, be refunded when refund-listed, or remain uncredited" (`docs/reference/invariants.md:685-689`). The test `test_flash_position_returning_debt_token_does_not_repay` proves the debt-token variant: returning the minted debt token does not reduce `scaled_amount` (`tests/test-harness/tests/strategy/flash_position.rs:331-358`).

Two concrete strands:

1. A receiver contract that swaps only part of the borrowed amount and pushes the unused `debt.asset` back to `controller`, while the caller omitted `debt.asset` from `refund_assets`, leaves the full borrowed balance sitting on the controller with the debt still minted and accruing interest.
2. A receiver that delivers collateral in a token different from what was declared (e.g., a route ending in an adjacent asset) pushes tokens that are stranded even though the call may still succeed via other declared collateral minima.

Notably, `borrow`/`withdraw` explicitly reject the pool/controller as recipients precisely because "the controller holds funds no balance-delta measurement can ever claim" (`tests/test-harness/tests/controller/recipient_is_protocol_contract.rs:1-5`) — the same reasoning applies to inbound flows, which have no equivalent guard.

### Impact Explanation
Permanent freezing of funds. Tokens left on the controller after `flash_position` settlement are unrecoverable by any user or admin path — no endpoint moves arbitrary controller-held balances. In the debt-token case the loss is doubled: the tokens are locked and the account still owes the full minted debt plus interest, degrading its health factor.

### Likelihood Explanation
Medium. Reaching it requires only an unprivileged `flash_position` call with the caller's own receiver — an explicitly supported composition pattern. The failure modes are ordinary integration mistakes (omitting the debt asset from `refund_assets`, a swap route outputting a token not declared as collateral) rather than adversarial conditions. The mock receiver's `KeepFunds`/extra-asset modes demonstrate callbacks routinely push arbitrary token combinations (`mock/flash-position-receiver/README.md`).

### Recommendation
Adopt the H-01 remediation pattern:
- Add an owner/governance `sweep(token, recipient)` endpoint on the controller for balances not attributable to an in-flight measured delta; or
- Auto-refund every positive post-callback balance delta to `caller` instead of restricting refunds to `refund_assets` (the baseline snapshot mechanism in `snapshot_balances`/`refund_controller_balance_delta` already generalizes); or
- At minimum, treat a returned `debt.asset` delta as an implicit `repay` credit on the account, since returning borrowed tokens to the controller is unambiguously repayment intent.

### Proof of Concept
1. Alice calls `Controller::flash_position(caller, 0, spoke_id, Multiply, debt=USDC, amount=1000e7, receiver=R, data, collaterals=[(XLM, 4000e7)], refund_assets=[])` — note `USDC` omitted from `refund_assets`.
2. The controller mints the debt, measures `amount_received`, and forwards 1000 USDC to `R` (`mint_and_forward`).
3. `R.execute_flash_position` swaps 500 USDC → XLM, pushes the XLM to `controller`, and returns the unspent 500 USDC to `controller` as well.
4. Settlement: XLM delta is deposited as collateral; the USDC delta matches neither `collaterals` (USDC ∉ collaterals) nor `refund_assets` (empty), so no branch consumes it.
5. Call succeeds — debt `scaled_amount` reflects the full 1000 USDC minted, and 500 USDC sits on the controller address with no reachable withdrawal path.