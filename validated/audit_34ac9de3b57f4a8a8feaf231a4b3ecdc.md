### Title
`flash_position` permanently locks callback-sent tokens that are neither declared as collateral nor listed in `refund_assets` - (File: contracts/controller/src/strategies/flash_position.rs)

### Summary
The bug class from the external report — value handed to a contract on a code path that does not account for it being locked forever — exists in the controller's `flash_position` flow. During the receiver callback, arbitrary tokens can be transferred into controller custody, but only assets declared in `collaterals` are deposited and only assets listed in `refund_assets` are refunded. Any other token balance increase is neither credited nor returned, and the controller has no sweep/rescue entrypoint, so those funds are stranded permanently.

### Finding Description
`process_flash_position` snapshots controller balances only for the declared `collaterals` assets and the `refund_assets` list (lines 125–130), then invokes the caller-chosen receiver's `execute_flash_position` (lines 131–141). After the callback it settles custody in exactly two ways:

- `collect_collateral_deposits` measures the balance delta per declared collateral asset and deposits it into the account (lines 325–352).
- `refund_listed_assets` calls `refund_controller_balance_delta` per `refund_assets` entry, returning the delta to `caller` (lines 372–384).

A token whose balance rose during the callback but which appears in neither list falls between the two paths. `validate_refund_assets` even forbids a refund asset from also being a collateral (lines 248–254), so an asset can only be claimed through exactly one of the two lists; an asset in neither is never touched. This is confirmed by tests showing that pre-existing or unrelated controller balances are deliberately preserved and never swept (`test_swap_debt_refund_only_uses_strategy_excess`, `test_migrate_refund_ignores_preexisting_controller_balance`), and by `withdraw`/`borrow` explicitly rejecting the controller as recipient because "the tokens would sit in the controller where no balance-delta measurement ever claims them" (certora/controller/spec/market_guard_rules.rs:157-159). There is no recovery entrypoint on the controller.

Unlike the analogous receiver-correctness issues, here the *caller* is unprivileged and selects `receiver`, `collaterals`, and `refund_assets`; the receiver is typically the caller's own contract, which is a permitted analog surface ("own flash receiver"). Any token the receiver pushes to the controller that the caller forgot (or was unable) to declare — e.g., an unlisted-in-this-hub asset that fails `require_listed_active_config`, or a hub/asset combination not present in `collaterals` — is locked in the controller forever.

### Impact Explanation
Permanent freezing of user funds: tokens transferred to the controller during the callback and matching neither list can never be withdrawn, credited, or refunded by anyone, including the admin (no sweep exists). The loss equals the undeclared amount.

### Likelihood Explanation
Medium likelihood: it requires the caller's receiver to send a token that is not declared, which is a caller-mistake scenario rather than a protocol-default path. However the API makes this easy — `refund_assets` is opt-in, collateral declaration is per `(hub_id, asset)` while balances are per token, and any residual output token from a multi-hop route that the receiver forwards "just in case" is silently stranded instead of reverting. The function returns success and emits a normal event, so the loss is silent.

### Recommendation
After `refund_listed_assets`, either:
- refund the positive balance delta of every extra token touched during the callback (e.g., snapshot the union of debt asset, collateral assets, and any tokens the receiver could plausibly return), or
- require callers to enumerate every expected return asset across `collaterals`/`refund_assets` and add an explicit admin `sweep`/`rescue` entrypoint on the controller so stranded balances are recoverable.

At minimum, document that undeclared tokens sent to the controller in the callback are unrecoverable.

### Proof of Concept
1. ALICE calls `flash_position` with `debt = USDC`, `collaterals = [(ETH_hub_asset, min)]`, and `refund_assets` empty; `receiver` is her own Wasm contract.
2. In `execute_flash_position`, the receiver swaps part of the borrowed USDC into ETH, transfers the ETH to the controller, and also transfers 100 XLM (or any other token) to the controller.
3. `collect_collateral_deposits` measures and deposits only the ETH delta; `refund_listed_assets` iterates an empty list.
4. The call succeeds, the position finalizes, and the 100 XLM remains on the controller address with no code path that can ever move it — confirmed by the guard-rule comment at certora/controller/spec/market_guard_rules.rs:157-159 that such balances are unclaimable by design.