### Title
`flash_position` opens leveraged strategy debt without charging the `flashloan_fee` protocol fee that `multiply`/`swap_debt` charge for the identical position — ([File: contracts/controller/src/strategies/flash_position.rs])

### Summary
The Caviar M-06 bug class is a fee-consistency failure: a flow that is economically equivalent to other fee-bearing flows skips the protocol fee. XOXNO Lending has the same shape. `multiply` and `swap_debt` mint strategy debt through `borrow_into_controller(..., charge_fee = true)`, which calls `pool.create_strategy` and books `flashloan_fee` bps of the gross debt as protocol revenue. `flash_position` mints the same kind of strategy debt for the same leveraged-position outcome but passes `charge_fee = false`, booking zero revenue.

### Finding Description
- `multiply`/`swap_debt` call `borrow_into_controller` with `charge_fee = true`; the pool computes `fee = half_up(amount × flashloan_fee / 10_000)` (min 1 when positive) and mints it as protocol revenue shares via `interest::add_protocol_revenue` while sending only `amount - fee` out (`contracts/pool/src/ops/strategy.rs:58-88`).
- `flash_position` performs the same operation — mints debt on the caller's account, forwards funds to a receiver contract, collects measured collateral deposits, and runs the same `strategy_finalize` health/LTV checks — but `mint_and_forward` calls `borrow_into_controller(env, account, debt, amount, false, PositionAction::FlashPos, cache)`, so `compute_fee` returns 0 (`contracts/controller/src/strategies/flash_position.rs:271-279`).
- The hardcoded `fee: 0` in `FlashPositionEvent` and the callback argument `0i128` confirm the fee is never charged (`flash_position.rs:156-166, 316`).
- The parity test `tests/test-harness/tests/strategy_origination_fee_parity.rs:96-131` explicitly proves the equivalence: same debt, same collateral requirements, same finalization — `multiply` books `expected_fee` revenue, `flash_position` books `0`, yielding strictly more collateral for the same debt.
- `flash_position` is an unprivileged controller entrypoint (`require_authorized_caller` only requires a non-restricted caller), reachable with `PositionMode::Multiply`, an arbitrary WASM `receiver` under the caller's control, and arbitrary `data` — the caller's own receiver can simply deliver the minted debt-asset proceeds swapped to collateral.

### Impact Explanation
Any user opening or extending a leveraged position can avoid the protocol origination fee entirely by routing through `flash_position` instead of `multiply`. The fee is `flashloan_fee` bps (up to `MAX_FLASHLOAN_FEE_BPS = 500`) of gross debt on every leveraged open/extend — revenue that accrues on every equivalent `multiply`/`swap_debt` call is permanently not booked. This is persistent loss of unclaimed protocol yield (revenue shares that would otherwise be claimable via `claim_revenue`), matching the Caviar finding's "protocol receives nothing" loss class.

### Likelihood Explanation
No special access, timing, or market state is needed beyond `is_flashloanable` on the debt market — the same flag `multiply`-style strategies rely on. The caller supplies a receiver contract (a trivial contract returning the funds as collateral suffices) and gets a strictly better outcome than `multiply`. Every rational leveraged-position opener is incentivized to use this route, so effectively 100% of origination fees on such positions can be bypassed.

### Recommendation
Charge the strategy origination fee in `flash_position` the same way `multiply` does: pass `charge_fee = true` in `mint_and_forward`, propagate the actual `fee` (from `result`/`PoolStrategyMutation`) into `FlashPositionEvent` and the `execute_flash_position` callback instead of `0`, and size the receiver's required collateral delivery against the net (`amount - fee`) receipt. If fee-free flash positions are intended (e.g., `migrate_from_blend`-like migrations), gate `charge_fee = false` behind a mode that cannot be used to open new leverage, or document the divergence explicitly.

### Proof of Concept
1. Configure a market with `flashloan_fee > 0` and `is_flashloanable = true` (e.g., 100 bps).
2. Attacker deploys a WASM receiver implementing `execute_flash_position` that swaps/forwards the received debt asset back to the controller as a listed collateral asset.
3. Attacker calls `controller.flash_position(account_id, spoke_id, PositionMode::Multiply, debt = HubAssetKey{hub, debt_asset}, amount, receiver = own receiver, collaterals = [(collateral_hub_asset, min)], refund_assets = [])`.
4. `mint_and_forward` mints `amount` debt with `charge_fee = false`; pool transfers the full `amount` (vs `amount - fee` under `multiply`); the receiver returns collateral which is deposited; `strategy_finalize` passes the same health checks as `multiply`.
5. Result: identical leveraged position to `multiply`, but `revenue` delta is 0 instead of `fee` — confirmed exactly by `strategy_origination_fee_parity.rs` which asserts `fp_revenue == 0` and `mul_revenue == expected_fee` for equal debt.