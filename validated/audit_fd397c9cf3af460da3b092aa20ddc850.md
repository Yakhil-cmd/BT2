Audit Report

## Title
`ensure_balance` Charges Rate Limiter Only on Delta vs. Live Balance, Enabling Rate-Limit Bypass via `create_canister` Cycle Residue - (File: `rs/nns/cmc/src/main.rs`)

## Summary
The `ensure_balance` function computes `cycles_to_mint = cycles - canister_balance128()` and charges only that delta to the per-period minting rate limiter and `total_cycles_minted`. Because the `create_canister` endpoint accepts the caller's cycles into the CMC's own balance on success, any subsequent ICP-based conversion whose cycle equivalent is ≤ the residual balance will charge zero against the rate limiter while still depositing the full amount to the target canister, effectively bypassing the minting rate limit and undercounting `total_cycles_minted`.

## Finding Description

`ensure_balance` reads the live canister balance and mints only the shortfall:

```rust
let current_balance = Cycles::from(ic_cdk::api::canister_balance128());
let cycles_to_mint = cycles - current_balance;   // saturates to 0 if balance >= cycles

with_state_mut(|state| {
    limiter_to_use.check_and_add_cycles(state, now, cycles_to_mint)?;
    state.total_cycles_minted += cycles_to_mint;
    ...
})?;
let _minted_cycles = ic0_mint_cycles128(cycles_to_mint);
``` [1](#0-0) 

The `create_canister` endpoint, on a successful canister creation, calls `msg_cycles_accept(cycles)`, depositing the caller's full cycle payment into the CMC's own balance: [2](#0-1) 

The integration test explicitly asserts this residue is stable and observable: [3](#0-2) 

The exploit path:
1. Attacker calls `create_canister` with X cycles. `do_create_canister` calls `ensure_balance(X)`, minting X cycles and sending them to the management canister. On success, `msg_cycles_accept(X)` deposits X cycles into the CMC's balance. Rate limiter charged: X.
2. Attacker (or any user) calls `notify_top_up` / `notify_create_canister` / `notify_mint_cycles` for an ICP amount whose cycle equivalent is ≤ X. `process_top_up` → `deposit_cycles` → `ensure_balance(X)`:
   - `current_balance = X`
   - `cycles_to_mint = X − X = 0`
   - Rate limiter charged: **0**
   - `total_cycles_minted += 0`
   - CMC sends X cycles from its pre-existing balance to the target.
   - `burn_and_log` burns the full ICP amount.
3. Repeat from step 1 to bypass the rate limiter indefinitely within a single window.

The `deposit_cycles` → `ensure_balance` call chain for ICP-based paths is confirmed: [4](#0-3) [5](#0-4) 

## Impact Explanation

**Rate-limiter bypass**: `check_and_add_cycles` is charged only `cycles_to_mint` (0 in the exploit scenario), not the full `cycles` amount. An unprivileged attacker can pre-fund the CMC's balance via the publicly callable `create_canister` endpoint and cause subsequent ICP-based conversions to consume zero rate-limit budget, allowing ICP burning at an unbounded rate within a single rate-limit window. This constitutes a significant NNS/CMC security impact with concrete protocol harm — the rate limiter protecting ICP-to-cycles conversion throughput is rendered ineffective.

**`total_cycles_minted` undercount**: The governance-visible counter is incremented by 0 instead of the full conversion amount, corrupting on-chain accounting relied upon by governance and monitoring.

**ICP conservation distortion**: ICP is burned via `burn_and_log` for the full amount while zero new cycles are minted in that transaction. The cycles deposited to the target originate from the CMC's pre-existing balance (funded by the `create_canister` caller), meaning ICP supply decreases without a corresponding increase in the cycles supply in that accounting period, distorting the ICP/cycles exchange rate.

This matches the allowed impact: **High ($2,000–$10,000)** — significant NNS canister security impact with concrete user and protocol harm, requiring no special privileges.

## Likelihood Explanation

The `create_canister` endpoint is publicly callable by any canister on the IC with sufficient cycles. No governance majority, subnet majority, privileged access, or leaked keys are required. The residue is a deterministic, stable property of the current implementation (confirmed by the integration test). The attack is repeatable: one `create_canister` call per ICP-based conversion suffices to bypass the rate limiter for that conversion. Cost to the attacker is the cycles spent on `create_canister` (which creates a real canister, so the cycles are not lost — they are deposited into the new canister).

## Recommendation

Replace the delta-based approach with one that always mints the full requested amount and charges the full amount to the rate limiter, regardless of the CMC's current balance:

```rust
fn ensure_balance(cycles: Cycles, limiter_to_use: CyclesMintingLimiterSelector) -> Result<(), String> {
    let now = now_system_time();
    with_state_mut(|state| {
        limiter_to_use.check_and_add_cycles(state, now, cycles)?;
        state.total_cycles_minted += cycles;
        Ok::<_, String>(())
    })?;
    let _minted_cycles = ic0_mint_cycles128(cycles);
    Ok(())
}
```

Alternatively, separate the cycles-based `create_canister` path from ICP-based paths so the CMC never accumulates caller-provided cycles in its own balance, and the rate limiter exclusively tracks ICP-originated minting.

## Proof of Concept

1. Deploy a canister (Canister A) with sufficient cycles on the IC.
2. Canister A calls `create_canister` on the CMC with 10 T cycles attached. CMC mints 10 T, sends to management canister, accepts 10 T from A. CMC balance = 10 T. Rate limiter charged: 10 T.
3. Send 1 ICP (≈ 10 T cycles at current rate) to the CMC's subaccount for a target canister and call `notify_top_up`.
4. Observe: `process_top_up` → `deposit_cycles` → `ensure_balance(10T)` → `cycles_to_mint = 0` → rate limiter charged 0 → target canister receives 10 T cycles → 1 ICP burned.
5. Verify `total_cycles_minted()` was not incremented for step 3.
6. Repeat steps 2–4 to bypass the rate limiter for each ICP conversion.

This is directly reproducible as a deterministic integration test using the existing `state_machine` test framework in `rs/nns/integration_tests/src/cycles_minting_canister.rs`, following the pattern already established at lines 461–476. [6](#0-5)

### Citations

**File:** rs/nns/cmc/src/main.rs (L1502-1505)
```rust
    match do_create_canister(caller(), cycles.into(), subnet_selection, settings).await {
        Ok(canister_id) => {
            ic_cdk::api::call::msg_cycles_accept(cycles);
            Ok(canister_id)
```

**File:** rs/nns/cmc/src/main.rs (L1999-1999)
```rust
    match deposit_cycles(canister_id, cycles, true, limiter_to_use).await {
```

**File:** rs/nns/cmc/src/main.rs (L2245-2249)
```rust
    // We have subnets available, so we can now mint the cycles and create the canister.

    // Always use base cycles limit for minting cycles, since the Subnet Rental Canister
    // doesn't call endpoints using this function.
    ensure_balance(cycles, CyclesMintingLimiterSelector::BaseLimit)?;
```

**File:** rs/nns/cmc/src/main.rs (L2312-2322)
```rust
    let current_balance = Cycles::from(ic_cdk::api::canister_balance128());
    let cycles_to_mint = cycles - current_balance;

    with_state_mut(|state| {
        limiter_to_use.check_and_add_cycles(state, now, cycles_to_mint)?;
        state.total_cycles_minted += cycles_to_mint;
        Ok::<_, String>(())
    })?;

    // unused because of check above
    let _minted_cycles = ic0_mint_cycles128(cycles_to_mint);
```

**File:** rs/nns/integration_tests/src/cycles_minting_canister.rs (L461-476)
```rust
    let canister = cmc_create_canister_with_cycles(
        &state_machine,
        universal_canister,
        None,
        None,
        10_000_000_000_000,
    )
    .unwrap();
    let status = canister_status(&state_machine, universal_canister.get(), canister).unwrap();
    assert_eq!(
        status.settings.controllers,
        vec![universal_canister.get().0]
    );

    // We minted, then used, then accepted some cycles.
    assert_eq!(cmc_cycles_balance(), Nat::from(10_000_000_000_000_u128));
```
