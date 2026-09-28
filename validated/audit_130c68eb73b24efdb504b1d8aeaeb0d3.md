### Title
Direct pool donation permanently desynchronizes flash-loan balance reconciliation - (File: contracts/pool/src/ops/flash.rs)

### Summary
An unprivileged user can transfer one base unit of any pool asset directly to the shared pool contract. The donation increases the token balance without increasing tracked `cash`; `flash_loan` reconciles the real balance and tracked cash using strict equality and consequently rejects subsequent flash loans until the accidental drift happens to be offset. [1](#0-0) 

### Finding Description
The pool does not isolate each market’s token balance. Its `cash` field is a bookkeeping total, while ordinary inbound flows merely trust the controller to have transferred the reported amount and then credit `cash`. [1](#0-0) 

The controller exposes permissionless `flash_loan(caller, asset, amount, receiver, data)` and forwards it to the pool after only authentication, amount, hub, and receiver checks. [2](#0-1) 

Because the pool performs strict balance reconciliation rather than measuring a per-call delta or tolerating untracked donations, a direct `Token::transfer(attacker, pool, 1)` makes `token.balance(pool) != state.cash` before the flash loan starts. Every subsequent `flash_loan` for that market fails its first reconciliation check while the discrepancy remains.

### Impact Explanation
A single unprivileged transfer can freeze the protocol’s entire flash-loan path for the selected `(hub_id, asset)` market. This also prevents ordinary users and integrations from using controller-level flash liquidity; the attacker needs only spend one token base unit. Depending on later market activity, the discrepancy may persist indefinitely because ordinary supplies increase both actual balance and tracked `cash` by the same amount and therefore preserve, rather than absorb, the donation.

The affected liquidity itself remains in the pool, but the flash-loan functionality is unavailable despite sufficient tracked cash. This is a protocol-level denial of service analogous to uncontrolled resource consumption: an untrusted input permanently desynchronizes an externally reachable reconciliation invariant.

### Likelihood Explanation
The attack requires no privileged role, oracle manipulation, contract vulnerability in a token, malformed asset, or race condition. Any holder of the market asset can send a small amount directly to the pool address at any time. The controller intentionally allows anyone to invoke `flash_loan`, while the pool’s documented trust model relies on the controller for cash accounting and reserves strict equality reconciliation for flash loans. [3](#0-2) 

### Recommendation
Do not require the entire token balance to equal tracked `cash`. Reconcile only the flash-loan delta:

1. Record `before = token.balance(pool)`.
2. Pay out principal and invoke the receiver.
3. Require `token.balance(pool) == before + fee`, or at minimum `>= before + fee`.
4. Track any surplus separately as an explicit donation/recoverable balance rather than letting it break reconciliation.

Alternatively, add an owner-reachable synchronization/sweep path for untracked balances, but that still permits repeated front-running DoS; delta-based settlement is the stronger fix.

### Proof of Concept
Assume `USDC` is listed under `hub_id = 1`, the pool has positive tracked cash, and `receiver` is a compliant flash-loan contract that authorizes repayment of `amount + fee`.

```rust
// Attacker sends one untracked base unit directly to the pool.
let pool = controller.get_pool();
let attacker_transfer = 1_i128;
usdc.transfer(&attacker, &pool, &attacker_transfer);

// Any unprivileged caller now attempts a valid flash loan.
controller.flash_loan(
    &borrower,
    &HubAssetKey { hub_id: 1, asset: usdc_address },
    &1_000_000_i128,
    &receiver,
    &Bytes::new(&env),
);
```

The flash loan reverts with `InvalidFlashloanRepay` or the corresponding initial balance-reconciliation failure because `USDC.balance(pool)` is one unit greater than the pool’s tracked `cash`. No repayment amount or receiver behavior can correct that pre-existing mismatch during the call.

### Citations

**File:** contracts/pool/README.md (L44-63)
```markdown
Because the controller is the sole caller, the pool does not re-validate what is
already guaranteed upstream:

| Guarantee | Enforced in |
| --- | --- |
| `asset_decimals` matches the listed decimals (the stored oracle's `asset_decimals`, else the token's live `decimals()`), in `[0,18]` | `governance/validate/asset.rs::validate_market_creation` |
| Asset contract is live (`try_decimals` + `try_symbol`) | `governance/validate/asset.rs` |
| Rate-model params are timelocked before reaching the pool | `governance/op.rs` |
| Flash-loan reentrancy | `controller/storage/account.rs::with_flash_guard`, checked by `controller/risk/validation.rs::require_not_flash_loaning` |
| `scaled_amount` maps to a real position | controller position ledger |
| Tokens arrived before any cash-crediting call | controller payment path |

The flash guard wraps every external-router and external-receiver call, so it
covers seven controller entrypoints: `flash_loan`, `flash_position`,
`migrate_from_blend`, and the swap-routed `multiply`, `swap_debt`,
`swap_collateral` and `repay_debt_with_collateral`. The last row is the
load-bearing one: `supply`, `repay` and `recapitalize` all credit `cash` on the
controller's word, without verifying the transfer. `cash` is a bookkeeping
number. The only reconciliation against a real `token.balance()` is in
`flash_loan`, which checks it three times with strict equality.
```

**File:** contracts/controller/src/strategies/flash_loan.rs (L22-33)
```rust
    require_authorized_caller(env, caller);
    require_positive_amount(env, amount);
    config::require_hub_active(env, hub_asset.hub_id);

    require_wasm_receiver(env, receiver);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();

    let fee = storage::with_flash_guard(env, || {
        pool_flash_loan_call(env, &pool_addr, hub_asset, caller, receiver, amount, data)
    });
```
