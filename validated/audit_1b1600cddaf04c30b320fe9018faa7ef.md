### Title
Caller-supplied swap routes can attach arbitrary token transfers beneath the caller's authorization tree, draining the caller's wallet - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The Mattermost bug class is an unrestricted allow-list of destinations to which a user's ambient authority (NTLM credentials) is forwarded. The direct analog in XOXNO Lending is the unrestricted allow-list of venue/pool/token addresses inside the `swap_xdr` route that `multiply`, `swap_collateral`, `swap_debt`, and `repay_debt_with_collateral` forward to the swap aggregator. A crafted route executes attacker-deployed contracts under the caller's `require_auth` tree and attaches `token::transfer(caller -> attacker, amount)` sub-invocations, which an honest simulation records as children of the caller's authorization entry and the wallet signs with the rest of the transaction.

### Finding Description
`swap_tokens` in `contracts/controller/src/strategies/swap.rs` authorizes exactly one input-token transfer to the router and then calls `router.execute_strategy(&controller, &amount_in, swap)` with the fully caller-supplied `StrategySwap` [1](#0-0) . The router decodes the packed program and dispatches each hop to whatever pool address the payload's `assets` registry names — `dispatch_hop` matches only on the venue enum and calls `hop.pool` with no allowlist of pools or tokens [2](#0-1) . Venue adapters invoke the pool as a contract call beneath the router, which is beneath the controller, which is beneath the caller's signed `require_auth` entry. Any contract the payload names can therefore issue `token::transfer(victim, attacker, x)` for any token the victim holds, and Soroban's recording mode folds that call into the caller's authorization tree [3](#0-2) . The threat model itself describes this exposure: the router "keeps no allowlist" of the pool/token addresses the payload names, so "a route can put third-party code on the call stack below the caller's authorization," and the loss is "the caller's wallet, not the routed amount" [4](#0-3) . Neither the router's `total_min_out` check nor the controller's post-swap solvency gate bounds the theft, because the stolen transfer does not touch the swapped amounts [5](#0-4) . The measured-delta guards (`RouterOverspend`, `NoSwapOutput`, `ZeroOutput`) only verify the controller's and router's own balances, not side transfers from the caller [6](#0-5) .

### Impact Explanation
Theft of user funds. A victim who signs a `swap_collateral`/`multiply`/`swap_debt`/`repay_debt_with_collateral` transaction containing a malicious route loses arbitrary amounts of arbitrary wallet tokens — including tokens the protocol never listed — in the same transaction. The swap itself can still execute honestly (fair output, correct position state), so there is no on-chain anomaly to detect. The harness test demonstrates the end state: Alice's entire `WALLET_BALANCE` of an unlisted token moves to the attacker while her `swap_collateral` completes normally [7](#0-6) . This mirrors CVE-2026-6517: the user's ambient authority is forwarded to an attacker-chosen destination the application failed to restrict.

### Likelihood Explanation
Reachable by any unprivileged address through `swap_collateral(caller, account_id, current, amount, new, swap)`, `multiply`, `swap_debt`, or `repay_debt_with_collateral` — the attacker only needs to get a victim to sign a transaction embedding the poisoned route (e.g., via a compromised or malicious quote/frontend), which is the same delivery model as the reference advisory's embedded-image credential leak. Severity Medium: requires victim interaction (signing the poisoned tree), but the route bytes are opaque XDR that wallets do not render, and neither the payload minimum nor the final risk gate reveals the extra transfer. Note the documented mitigation is client-side route verification; nothing in the contracts prevents the poisoned tree from executing once signed.

### Recommendation
Restrict the destinations the route can name. Options, in increasing strength: (a) maintain an on-chain allowlist of pool/share-token addresses per venue that `dispatch_hop` checks before invoking `hop.pool`; (b) pin venue contracts to a registry the router validates pool addresses against (e.g., Aquarius pool factory lookups) instead of trusting the `assets` registry; (c) at minimum, have the controller reject routes whose registries reference token/pool addresses outside the hub's listed markets. Additionally, clients should refuse to sign an authorization tree containing children other than the single input transfer, per the threat-model guidance.

### Proof of Concept
The repository ships the exploit as a test harness fixture. `contracts/controller/src/strategies/swap.rs` forwards the caller's route to the router; `contracts/swap-aggregator/src/venues/mod.rs::dispatch_hop` invokes whatever `hop.pool` the payload names with no allowlist; and `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` builds the full attack:

```rust
// tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs
// Attacker "pool" invoked as a route hop; it pulls from the caller's wallet.
pub fn swap(env: Env) {
    let (victim, wallet_token, to, amount): (Address, Address, Address, i128) = ...;
    if amount > 0 {
        token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
    }
}
```

`simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` (lines 194-227) shows `env.auths()` recording the `transfer(alice -> attacker, WALLET_BALANCE)` as a child of Alice's `swap_collateral` entry — the exact tree an honest simulation returns for signing — and asserts `wallet(alice) == 0`, `wallet(attacker) == WALLET_BALANCE`, while her ETH supply credit is the honest `FAIR_OUT_ETH`. In production, once the victim signs that recorded tree, the same transfer executes in enforcing mode and the funds are unrecoverable.

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L34-38)
```rust
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** contracts/controller/src/strategies/swap.rs (L41-48)
```rust
    let in_after = token_in_client.balance(&controller);
    assert_with_error!(env, in_after <= in_before, StrategyError::RouterOverspend);
    let actual_spent = in_before - in_after;
    assert_with_error!(
        env,
        actual_spent <= amount_in,
        StrategyError::RouterOverspend
    );
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L34-40)
```rust
    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-71)
```rust
    pub fn swap(env: Env) {
        let (victim, wallet_token, to, amount): (Address, Address, Address, i128) = env
            .storage()
            .instance()
            .get(&symbol_short!("PLAN"))
            .expect("plan is set by the constructor");
        if amount > 0 {
            token::Client::new(&env, &wallet_token).transfer(&victim, &to, &amount);
        }
    }
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L224-226)
```rust
    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
    assert_eq!(s.t.supply_balance_raw(ALICE, "ETH"), FAIR_OUT_ETH);
```

**File:** docs/explanation/threat-model.md (L154-165)
```markdown
That bound covers the controller's own grant only. The router calls the pool
and token addresses its payload names and keeps no allowlist of them, so a
route can put third-party code on the call stack below the caller's
authorization. A token transfer that such code makes from the caller is
recorded by an honest simulation as a child of the caller's authorization
entry, and it executes if the caller signs that tree. The loss is then the
caller's wallet, not the routed amount, and neither the payload minimum nor the
final risk gate bounds it. An honest swap strategy gives the caller no child
entry, and a direct router swap gives exactly one input transfer. A client must
decode the route it signs and refuse an authorization tree with any other
child. The direct `execute_strategy` path has the same exposure for every swap
user.
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L125-131)
```rust
    let total_out = vault.balance_of(&output_token);
    if total_out < total_min_out {
        panic_with_error!(&env, Error::SlippageExceeded);
    }

    vault.withdraw(&output_token, total_out);
    token::Client::new(&env, &output_token).transfer(&router, &sender, &total_out);
```
