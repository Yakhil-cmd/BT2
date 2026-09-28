### Title
Unallowlisted swap route venue can attach a rogue token `transfer` under the caller's signed auth tree and drain the caller's wallet - (File: contracts/swap-aggregator/src/venues/auth.rs)

### Summary
In the original Splits report, a privileged owner used `execCalls` to run arbitrary `transferFrom` against traders' standing approvals. In XOXNO Lending the same bug class — "an execution path reaches arbitrary token calls beyond the authorized scope and steals the user's wallet funds" — materializes through the swap-aggregator / controller strategy routes: route venues are not allowlisted, so a malicious venue invoked under the strategy call can issue `token.transfer(victim, attacker, amount)` that the host records as a child of the victim's own authorization entry, stealing funds far beyond the routed swap input.

### Finding Description
The swap-aggregator executes user-supplied route bytes and calls whatever pool/token addresses the payload names; the threat model confirms it "keeps no allowlist" of venues [1](#0-0) . The controller grants exactly one exact input-transfer authorization for the strategy (`authorize_token_transfer` / `authorize_token_approve` wrap `env.authorize_as_current_contract`) [2](#0-1) , but nothing constrains what a venue contract does with the caller's `require_auth` context once it is on the call stack.

`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` proves the primitive end-to-end: a rogue hop pool registered in the route calls `wallet_token.transfer(alice, attacker, WALLET_BALANCE)`, and host simulation records it as a `sub_invocation` of Alice's `swap_collateral` authorization [3](#0-2) . When Alice signs the recorded tree — which simulation returns — the transfer executes and her entire wallet balance moves to the attacker [4](#0-3) .

Any unprivileged attacker can reach this: deploy a rogue venue contract, craft route bytes that pass through it, and get a victim to sign the simulated `execute_strategy` / `swap_collateral` / `swap_debt` transaction (`scripts/permissionless_entrypoints.txt` marks all of them `caller-auth`) [5](#0-4) .

### Impact Explanation
Theft of user funds. The stolen amount is the victim's full token wallet balance — not the routed input, not bounded by the payload's `min_out`, and not bounded by the controller's post-swap account risk check, because the transfer settles inside the token contract, not inside the lending books [6](#0-5) . The swap itself can still satisfy `min_out` and final solvency, so no controller-side check detects the loss.

### Likelihood Explanation
Requires an attacker to publish/relay a poisoned route and a victim's wallet to sign the auth tree containing the foreign transfer. The threat model itself states "a client must decode the route it signs and refuse an authorization tree with any other child" and that "the direct `execute_strategy` path has the same exposure for every swap user" — i.e., safety currently rests entirely on every integrating client/wallet decoding Soroban auth trees correctly [7](#0-6) . Any client that signs simulation output without inspecting sub-invocations exposes its users; the on-chain contracts provide no defense.

### Recommendation
Mirror the original report's fix: bound what the strategy frame can authorize. Options on XOXNO's shape:
- Maintain a governance-set venue allowlist in the swap-aggregator and reject route hops whose pool/router address is not listed (the `calli.to != $tokenToBeneficiary` analog — token contracts used in routes should be the declared route tokens only).
- Have the aggregator/controller pre-declare the complete expected child-invocation set (the single `authorize_as_current_contract` input transfer) and compare recorded auth trees against it rather than relying on the venue's behavior.
- At minimum, enforce that no hop's callee may be a `token` contract other than the declared route input/output tokens.

### Proof of Concept
1. Attacker deploys `RogueHopPool`, a contract whose `swap` executes `token::Client::transfer(victim, attacker, victim_balance)` — the fixture at `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs:271-299` demonstrates the pattern.
2. Attacker serves route bytes whose decoded hop targets `RogueHopPool`, e.g. as offered by a third-party route API for `controller::swap_collateral` or `swap_aggregator::execute_strategy`.
3. Victim simulates; the host returns an auth tree for the entrypoint with a child `token.transfer(victim → attacker, WALLET_BALANCE)` — asserted at lines 206-222 of the test.
4. Victim signs the tree (wallet UIs that display only the root invocation, or clients that sign simulation output verbatim, both accept it).
5. Submission succeeds: the swap leg delivers `FAIR_OUT_ETH` so all output/risk checks pass, while `token.transfer` moves `WALLET_BALANCE` to the attacker — asserted at lines 224-226 and 264-268.

### Citations

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

**File:** contracts/swap-aggregator/src/venues/auth.rs (L9-27)
```rust
pub(crate) fn authorize_token_transfer(
    env: &Env,
    token: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) {
    authorize_as_current(
        env,
        token,
        "transfer",
        vec![
            env,
            from.into_val(env),
            to.into_val(env),
            amount.into_val(env),
        ],
    );
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-227)
```rust
fn simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry() {
    let s = Scene::new();
    let route = s.route_through_pool_stealing(WALLET_BALANCE);

    // `simulateTransaction` runs recording mode with non-root auth disabled.
    s.t.env.mock_all_auths();
    s.try_swap(&route)
        .expect("recording mode accepts the route");
    let recorded = s.t.env.auths();
    std::println!("recorded auth tree = {recorded:#?}");

    let stolen_transfer = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.wallet_token.clone(),
            symbol_short!("transfer"),
            (s.alice.clone(), s.attacker.clone(), WALLET_BALANCE).into_val(&s.t.env),
        )),
        sub_invocations: std::vec![],
    };
    let poisoned_root = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.t.controller.clone(),
            Symbol::new(&s.t.env, "swap_collateral"),
            s.swap_args(&route),
        )),
        sub_invocations: std::vec![stolen_transfer],
    };
    assert_eq!(recorded, std::vec![(s.alice.clone(), poisoned_root)]);

    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
    assert_eq!(s.t.supply_balance_raw(ALICE, "ETH"), FAIR_OUT_ETH);
}
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L258-269)
```rust
    // Same route, with the tree that simulation returned.
    let stolen_transfer = MockAuthInvoke {
        contract: &s.wallet_token,
        fn_name: "transfer",
        args: (s.alice.clone(), s.attacker.clone(), WALLET_BALANCE).into_val(&s.t.env),
        sub_invokes: &[],
    };
    s.try_swap_with_signed_tree(&rogue, core::slice::from_ref(&stolen_transfer))
        .expect("the poisoned tree authorizes the rogue transfer");
    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
}
```

**File:** scripts/permissionless_entrypoints.txt (L49-56)
```text
controller::borrow | caller-auth | INV-AUTH-02, INV-RISK-01 | Any address may call, but the funds are drawn against account_id, which require_owner_or_delegate pins to its owner or an active listed delegate, and post-pool solvency is re-proven.
controller::withdraw | caller-auth | INV-AUTH-02, INV-RISK-01 | Any address may call, but require_owner_or_delegate pins account_id to its owner or an active listed delegate before any collateral leaves, and solvency is re-proven afterward.
controller::multiply | caller-auth | INV-AUTH-02, INV-STRAT-02 | Leverage entry on account_id; the Multiply account guard requires the owner or an active listed delegate and asserts the account's position mode matches.
controller::flash_position | caller-auth | INV-AUTH-02, INV-STRAT-02, INV-STRAT-04 | Callback leverage entry on account_id; the Multiply account guard requires the owner or an active listed delegate, require_wasm_receiver admits only a Wasm contract receiver, collateral is credited from measured receipts only, and FlashPositionClosed plus strategy_finalize keep the minted debt on a solvent account that still holds supply.
controller::swap_debt | caller-auth | INV-AUTH-02, INV-STRAT-02 | Moves debt on account_id from one asset to another; require_owner_or_delegate pins the account before the borrow-and-repay legs run.
controller::swap_collateral | caller-auth | INV-AUTH-02, INV-STRAT-02 | Moves collateral on account_id from one asset to another; require_owner_or_delegate pins the account before the withdraw-and-deposit legs run.
controller::repay_debt_with_collateral | caller-auth | INV-AUTH-02, INV-STRAT-02 | Nets or swaps account_id's own collateral into a repayment; require_owner_or_delegate pins the account, so a stranger cannot force-close a position.
controller::migrate_from_blend | caller-auth | INV-AUTH-02, INV-STRAT-02, INV-STRAT-03 | Sweeps the caller's Blend position into account_id from a governance-approved pool only; the Migrate account guard requires the owner or an active listed delegate.
```
