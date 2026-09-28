### Title
Caller-controlled swap routes can add unauthorized wallet transfers to the signed authorization tree - (File: contracts/controller/src/strategies/swap.rs)

### Summary
The controller accepts an opaque `Bytes` route and forwards it unchanged to the configured swap router, while its explicit contract authorization only covers one exact transfer of controller-owned input tokens to that router. [1](#0-0) [2](#0-1) 

Because route processing can reach a route-selected external pool beneath the caller’s root authorization, that external code can add a token transfer from the caller as a child authorization. [3](#0-2) 

If the caller signs the simulated authorization tree without decoding that child, the transaction can transfer unrelated wallet tokens to an attacker while still producing a valid swap output. [4](#0-3) [5](#0-4) 

### Finding Description
The public `swap_collateral` entrypoint accepts `caller`, `account_id`, `current`, `amount`, `new`, and an opaque `swap: Bytes` argument. [6](#0-5) [7](#0-6) 

`process_swap_collateral` authenticates the caller and requires owner-or-delegate authority before withdrawing the specified collateral. [8](#0-7) [9](#0-8) 

The withdrawn funds are passed to `swap_tokens_or_passthrough` together with the caller-controlled route bytes. [10](#0-9) [11](#0-10) 

`swap_tokens` loads the configured router and invokes `execute_strategy(controller, amount_in, swap)` without decoding the route or checking the contract addresses and function selectors it can reach. [12](#0-11) [13](#0-12) 

The only explicit authorization granted by the controller is `token_in.transfer(controller, router, amount_in)` with no sub-invocations. [14](#0-13) [15](#0-14) 

The subsequent checks bound only controller balance deltas and output receipt; they do not bound additional token movements requested under the caller’s own signed authorization tree. [16](#0-15) [17](#0-16) 

The same opaque route pattern is reachable through `multiply`, `swap_debt`, and `repay_debt_with_collateral`, but `swap_collateral` provides a direct path because it converts existing collateral and requires no new debt. [18](#0-17) [19](#0-18) [20](#0-19) 

### Impact Explanation
A malicious route can cause loss of unrelated tokens held directly by the caller, not merely loss of the collateral amount being routed. [21](#0-20) 

The repository’s authorization-tree test demonstrates an unrelated wallet token moving entirely from the victim to the attacker while the protocol-side collateral swap still completes with fair output. [5](#0-4) 

The loss is bounded by what the poisoned child invocation transfers rather than by `amount_in`, the route minimum output, or the final account-risk checks. [22](#0-21) [23](#0-22) 

This is theft of user funds rather than poor route quality: the malicious transfer is an additional authorization effect that is economically unrelated to the swap output. [24](#0-23) 

### Likelihood Explanation
Exploitation requires the victim to submit or sign an attacker-constructed route and to approve an authorization tree containing the malicious child transfer. [21](#0-20) 

That precondition is plausible because the route is opaque XDR bytes in the signed root call, while a benign strategy produces no caller child entry and therefore gives clients little visible reason to expect one. [1](#0-0) [25](#0-24) 

The exploit does not require a compromised router, leaked key, governance action, or protocol privilege; it only requires route bytes that direct execution through attacker-deployed code. [26](#0-25) 

Enforced authorization rejects the malicious transfer when the caller signs only the honest root tree, so the attack depends on wallet/client failure to reject the additional simulated child rather than on bypassing Soroban authorization. [27](#0-26) [28](#0-27) 

### Recommendation
Decode routes into a typed representation before execution and enforce a strict allowlist of venue contracts, token addresses, pool addresses, and function selectors for every route leg. [1](#0-0) [13](#0-12) 

Do not let route payload bytes name arbitrary executable contracts; route through immutable, protocol-controlled venue adapters or require governance-approved venue/pool registrations. [29](#0-28) 

Reject any route whose execution can introduce caller-authorized token movements beyond the declared input payment, and make route decoding deterministic so clients can display every token and contract involved before signing. [30](#0-29) 

At minimum, add regression coverage asserting that a route-selected contract cannot place an extra token transfer beneath any controller strategy’s caller authorization. [31](#0-30) 

### Proof of Concept
1. Deploy a contract whose route-invoked function reads a stored `(victim, wallet_token, attacker, amount)` plan and calls `wallet_token.transfer(victim, attacker, amount)`. [32](#0-31) 

2. Construct swap bytes that name this contract as the route’s hop pool while specifying a fair output, using the victim’s supplied USDC as input and ETH as output. [26](#0-25) 

3. Have the victim invoke `swap_collateral(caller=victim, account_id, current=USDC, amount, new=ETH, swap=route)`. [33](#0-32) [34](#0-33) 

4. During simulation, the route-selected contract’s wallet-token transfer is recorded as a child of the victim’s `swap_collateral` authorization. [35](#0-34) [36](#0-35) 

5. If the victim signs that returned tree, execution succeeds, the victim’s unrelated wallet-token balance becomes zero, and the attacker receives the full amount. [24](#0-23)

### Citations

**File:** common/src/types/shared.rs (L9-10)
```rust
/// Encoded swap route passed to the aggregator router's `execute_strategy` entry point.
pub type StrategySwap = Bytes;
```

**File:** contracts/controller/src/strategies/swap.rs (L24-27)
```rust
    let controller = env.current_contract_address();
    let router_addr = storage::get_swap_aggregator(env);
    let router = SwapAggregatorClient::new(env, &router_addr);
    let token_in_client = token::Client::new(env, token_in);
```

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** contracts/controller/src/strategies/swap.rs (L40-48)
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
```

**File:** contracts/controller/src/strategies/swap.rs (L74-83)
```rust
/// Returns the output balance increase; rejects zero or negative receipts.
fn verify_router_output(env: &Env, token_out: &Address, balance_before: i128) -> i128 {
    let received = balance_delta_since(
        env,
        token_out,
        &env.current_contract_address(),
        balance_before,
    );
    assert_with_error!(env, received > 0, StrategyError::NoSwapOutput);
    received
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L56-70)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L134-145)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L147-157)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L166-182)
```rust
    /// Enforcing mode: Alice signs `swap_collateral` with exactly `children` beneath it.
    fn try_swap_with_signed_tree(
        &self,
        route: &Bytes,
        children: &[MockAuthInvoke],
    ) -> Result<(), soroban_sdk::Error> {
        let root = MockAuthInvoke {
            contract: &self.t.controller,
            fn_name: "swap_collateral",
            args: self.swap_args(route),
            sub_invokes: children,
        };
        self.t.env.mock_auths(&[MockAuth {
            address: &self.alice,
            invoke: &root,
        }]);
        self.try_swap(route)
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L195-203)
```rust
fn simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry() {
    let s = Scene::new();
    let route = s.route_through_pool_stealing(WALLET_BALANCE);

    // `simulateTransaction` runs recording mode with non-root auth disabled.
    s.t.env.mock_all_auths();
    s.try_swap(&route)
        .expect("recording mode accepts the route");
    let recorded = s.t.env.auths();
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L206-222)
```rust
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L224-226)
```rust
    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
    assert_eq!(s.t.supply_balance_raw(ALICE, "ETH"), FAIR_OUT_ETH);
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-245)
```rust
    // Rogue pool, honest tree: the host refuses the transfer and the whole call rolls back.
    s.t.env.mock_all_auths_allowing_non_root_auth();
    let rogue = s.route_through_pool_stealing(WALLET_BALANCE);
    let usdc_before = s.t.supply_balance_raw(ALICE, "USDC");
    let refused = s
        .try_swap_with_signed_tree(&rogue, &[])
        .expect_err("a transfer outside the signed tree is unauthorized");
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L247-254)
```rust
    assert!(
        refused.is_type(ScErrorType::Auth) || refused.is_type(ScErrorType::Context),
        "expected a host auth failure, got {refused:?}"
    );
    assert!(s
        .diagnostics()
        .contains("Unauthorized function call for address"));
    assert_eq!(s.wallet(&s.alice), WALLET_BALANCE);
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

**File:** contracts/controller/src/lib.rs (L225-229)
```rust
    fn multiply(
        env: Env,
        caller: Address,
        account_id: u64,
        spoke_id: u32,
```

**File:** contracts/controller/src/lib.rs (L258-265)
```rust
    fn swap_debt(
        env: Env,
        caller: Address,
        account_id: u64,
        existing_debt: HubAssetKey,
        amount: i128,
        new_debt: HubAssetKey,
        swap: Bytes,
```

**File:** contracts/controller/src/lib.rs (L283-287)
```rust
    fn swap_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        current: HubAssetKey,
```

**File:** contracts/controller/src/lib.rs (L288-291)
```rust
        amount: i128,
        new: HubAssetKey,
        swap: Bytes,
    ) {
```

**File:** contracts/controller/src/lib.rs (L311-319)
```rust
    fn repay_debt_with_collateral(
        env: Env,
        caller: Address,
        account_id: u64,
        collateral: HubAssetKey,
        collateral_amount: i128,
        debt: HubAssetKey,
        swap: Bytes,
        close_position: bool,
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L40-47)
```rust
    require_authorized_caller(env, caller);

    assert_with_error!(env, current != new, GenericError::AssetsAreTheSame);
    config::require_hub_active(env, current.hub_id);
    require_positive_amount(env, from_amount);

    let mut account = storage::get_account(env, account_id);
    account::require_owner_or_delegate(env, account_id, caller, &account.owner);
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L55-59)
```rust
    let swapped_amount = withdraw_and_swap_from_supply(
        env,
        &mut account,
        &mut cache,
        caller,
```

**File:** contracts/controller/src/strategies/swap_collateral.rs (L60-64)
```rust
        current,
        from_amount,
        &new.asset,
        swap,
        events::PositionAction::SwColWd,
```

**File:** contracts/controller/src/risk/validation.rs (L13-15)
```rust
pub(crate) fn require_authorized_caller(env: &Env, caller: &Address) {
    caller.require_auth();
    require_not_flash_loaning(env);
```

**File:** common/src/token.rs (L36-42)
```rust
pub fn authorize_transfer_as_current(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) {
```
