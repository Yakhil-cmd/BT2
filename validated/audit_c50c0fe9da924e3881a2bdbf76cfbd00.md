### Title
Arbitrary `flash_position` receiver can hide unauthorized wallet transfers inside the caller’s authorization tree - ([File: contracts/controller/src/strategies/flash_position.rs](rs-lending-xlm--015/contracts/controller/src/strategies/flash_position.rs))

### Summary
`flash_position` accepts an arbitrary deployed Wasm receiver and opaque callback data, but only rejects the controller and pool as receivers. Because the account owner’s authorization covers the entire strategy call, code executed by the receiver can request additional `caller` authorization for unrelated token transfers. Simulation records that transfer as a child of the `flash_position` authorization; if the victim signs the poisoned tree, the receiver can steal wallet tokens unrelated to the borrowed asset while still returning enough collateral for the strategy to succeed. This mirrors the SVG issue: an allowed outer construct contains uninspected executable content with effects outside the expected transfer.

### Finding Description
`process_flash_position` requires `caller` authorization, then accepts caller-controlled `receiver` and `data` arguments. [1](#0-0)  The only receiver-specific checks are that it is a Wasm contract and is neither the controller nor the pool. [2](#0-1)  The strategy then mints/forwards the debt under the flash guard before measuring callback-delivered collateral. [3](#0-2) 

Nothing in these checks limits the receiver’s nested contract calls or the additional `caller` authorizations those calls can request. A malicious receiver can invoke `wallet_token.transfer(caller, attacker, amount)`. During authorization recording, Soroban places that transfer under the caller’s strategy authorization; the repository’s equivalent router-hop test records exactly such a child invocation and observes the victim wallet balance reaching zero while the strategy completes. [4](#0-3) [5](#0-4)  Enforced authorization confirms that signing that simulated child is sufficient for the theft. [6](#0-5) 

The same authorization-tree exposure exists for opaque `swap` routes: the controller grants only its own exact input transfer and invokes `execute_strategy` with attacker-supplied bytes, without constraining which nested contracts may request further caller authorization. [7](#0-6) 

### Impact Explanation
An attacker can steal unrelated tokens held directly by a strategy caller. The stolen assets need not be listed collateral, debt assets, routed input, or routed output, so the controller’s balance-delta checks and final solvency checks do not bound the loss. The malicious callback can also return the declared collateral, leaving the account healthy and the operation externally successful. This is theft of user funds.

### Likelihood Explanation
Exploitation requires user interaction: the victim must authorize a `flash_position`, `multiply`, `swap_collateral`, `swap_debt`, or `repay_debt_with_collateral` transaction whose simulated authorization tree contains the malicious child transfer. This is plausible where users receive receiver addresses, callback payloads, or route bytes from an application and do not inspect every nested authorization. The receiver can be deployed by any unprivileged address, and the existing authorization model provides no protocol-side distinction between expected collateral movement and unrelated wallet theft.

### Recommendation
Do not expose callers to arbitrary executable receivers or route-selected contracts under the account owner’s root authorization. Restrict `flash_position` receivers and route venue/pool addresses to a governance-approved set, or restructure the flow so untrusted callbacks cannot execute while the caller’s strategy authorization is active. At the integration layer, display and enforce an allowlist of expected child authorizations; any additional token transfer, approval, or contract invocation should reject the transaction.

### Proof of Concept
1. Deploy `TheftReceiver` with `victim`, `wallet_token`, `attacker`, and `amount` stored at construction.
2. Implement `execute_flash_position` so it calls:
   ```rust
   token::Client::new(&env, &wallet_token)
       .transfer(&victim, &attacker, &amount);
   ```
   and then transfers enough declared collateral to the controller to satisfy the strategy minimum.
3. Present the victim with a valid `flash_position` call selecting `TheftReceiver` and corresponding collateral declarations.
4. Simulate the call. The authorization tree contains `wallet_token.transfer(victim, attacker, amount)` beneath the caller’s `flash_position` authorization.
5. If the victim signs that tree, the host authorizes the nested transfer; the test demonstrates Alice’s unrelated wallet token moving entirely to the attacker while the strategy still deposits its expected output. [8](#0-7)

### Citations

**File:** contracts/controller/src/strategies/flash_position.rs (L40-56)
```rust
pub(crate) fn process_flash_position(
    env: &Env,
    caller: &Address,
    params: FlashPositionParams<'_>,
) -> u64 {
    require_authorized_caller(env, caller);

    let FlashPositionParams {
        account_id,
        spoke_id,
        mode,
        debt,
        amount,
        receiver,
        data,
        collaterals,
        refund_assets,
```

**File:** contracts/controller/src/strategies/flash_position.rs (L69-83)
```rust
    require_wasm_receiver(env, receiver);

    let controller = env.current_contract_address();
    assert_with_error!(
        env,
        *receiver != controller,
        FlashLoanError::InvalidFlashloanReceiver
    );

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    assert_with_error!(
        env,
        *receiver != pool_addr,
        FlashLoanError::InvalidFlashloanReceiver
```

**File:** contracts/controller/src/strategies/flash_position.rs (L119-125)
```rust
    // Guard both forwarding and the callback: token hooks can reenter first.
    let (amount_received, collateral_before, refund_before) =
        storage::with_flash_guard(env, || {
            let amount_received =
                mint_and_forward(env, &mut account, debt, amount, receiver, &mut cache);
            // Baselines exclude funding and forwarding; count callback receipts only.
            let collateral_before = snapshot_balances(
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L206-226)
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

    assert_eq!(s.wallet(&s.alice), 0);
    assert_eq!(s.wallet(&s.attacker), WALLET_BALANCE);
    assert_eq!(s.t.supply_balance_raw(ALICE, "ETH"), FAIR_OUT_ETH);
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

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```
