### Title
Unvalidated swap-route pool contracts can abuse sender authorization to steal unrelated wallet tokens - ([File: contracts/swap-aggregator/src/execute/mod.rs])

### Summary
`execute_strategy` executes pool contracts supplied through the route payload without an on-chain venue allowlist, placing attacker-controlled code beneath the sender’s authorization tree. A malicious pool can return enough output to satisfy settlement while adding an unrelated `token.transfer(sender, attacker, amount)` child invocation that drains the sender’s wallet if the simulated authorization tree is signed. [1](#0-0) [2](#0-1) 

### Finding Description
`Router::execute_strategy` accepts caller-supplied `swap_xdr`, decodes it into `StrategyPayload`, and calls `execute::run` for the supplied `sender`. [3](#0-2)  The strategy payload’s `assets` registry carries arbitrary token and pool `Address` values selected by instruction indices. [4](#0-3) [5](#0-4)  Execution requires `sender.require_auth()` and transfers `total_in` from that sender before dispatching the route’s pool calls. [6](#0-5)  For a Phoenix hop, the router authorizes the input-token pull and then invokes `swap` on the payload-selected pool address. [7](#0-6)  The project’s own threat model confirms that route-selected pools and token addresses are not allowlisted and that third-party code can add a caller-token transfer beneath the caller’s authorization entry. [2](#0-1) 

### Impact Explanation
The malicious pool can satisfy the router’s measured settlement checks by consuming the routed input and returning a positive output while separately transferring unrelated tokens from the victim’s wallet. [8](#0-7)  Because Soroban records the malicious transfer as a child of the victim’s signed swap authorization, signing the simulated tree authorizes the theft of wallet assets beyond the routed input. [9](#0-8)  The repository’s regression test demonstrates this exact outcome: after the poisoned authorization tree is accepted, the victim’s unrelated wallet-token balance becomes zero and the attacker receives it. [10](#0-9) 

### Likelihood Explanation
An unprivileged attacker can deploy a contract implementing the expected venue interface, embed its address in a route’s `assets` registry, and make it return sufficient output so normal input, output, and minimum checks pass. [11](#0-10) [8](#0-7)  Exploitation requires the victim to submit and sign the poisoned authorization tree produced by simulation, so wallet or client verification is the remaining defense rather than an on-chain control. [12](#0-11) [13](#0-12)  The issue is directly reachable through `execute_strategy`, and controller route-using strategies can place equivalent third-party code beneath the caller’s root authorization. [3](#0-2) [14](#0-13) 

### Recommendation
Enforce a governance-managed pool allowlist per venue before dispatch, so `assets` cannot name arbitrary executable contracts for trusted venue opcodes. Keep and strengthen client-side authorization-tree validation to reject any child invocation other than the expected input transfer, but treat that validation as defense-in-depth rather than the protocol boundary. [2](#0-1) 

### Proof of Concept
1. Deploy `RoguePool`, implementing the Phoenix `swap` signature and containing logic that pulls the routed input from the router, sends enough `token_out` back to the router, and calls `wallet_token.transfer(victim, attacker, victim_balance)`. The router grants the pool pull authorization before invoking the payload-selected pool. [7](#0-6) 
2. Construct `StrategyPayload { amounts, assets, ops }` where `assets` contains `[token_in, token_out, rogue_pool]`, `amounts` contains a positive `min_out`, and `ops` encodes one Phoenix `Swap` with `idx_a = 2`, `idx_b = 0`, and `idx_c = 1`. Instructions resolve all three values directly from the caller-controlled `assets` registry. [5](#0-4) [15](#0-14) 
3. Have the victim call `Router::execute_strategy(victim, total_in, swap_xdr)` or an equivalent controller route strategy; the router authenticates `sender`, pulls the input, and dispatches the malicious pool. [3](#0-2) [6](#0-5) 
4. During simulation, the rogue wallet transfer appears as a child invocation under the victim’s swap authorization; if that tree is signed, the malicious transfer executes. [16](#0-15) 
5. The checked test path shows the poisoned tree reducing the victim wallet balance from `77_770_000_000` to zero and crediting the same amount to the attacker while the swap still completes. [17](#0-16)

### Citations

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-85)
```rust
pub(crate) fn run(env: Env, sender: Address, total_in: i128, payload: StrategyPayload) -> i128 {
    sender.require_auth();

    if total_in <= 0 {
        panic_with_error!(&env, Error::InvalidAmount);
    }

    let StrategyPayload {
        amounts,
        assets,
        ops,
    } = payload;
    let program = Program::decode(&env, &ops, assets.len(), amounts.len());

    let input_token = assets.get_unchecked(program.token_in);
    let output_token = assets.get_unchecked(program.token_out);
    let total_min_out = amounts.get_unchecked(program.min_out);
    if total_min_out <= 0 {
        panic_with_error!(&env, Error::SlippageExceeded);
    }

    let router = env.current_contract_address();
    let mut vault = Vault::new(&env);
    let mut tokens_cache: Map<Address, Vec<Address>> = Map::new(&env);

    // Credit the measured delta, not declared `total_in`: a fee-on-transfer
    // input would otherwise draw the shortfall from the fee reserve.
    let credited_in = transfer_amount_measured(
        &env,
        &input_token,
        &sender,
        &router,
        total_in,
        GenericError::AmountMustBePositive,
    );
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L121-135)
```rust
    if !fee_on_input {
        fees::apply_fees_on_token(&env, &mut vault, &output_token, referral_id);
    }

    let total_out = vault.balance_of(&output_token);
    if total_out < total_min_out {
        panic_with_error!(&env, Error::SlippageExceeded);
    }

    vault.withdraw(&output_token, total_out);
    token::Client::new(&env, &output_token).transfer(&router, &sender, &total_out);

    residual::accrue_residual_as_revenue(&env, &mut vault);

    total_out
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L153-158)
```rust
            let hop = SwapHop {
                pool: ctx.assets.get_unchecked(op.idx_a),
                token_in: ctx.assets.get_unchecked(op.idx_b),
                token_out: ctx.assets.get_unchecked(op.idx_c),
                venue,
            };
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

**File:** contracts/swap-aggregator/src/lib.rs (L245-255)
```rust
    /// Decodes `swap_xdr` as a `StrategyPayload` and runs it for `sender`.
    ///
    /// Requires `sender` authorization. Pulls `total_in` of the input token, runs the
    /// instruction stream, applies fees, checks the minimum output, and returns the amount
    /// delivered to `sender`. Panics with `Error::InvalidRouteXdr` if the XDR does not decode.
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        renew_instance(&env);
        let payload = StrategyPayload::from_xdr(&env, &swap_xdr)
            .unwrap_or_else(|_| panic_with_error!(&env, Error::InvalidRouteXdr));
        execute::run(env, sender, total_in, payload)
    }
```

**File:** contracts/swap-aggregator/src/types.rs (L38-44)
```rust
pub struct StrategyPayload {
    /// Amount registry: min-out, fixed inputs, burn floors, mint min-shares.
    pub amounts: Vec<i128>,
    /// Address registry: tokens, pools, and LP share tokens.
    pub assets: Vec<Address>,
    /// Packed program: header, instruction records, split weights.
    pub ops: Bytes,
```

**File:** contracts/swap-aggregator/src/venues/phoenix.rs (L22-25)
```rust
    ctx.authorize_pool_pull();
    let _: i128 = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L42-58)
```rust
    let received = ctx
        .output_balance()
        .checked_sub(before_out)
        .unwrap_or_else(|| panic_with_error!(env, Error::ZeroOutput));
    if received <= 0 {
        panic_with_error!(env, Error::ZeroOutput);
    }

    let after_in = ctx.input_balance();
    let spent = before_in
        .checked_sub(after_in)
        .unwrap_or_else(|| panic_with_error!(env, Error::InvalidAmount));
    if spent != amount_in {
        panic_with_error!(env, Error::InvalidAmount);
    }

    received
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

**File:** contracts/swap-aggregator/src/program.rs (L110-117)
```rust
            0 => Some(Self::Swap(SwapVenue::Soroswap)),
            1 => Some(Self::Swap(SwapVenue::Aquarius)),
            2 => Some(Self::Swap(SwapVenue::Phoenix)),
            3 => Some(Self::Swap(SwapVenue::Sushi)),
            4 => Some(Self::Swap(SwapVenue::CometDex)),
            5 => Some(Self::Burn),
            6 => Some(Self::Mint),
            _ => None,
```
