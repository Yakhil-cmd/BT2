### Title
Unvalidated route pool addresses let malicious contracts steal caller wallet tokens - ([File: contracts/swap-aggregator/src/execute/mod.rs])

### Summary

High. The router accepts the pool contract for every swap instruction from caller-supplied `assets` and invokes it without checking an allowlist. `Program::decode` validates only the packed-route structure, registry bounds, token inequality, and split weights; it does not validate that `idx_a` names a genuine venue pool. [1](#0-0) [2](#0-1)  A malicious pool can therefore execute arbitrary contract code inside the swap call, including a token transfer from the user that invoked the controller strategy. [3](#0-2) 

### Finding Description

Controller strategies such as `swap_collateral` authenticate the caller, verify ownership or delegation of the account, withdraw collateral, and forward caller-controlled `swap` bytes to the configured router. [4](#0-3)  The controller narrowly authorizes one input-token transfer to the router and measures the router's input/output deltas, but those checks do not constrain contracts invoked by the route. [5](#0-4) 

For a swap instruction, the router constructs `SwapHop.pool` directly from `assets[idx_a]` and invokes the selected venue adapter. [1](#0-0)  For Phoenix and Sushi routes, the router authorizes the pool to pull the routed input and then invokes that arbitrary `pool` address's `swap` method. [3](#0-2) [6](#0-5)  During that invocation, the pool can call `unrelated_token.transfer(victim, attacker, balance)`; transaction simulation records that transfer as a child of the user's controller-strategy authorization, and the transfer succeeds if the user signs the simulated tree. [7](#0-6) [8](#0-7) 

The attack is not merely bad routing: the malicious pool can return a fair `token_out` amount to the router, so the measured output, payload minimum, collateral redeposit, and final account-risk checks can all pass while an unrelated wallet token is drained. [9](#0-8) [10](#0-9) 

### Impact Explanation

An attacker can steal any spendable token balance held by a user who signs a poisoned controller-strategy transaction. The stolen amount is unrelated to the routed input and is not bounded by `amount_in`, the route's `min_out`, or the account's final health checks. The repository's enforcing-mode test demonstrates that signing the recorded rogue child transfer moves the victim's entire unrelated `WALLET_BALANCE` to the attacker while preserving the expected swap output. [8](#0-7) 

### Likelihood Explanation

An unprivileged attacker can deploy the malicious pool, construct a structurally valid route naming it as `idx_a`, and pre-fund it with enough output token to satisfy the victim's quote. No privileged role, leaked key, router compromise, or protocol upgrade is required. [11](#0-10)  Exploitation does require tricking the victim into signing the simulation-produced authorization tree containing the extra token transfer, which lowers likelihood but still leaves high-impact theft of user funds. [12](#0-11) 

### Recommendation

Do not invoke route-supplied pool addresses directly. Maintain an on-chain, governance-controlled venue-pool registry, or otherwise bind each venue instruction to a cryptographically verified pool identity before dispatch. If arbitrary pools must remain supported, add a protocol-level safeguard that prevents route-descendant contracts from obtaining user authorization for calls outside the expected input pull; client-side decoded-auth warnings should be defense in depth rather than the primary control.

### Proof of Concept

1. Victim owns controller account `account_id`, has USDC collateral, and holds `VICTIM_TOKEN` unrelated to the lending market.
2. Attacker deploys `MaliciousPool` and funds it with enough ETH to pay the expected output. Its Phoenix-compatible `swap` method:
   - pulls `amount_in` of `token_in` from the router under the router's authorized child invocation;
   - calls `VICTIM_TOKEN.transfer(victim, attacker, victim_balance)`;
   - transfers at least `min_out` ETH back to the router.
3. Construct a `StrategyPayload` with:
   - `assets = [MaliciousPool, USDC, ETH]`
   - `amounts = [fair_min_out]`
   - one instruction: Phoenix opcode `2`, mode `All`, `idx_a = 0`, `idx_b = 1`, `idx_c = 2`.
4. Have the victim invoke:

```text
controller::swap_collateral(
    caller = victim,
    account_id = victim_account_id,
    current = HubAssetKey { hub_id, asset: USDC },
    amount = 5_000 USDC,
    new = HubAssetKey { hub_id, asset: ETH },
    swap = malicious_payload_xdr,
)
```

The controller authorizes only the USDC input transfer to the router, but the router invokes the route-selected malicious pool. [13](#0-12) [1](#0-0)  Simulation records the pool's `VICTIM_TOKEN.transfer(victim, attacker, balance)` beneath the victim's `swap_collateral` authorization; once signed, the transfer executes and the unrelated token is stolen while the ETH output and final account checks succeed. [14](#0-13) [8](#0-7)

### Citations

**File:** contracts/swap-aggregator/src/execute/mod.rs (L125-135)
```rust
    let total_out = vault.balance_of(&output_token);
    if total_out < total_min_out {
        panic_with_error!(&env, Error::SlippageExceeded);
    }

    vault.withdraw(&output_token, total_out);
    token::Client::new(&env, &output_token).transfer(&router, &sender, &total_out);

    residual::accrue_residual_as_revenue(&env, &mut vault);

    total_out
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L152-165)
```rust
        Opcode::Swap(venue) => {
            let hop = SwapHop {
                pool: ctx.assets.get_unchecked(op.idx_a),
                token_in: ctx.assets.get_unchecked(op.idx_b),
                token_out: ctx.assets.get_unchecked(op.idx_c),
                venue,
            };
            let amount_in = resolve_amount(ctx, vault, op.mode, &hop.token_in, prev);
            if amount_in <= 0 {
                panic_with_error!(ctx.env, Error::InvalidAmount);
            }

            vault.withdraw(&hop.token_in, amount_in);
            let out = venues::dispatch_hop(ctx.env, ctx.router, &hop, amount_in, tokens_cache);
```

**File:** contracts/swap-aggregator/src/program.rs (L183-235)
```rust
    pub(crate) fn decode(env: &Env, ops: &Bytes, assets_len: u32, amounts_len: u32) -> Self {
        if assets_len == 0 || assets_len > MAX_ASSETS || amounts_len > MAX_AMOUNTS {
            panic_with_error!(env, Error::InvalidRouteXdr);
        }

        let len = ops.len();
        if len < HEADER_LEN || len as usize > MAX_PROGRAM_BYTES {
            panic_with_error!(env, Error::InvalidRouteXdr);
        }

        let mut buf = [0u8; MAX_PROGRAM_BYTES];
        ops.copy_into_slice(&mut buf[..len as usize]);

        if buf[head::VERSION] != VERSION {
            panic_with_error!(env, Error::InvalidRouteXdr);
        }

        let op_count = buf[head::OP_COUNT] as u32;
        let weight_count = buf[head::WEIGHT_COUNT] as u32;
        if op_count == 0 || op_count > MAX_OPS || weight_count > MAX_WEIGHTS {
            panic_with_error!(env, Error::EmptyBatch);
        }
        let weights_at = HEADER_LEN + OP_LEN * op_count;
        if len != weights_at + WEIGHT_LEN * weight_count {
            panic_with_error!(env, Error::InvalidRouteXdr);
        }

        let token_in = buf[head::TOKEN_IN] as u32;
        let token_out = buf[head::TOKEN_OUT] as u32;
        let min_out = buf[head::MIN_OUT] as u32;
        if token_in >= assets_len || token_out >= assets_len || min_out >= amounts_len {
            panic_with_error!(env, Error::InvalidRouteXdr);
        }
        if token_in == token_out {
            panic_with_error!(env, Error::SameToken);
        }

        let referral = &buf[head::REFERRAL..head::REFERRAL + 4];
        let referral_id =
            u32::from_be_bytes([referral[0], referral[1], referral[2], referral[3]]) as u64;

        let program = Self {
            buf,
            op_count,
            weights_at,
            token_in,
            token_out,
            min_out,
            referral_id,
        };
        program.validate(env, assets_len, amounts_len, weight_count);
        program
    }
```

**File:** contracts/swap-aggregator/src/program.rs (L281-291)
```rust
            if idx_a >= assets_len || idx_b >= assets_len {
                panic_with_error!(env, Error::InvalidRouteXdr);
            }
            match opcode {
                Opcode::Swap(_) => {
                    if idx_c >= assets_len {
                        panic_with_error!(env, Error::InvalidRouteXdr);
                    }
                    if idx_b == idx_c {
                        panic_with_error!(env, Error::SameToken);
                    }
```

**File:** contracts/swap-aggregator/src/venues/phoenix.rs (L22-25)
```rust
    ctx.authorize_pool_pull();
    let _: i128 = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
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

**File:** contracts/controller/src/strategies/swap_collateral.rs (L67-76)
```rust
    let deposit_assets = vec![env, (new.clone(), swapped_amount)];
    supply::process_deposit(
        env,
        &env.current_contract_address(),
        &mut account,
        &deposit_assets,
        &mut cache,
    );

    strategy_finalize(env, account_id, &mut account, &mut cache);
```

**File:** contracts/controller/src/strategies/swap.rs (L29-54)
```rust
    // Snapshot before router execution to measure its spend and output.
    let in_before = token_in_client.balance(&controller);
    let out_before = token::Client::new(env, token_out).balance(&controller);

    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });

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

**File:** contracts/swap-aggregator/src/venues/sushi.rs (L37-50)
```rust
    ctx.authorize_pool_pull();

    let args: Vec<Val> = vec![
        ctx.env,
        ctx.router.into_val(ctx.env),
        ctx.router.into_val(ctx.env),
        zero_for_one.into_val(ctx.env),
        ctx.amount_in.into_val(ctx.env),
        price_limit.into_val(ctx.env),
        hints,
    ];
    let _: Val = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &Symbol::new(ctx.env, "swap"), args);
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
