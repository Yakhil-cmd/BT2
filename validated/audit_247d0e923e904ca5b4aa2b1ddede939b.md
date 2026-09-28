### Title

Route-selected pool contracts can inject unauthorized-looking token transfers into the caller’s signed authorization tree - (File: `contracts/swap-aggregator/src/execute/mod.rs`) [1](#0-0) 

### Summary

`execute_strategy` decodes caller-supplied route bytes whose `assets` registry can contain arbitrary pool addresses, then invokes venue-specific functions on those addresses without an on-chain pool allowlist. [2](#0-1) [3](#0-2)  A malicious pool can satisfy the measured input and output accounting while also calling `token.transfer(victim, attacker, amount)`; if the victim signs the simulated authorization tree containing that nested transfer, the unrelated wallet token is stolen. [4](#0-3) [5](#0-4) 

### Finding Description

The controller’s strategy helper authorizes one exact input-token transfer to the configured router and then invokes `router.execute_strategy(controller, amount_in, swap)`. [6](#0-5)  The router only checks that `sender` authorized the call before pulling `total_in`, decoding the packed program, and executing its instructions. [7](#0-6) [8](#0-7) 

For each `Swap` instruction, `idx_a` selects an arbitrary `pool` address from the caller-supplied `assets` vector and `dispatch_hop` receives that address. [1](#0-0)  Venue adapters then invoke fixed methods on the supplied pool address; for example, the Phoenix adapter calls `hop.pool.swap(...)`, while Sushi calls `hop.pool.token0()`, `token1()`, `get_oracle_hints()`, and `swap()`. [9](#0-8) [10](#0-9) 

Although the router measures its own `token_in` spend and `token_out` receipt, those checks do not prevent the invoked pool from requesting an additional token transfer from the original transaction signer. [11](#0-10)  The harness demonstrates that an unsigned rogue transfer is rejected, while including that transfer as a child of the victim’s signed `swap_collateral` invocation makes it execute. [12](#0-11) [13](#0-12) 

The project threat model explicitly records this behavior: route-selected third-party code runs below the caller’s authorization, and a token transfer it requests executes when the caller signs the resulting tree. [14](#0-13)  The same exposure applies to direct `execute_strategy` calls, where the sender’s authorization already contains the expected input transfer. [15](#0-14) 

### Impact Explanation

A malicious route can cause theft of user funds unrelated to the swap’s declared input and output assets. [16](#0-15)  In the proof-of-concept test, the victim’s unrelated `WALLET_BALANCE` moves entirely from Alice to the attacker while the swap itself still completes. [5](#0-4) 

The loss is not bounded by `amount_in`, `min_out`, measured router deltas, or the lending account’s final risk checks because those controls only cover the declared route tokens and position state. [11](#0-10) [17](#0-16) 

### Likelihood Explanation

Exploitation requires the victim to submit a crafted route and sign the authorization tree containing the extra token transfer, so it is not executable solely by calling the victim’s account without their authorization. [18](#0-17)  However, an unprivileged attacker can deploy the malicious pool, encode its address in the payload’s `assets` registry, and make it satisfy the selected venue ABI plus the router’s balance-delta checks. [1](#0-0) [11](#0-10) 

The route bytes are opaque to users, and an honest simulation presents the rogue transfer as a nested authorization under the operation the user intended to authorize. [19](#0-18)  This is therefore a credible phishing or malicious-route-source scenario rather than a purely theoretical signer compromise.

### Recommendation

Do not allow arbitrary route-supplied addresses to be invoked as DEX pools. Maintain an on-chain venue pool registry or cryptographic pool verification mechanism, validate `hop.pool` before dispatch, and reject any pool/token combination not explicitly registered for the selected venue. [20](#0-19) [3](#0-2) 

Until on-chain validation exists, clients must treat the entire simulated authorization tree as security-critical and reject any child invocation beyond the single expected `token_in.transfer(sender, router, total_in)` for direct swaps—or the expected controller operation tree for composed strategies. [8](#0-7) [15](#0-14) 

### Proof of Concept

1. Deploy a malicious contract exposing the ABI expected by a selected venue, such as Phoenix `swap`. [21](#0-20) 
2. Inside that `swap` function, pull `amount_in` from the router, transfer enough `token_out` back to satisfy `received > 0`, and additionally call `unrelated_token.transfer(victim, attacker, victim_balance)`. [11](#0-10) [4](#0-3) 
3. Encode a `StrategyPayload` whose `assets` registry contains the input token, output token, and malicious pool address, and whose swap instruction sets `idx_a` to that pool. [2](#0-1) [20](#0-19) 
4. Cause the victim to invoke either `Router::execute_strategy(sender, total_in, swap_xdr)` directly or `Controller::swap_collateral(caller, account_id, current, amount, new, swap)` with the crafted route. [22](#0-21) [6](#0-5) 
5. Simulation records the unrelated transfer as a nested authorization; if the victim signs that tree, the malicious pool’s transfer succeeds and the attacker receives the victim’s unrelated token balance. [13](#0-12)

### Citations

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-63)
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
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L78-86)
```rust
    let credited_in = transfer_amount_measured(
        &env,
        &input_token,
        &sender,
        &router,
        total_in,
        GenericError::AmountMustBePositive,
    );
    vault.deposit(&input_token, credited_in);
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L151-165)
```rust
    match op.opcode {
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

**File:** contracts/swap-aggregator/src/venues/mod.rs (L42-56)
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L20-22)
```rust
const SWAP_IN_USDC: i128 = 50_000_000_000; // 5 000 USDC, 7 decimals
const FAIR_OUT_ETH: i128 = 25_000_000; // 2.5 ETH at $2 000
const WALLET_BALANCE: i128 = 77_770_000_000; // Alice's balance of a token the protocol never listed
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L243-253)
```rust
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
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L259-268)
```rust
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

**File:** contracts/swap-aggregator/src/venues/phoenix.rs (L11-25)
```rust
pub(crate) fn swap(ctx: &HopContext<'_>) {
    let args: Vec<Val> = vec![
        ctx.env,
        ctx.router.into_val(ctx.env),
        ctx.hop.token_in.into_val(ctx.env),
        ctx.amount_in.into_val(ctx.env),
        Option::<i128>::None.into_val(ctx.env),
        Option::<i64>::None.into_val(ctx.env),
        Option::<u64>::None.into_val(ctx.env),
        Option::<i64>::None.into_val(ctx.env),
    ];
    ctx.authorize_pool_pull();
    let _: i128 = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
```

**File:** contracts/swap-aggregator/src/venues/sushi.rs (L20-35)
```rust
    let token0: Address = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "token0"),
        no_args.clone(),
    );
    let token1: Address =
        ctx.env
            .invoke_contract(&ctx.hop.pool, &Symbol::new(ctx.env, "token1"), no_args);
    let zero_for_one = ctx.direction_for_pair(&token0, &token1);

    let price_limit = sqrt_price_limit(ctx.env, zero_for_one);
    let hints: Val = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "get_oracle_hints"),
        vec![ctx.env],
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

**File:** contracts/swap-aggregator/src/lib.rs (L250-255)
```rust
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        renew_instance(&env);
        let payload = StrategyPayload::from_xdr(&env, &swap_xdr)
            .unwrap_or_else(|_| panic_with_error!(&env, Error::InvalidRouteXdr));
        execute::run(env, sender, total_in, payload)
    }
```
