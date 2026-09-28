### Title

Unvalidated route pools can execute arbitrary sender-authorized token transfers and drain unrelated wallet funds - (File: contracts/swap-aggregator/src/venues/soroswap.rs)

### Summary

`execute_strategy` accepts a caller-controlled `swap_xdr` program whose `assets` registry supplies the pool address for every hop. The program decoder bounds indices and opcodes, but it does not bind a swap opcode to an approved venue contract. A Soroswap hop therefore invokes whatever address the payload names as `pool`, allowing that contract to request additional `sender` authorization for unrelated token transfers while still satisfying the router’s measured-input and measured-output checks. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description

`Router::execute_strategy` deserializes attacker-controlled route bytes and passes the decoded `StrategyPayload` to `execute::run`. [1](#0-0) 

`execute::run` authenticates `sender`, decodes the packed program, pulls `total_in`, and then executes every payload instruction. [4](#0-3) [5](#0-4) 

For a swap instruction, `execute_op` obtains `pool`, `token_in`, and `token_out` directly from the payload’s `assets` registry and dispatches to the selected venue adapter. [6](#0-5) 

`Program::validate` checks the opcode, index ranges, `Prev` links, same-token hops, and split weights, but contains no pool-identity or venue-address allowlist check. [3](#0-2) 

The Soroswap adapter trusts that payload-selected pool: it calls `pool.get_reserves`, sends `amount_in` to that pool, and then invokes `pool.swap`. [7](#0-6) 

The surrounding `dispatch_hop` only verifies that the router spent exactly `amount_in` and received a positive `token_out` delta; it does not prevent the invoked pool from adding an unrelated `token.transfer(sender, attacker, amount)` requiring `sender` authorization inside the same transaction’s authorization tree. [8](#0-7) [9](#0-8) 

The controller strategy path forwards caller-supplied `swap` bytes to the configured router, while the direct `execute_strategy` path exposes the same payload trust boundary to any swap user. [10](#0-9) [11](#0-10) 

### Impact Explanation

A malicious route can steal tokens from the signing sender beyond the declared `total_in`. The rogue pool can satisfy the swap accounting—receive `amount_in` and return a positive `token_out`—while also making a nested transfer of a different token from the victim to the attacker. [12](#0-11) [9](#0-8) 

Neither the payload’s `min_out` nor the controller’s measured-output and overspend checks bounds that extra transfer because both only account for the route’s input and output tokens. [13](#0-12) [14](#0-13) 

### Likelihood Explanation

An unprivileged attacker can deploy a contract that implements the small `get_reserves`/`swap` interface expected by the Soroswap adapter and encode it as the hop pool. The attacker must then persuade a victim to sign a transaction whose simulated authorization tree includes the malicious child transfer; wallets or clients that display only the top-level swap and input pull can make that practical. [15](#0-14) [9](#0-8) 

The impact is theft of arbitrary signed user funds, but the required victim signature and authorization-tree approval keep the overall severity below a no-interaction wallet-drain primitive. [9](#0-8) 

### Recommendation

Bind each venue opcode to governance-approved pool contracts before dispatching the hop, rather than accepting `hop.pool` as arbitrary route data. [6](#0-5) [3](#0-2) 

At minimum, `Program::decode` or `dispatch_hop` should reject any `Swap` whose `idx_a` is not registered for the selected venue, and the registration should record the immutable contract address expected to implement that pool. [16](#0-15) 

Clients should additionally decode every nested authorization entry and reject a route whose `sender` authorization contains any transfer other than the single `token_in.transfer(sender, router, total_in)` pull. [17](#0-16) [18](#0-17) 

### Proof of Concept

Construct a valid one-hop `StrategyPayload`:

```text
assets  = [TOKEN_IN, TOKEN_OUT, ROGUE_POOL]
amounts = [1]                    // positive min_out
ops =
  [VERSION=1,
   TOKEN_IN=0,
   TOKEN_OUT=1,
   MIN_OUT=0,
   REFERRAL=0u32,
   OP_COUNT=1,
   WEIGHT_COUNT=0,
   opcode=0,                     // SwapVenue::Soroswap
   mode=0,                       // Mode::All
   idx_a=2,                      // pool = ROGUE_POOL
   idx_b=0,                      // token_in = TOKEN_IN
   idx_c=1]                      // token_out = TOKEN_OUT
```

Call:

```text
execute_strategy(
    sender    = victim,
    total_in  = 100,
    swap_xdr  = XDR(payload)
)
```

`ROGUE_POOL` implements `get_reserves` with values producing a positive `requested_out`, accepts the router’s `TOKEN_IN` transfer, and implements `swap(amount_0_out, amount_1_out, router)` to:

1. transfer the requested positive `TOKEN_OUT` amount to the router;
2. call `ATTACKED_TOKEN.transfer(victim, attacker, stolen_amount)`.

The route passes the program’s structural validation because `idx_a` only has to be an in-range `assets` index, not a known Soroswap pool. [19](#0-18) 

The router records a positive output and exact input spend, so `dispatch_hop`, `min_out`, payout, and residual checks can all succeed while the nested `ATTACKED_TOKEN` transfer is included in the victim-signed authorization tree. [12](#0-11) [14](#0-13)

### Citations

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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L51-86)
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
    vault.deposit(&input_token, credited_in);
```

**File:** contracts/swap-aggregator/src/execute/mod.rs (L111-119)
```rust
    for i in 0..program.len() {
        prev = execute_op(
            &ctx,
            &mut vault,
            program.op(&env, i),
            prev,
            &mut tokens_cache,
        );
    }
```

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

**File:** contracts/swap-aggregator/src/execute/mod.rs (L151-170)
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
            if out <= 0 {
                panic_with_error!(ctx.env, Error::ZeroOutput);
            }
            vault.deposit(&hop.token_out, out);
            Some((hop.token_out, out))
```

**File:** contracts/swap-aggregator/src/program.rs (L237-302)
```rust
    /// Validates every instruction's opcode, mode, and indices before execution begins,
    /// including the `Prev` chain, same-token swaps, and split-weight bounds.
    fn validate(&self, env: &Env, assets_len: u32, amounts_len: u32, weight_count: u32) {
        for i in 0..self.op_count {
            let record = self.raw(i);
            let Some(opcode) = Opcode::from_u8(record[field::OPCODE]) else {
                panic_with_error!(env, Error::InvalidRouteXdr);
            };
            let mode = Mode::from_u8(record[field::MODE]);
            let (idx_a, idx_b, idx_c) = (
                record[field::POOL] as u32,
                record[field::TOKEN_IN] as u32,
                record[field::TOKEN_OUT] as u32,
            );

            // `Prev` is a purely structural link: the predecessor must exist,
            // must have a single output, and that output must be this
            // instruction's input.
            if mode == Mode::Prev {
                if i == 0 {
                    panic_with_error!(env, Error::BrokenTokenChain);
                }
                let previous = self.raw(i - 1);
                let produced = match Opcode::from_u8(previous[field::OPCODE]) {
                    // A swap produces its `token_out`, a mint its share token.
                    Some(Opcode::Swap(_)) => previous[field::TOKEN_OUT],
                    Some(Opcode::Mint) => previous[field::TOKEN_IN],
                    // A burn releases every constituent at once.
                    _ => panic_with_error!(env, Error::BrokenTokenChain),
                };
                if idx_b != produced as u32 {
                    panic_with_error!(env, Error::BrokenTokenChain);
                }
            }
            match mode {
                Mode::Fixed(idx) if idx as u32 >= amounts_len => {
                    panic_with_error!(env, Error::InvalidRouteXdr)
                }
                Mode::Ppm(idx) if idx as u32 >= weight_count => {
                    panic_with_error!(env, Error::InvalidRouteXdr)
                }
                _ => {}
            }

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
                }
                // Liquidity legs spend the full vault balance, so only `Mode::All` is valid.
                Opcode::Burn | Opcode::Mint => {
                    if mode != Mode::All {
                        panic_with_error!(env, Error::InvalidRouteXdr);
                    }
                    if idx_c >= amounts_len {
                        panic_with_error!(env, Error::InvalidRouteXdr);
                    }
                }
            }
```

**File:** contracts/swap-aggregator/src/venues/soroswap.rs (L51-87)
```rust
pub(crate) fn swap(ctx: &HopContext<'_>) {
    let token_in_is_0 = ctx.hop.token_in < ctx.hop.token_out;

    let no_args: Vec<Val> = vec![ctx.env];
    let (reserve_0, reserve_1): (i128, i128) = ctx.env.invoke_contract(
        &ctx.hop.pool,
        &Symbol::new(ctx.env, "get_reserves"),
        no_args,
    );
    let (reserve_in, reserve_out) = if token_in_is_0 {
        (reserve_0, reserve_1)
    } else {
        (reserve_1, reserve_0)
    };

    let requested_out = soroswap_amount_out(ctx.env, ctx.amount_in, reserve_in, reserve_out);
    if requested_out <= 0 {
        panic_with_error!(ctx.env, Error::ZeroOutput);
    }

    let token_client = token::Client::new(ctx.env, &ctx.hop.token_in);
    token_client.transfer(ctx.router, &ctx.hop.pool, &ctx.amount_in);

    let (amount_0_out, amount_1_out) = if token_in_is_0 {
        (0_i128, requested_out)
    } else {
        (requested_out, 0_i128)
    };
    let args: Vec<Val> = vec![
        ctx.env,
        amount_0_out.into_val(ctx.env),
        amount_1_out.into_val(ctx.env),
        ctx.router.into_val(ctx.env),
    ];
    let _: () = ctx
        .env
        .invoke_contract(&ctx.hop.pool, &symbol_short!("swap"), args);
```

**File:** contracts/swap-aggregator/src/venues/mod.rs (L23-58)
```rust
pub(crate) fn dispatch_hop(
    env: &Env,
    router: &Address,
    hop: &SwapHop,
    amount_in: i128,
    tokens_cache: &mut Map<Address, Vec<Address>>,
) -> i128 {
    let ctx = HopContext::new(env, router, hop, amount_in);
    let before_in = ctx.input_balance();
    let before_out = ctx.output_balance();

    match hop.venue {
        SwapVenue::Soroswap => soroswap::swap(&ctx),
        SwapVenue::Aquarius => aquarius::swap(&ctx, tokens_cache),
        SwapVenue::Phoenix => phoenix::swap(&ctx),
        SwapVenue::Sushi => sushi::swap(&ctx),
        SwapVenue::CometDex => comet::swap(&ctx),
    };

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

**File:** contracts/controller/src/strategies/swap.rs (L33-38)
```rust
    // Authorize only this token transfer to this router for this exact amount.
    authorize_transfer_as_current(env, token_in, &controller, &router_addr, amount_in);

    storage::with_flash_guard(env, || {
        let _ = router.execute_strategy(&controller, &amount_in, swap);
    });
```

**File:** contracts/controller/src/strategies/swap.rs (L40-55)
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
}
```

**File:** interfaces/swap-aggregator/src/lib.rs (L18-21)
```rust
#[contractclient(name = "SwapAggregatorClient")]
pub trait SwapAggregatorInterface {
    fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128;

```

**File:** common/src/token.rs (L16-30)
```rust
pub fn transfer_amount_measured(
    env: &Env,
    asset: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
    non_positive_error: GenericError,
) -> i128 {
    assert_with_error!(env, amount > 0, non_positive_error);
    let tok = token::Client::new(env, asset);
    let pre = tok.balance(to);
    tok.transfer(from, to, &amount);
    let post = tok.balance(to);
    post.checked_sub(pre)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::AmountMustBePositive))
```
