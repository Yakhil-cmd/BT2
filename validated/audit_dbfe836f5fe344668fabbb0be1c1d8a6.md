### Title
Caller-selected flash-loan receiver can execute unauthorized wallet transfers under the caller's authorization tree - (File: `contracts/pool/src/ops/flash.rs`)

### Summary
A malicious `receiver` supplied to `Controller::flash_loan` is invoked by the pool while the initiator's authorization context is active, allowing it to request additional token transfers from the initiator that are recorded as children of the signed authorization tree. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`Controller::flash_loan` accepts a caller-selected `receiver` and forwards it unchanged to `LiquidityPoolClient::flash_loan`. [1](#0-0) 

The pool then performs a dynamic cross-contract call to `execute_flash_loan` on that receiver and passes the original `initiator` to it. [2](#0-1) 

Soroban records an authorization required by code invoked below the caller's entrypoint as a child of that caller's authorization tree; if the caller signs the simulated tree, that child transfer executes. [4](#0-3) 

Consequently, a malicious receiver can invoke `token.transfer(initiator, attacker, amount)` for any token held by the initiator, while still approving normal flash-loan repayment so the surrounding protocol settlement succeeds. [5](#0-4) [6](#0-5) 

This is analogous to insecure library loading because an attacker-selected contract is loaded into an execution context carrying the user's authority. [7](#0-6) 

### Impact Explanation
The receiver can steal unrelated wallet assets not involved in the flash loan, provided the victim signs the poisoned authorization tree produced by simulation. [8](#0-7) 

The malicious transfer does not need to interfere with repayment: the receiver retains the borrowed principal, adds the fee, and approves the pool for `amount + fee`, while the separate wallet-token transfer is authorized by the victim's signature. [6](#0-5) [9](#0-8) 

### Likelihood Explanation
Exploitation requires the victim to submit a flash loan using an attacker-provided receiver or integration payload and to sign an authorization tree containing an unexpected token-transfer child. [10](#0-9) 

Honest simulation exposes the extra authorization, so wallets and clients that reject unexpected children prevent the loss; however, the protocol itself places no venue-like allowlist or authorization-tree constraint on the caller-selected receiver. [1](#0-0) [11](#0-10) 

### Recommendation
Treat the authorization tree as part of the flash-loan payload and require clients to reject any child invocation other than the expected operations needed for the loan. [11](#0-10) 

For production integrations, prefer pinned and reviewed receiver contracts or a governance-managed receiver registry rather than accepting an arbitrary `receiver` address from untrusted input. [1](#0-0) 

### Proof of Concept
1. Deploy a receiver exposing `execute_flash_loan` whose callback approves `amount + fee` to the pool and additionally calls `token.transfer(victim, attacker, wallet_balance)` on an unrelated token. [6](#0-5) 
2. Have the victim invoke `Controller::flash_loan(caller=victim, hub_asset=..., amount=..., receiver=malicious_receiver, data=...)`; the controller passes that receiver to the pool. [1](#0-0) 
3. The pool invokes `malicious_receiver.execute_flash_loan(...)`, and the malicious token transfer is recorded under the victim's authorization tree during simulation. [2](#0-1) [12](#0-11) 
4. If the victim signs that tree, the unrelated wallet tokens move to the attacker and the flash loan still settles normally. [8](#0-7)

### Citations

**File:** contracts/controller/src/external/pool.rs (L96-107)
```rust
pub(crate) fn pool_flash_loan_call(
    env: &Env,
    pool_addr: &Address,
    hub_asset: &HubAssetKey,
    initiator: &Address,
    receiver: &Address,
    amount: i128,
    data: &Bytes,
) -> i128 {
    LiquidityPoolClient::new(env, pool_addr)
        .flash_loan(hub_asset, initiator, receiver, &amount, data)
}
```

**File:** contracts/pool/src/ops/flash.rs (L150-167)
```rust
    env.invoke_contract::<()>(
        receiver,
        &Symbol::new(env, "execute_flash_loan"),
        (
            initiator,
            cache.params().asset_id.clone(),
            amount,
            fee,
            pool.clone(),
            data,
        )
            .into_val(env),
    );
}

/// Pulls principal + fee via `transfer_from` after verifying allowance.
fn collect_repayment(
    env: &Env,
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L1-3)
```rust
//! What the host does when code inside a route hop calls
//! `token.transfer(caller, third_party, x)` below the controller: recording mode
//! attaches it to the caller's entry; enforcing mode accepts it only if signed.
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L239-268)
```rust
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

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L271-280)
```rust
/// Controller stand-in: root-frame `caller.require_auth()`, then route-selected code.
#[contract]
pub struct RootAuthEntry;

#[contractimpl]
impl RootAuthEntry {
    pub fn run(env: Env, caller: Address, hop_pool: Address) {
        caller.require_auth();
        let _: Val = env.invoke_contract(&hop_pool, &symbol_short!("swap"), vec![&env]);
    }
```

**File:** mock/flash-loan-receiver/README.md (L13-15)
```markdown
`data` is XDR `FlashLoanRequest { mode }`; other bytes trap with `InvalidData`.
The receiver repays by `approve`. The pool pulls `amount + fee` with
`transfer_from` after the callback returns.
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
