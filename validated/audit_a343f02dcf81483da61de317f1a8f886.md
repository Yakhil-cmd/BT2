### Title
Attacker-controlled flash receiver can abuse the caller authorization tree to steal wallet funds - ([File: contracts/controller/src/strategies/flash_loan.rs](contracts/controller/src/strategies/flash_loan.rs))

### Summary
`flash_loan` accepts an arbitrary deployed Wasm `receiver` supplied by the caller and causes the pool to invoke its `execute_flash_loan` callback. Because the original `caller` has already authorized the enclosing controller call, a malicious receiver can place an unauthorized-looking token transfer from that caller into the transaction’s authorization tree. If the caller signs the simulated tree without inspecting every nested invocation, the receiver can transfer unrelated wallet tokens to an attacker-controlled address while still repaying the flash loan correctly. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The controller requires authorization only from `caller` and validates only that `receiver` is a Wasm contract; it does not restrict the receiver to an allowlist. [4](#0-3) 

It then calls the pool through `pool_flash_loan_call`, passing both the initiator and caller-selected receiver unchanged. [5](#0-4) 

The pool transfers principal to that receiver and invokes `execute_flash_loan` with the initiator, asset, amount, fee, pool, and attacker-controlled `data`. [6](#0-5) [7](#0-6) 

The post-callback checks only verify that the pool balance remains unchanged during the callback and that the receiver repays principal plus fee. They do not limit what other contract invocations the receiver performs during its callback. [8](#0-7) [9](#0-8) 

A malicious receiver can therefore invoke a separate token’s `transfer(victim, attacker, amount)` during the callback. In Soroban’s invoker-authorization model, that token call can be represented as a nested invocation under the victim’s authorization for the outer `flash_loan` call. A wallet or simulation flow that presents only the outer flash-loan request—or a user who does not audit the full auth tree—can cause the victim to sign both the intended flash-loan call and the nested token theft.

### Impact Explanation
The malicious callback can steal tokens held by the caller that are unrelated to the borrowed asset, the loan amount, or the flash-loan fee. The attacker can make the receiver repay the pool correctly, so the transaction succeeds while also transferring victim wallet funds to the attacker. [3](#0-2) [9](#0-8) 

This is direct theft of user funds rather than limited to manipulated swap output or an insolvent protocol position.

### Likelihood Explanation
An unprivileged caller can reach the affected path through the public controller entrypoint:

```text
flash_loan(
    caller = victim,
    asset = flashloanable HubAssetKey,
    amount = principal,
    receiver = attacker_contract,
    data = attacker_payload
)
```

The entrypoint is permissionless apart from `caller` authorization, and both controller and pool accept any deployed Wasm receiver rather than a protocol-approved receiver. [1](#0-0) [2](#0-1) [10](#0-9) 

Exploitation requires the victim to authorize the transaction containing the malicious nested invocation. That is plausible when a UI or counterparty supplies the receiver and transaction payload and the wallet does not clearly require the user to inspect every nested authorization. Severity is therefore High rather than Critical.

### Recommendation
Treat caller-selected callback contracts as untrusted external endpoints and prevent unrelated operations from joining the caller’s authorization tree.

Recommended mitigations:

1. Prefer receiver architectures where the caller is a contract that explicitly authorizes only its intended operations, rather than an end-user wallet.
2. Require clients to simulate and display the complete authorization tree before signing `flash_loan`.
3. Reject transactions whose caller authorization tree contains token `transfer`, `transfer_from`, or `approve` calls not strictly required for the intended flash-loan repayment path.
4. Document that `receiver` and `data` must never be supplied blindly by an untrusted party.
5. If compatible with the intended product flow, add a governance-controlled receiver allowlist or require receivers to be registered and reviewed before use.
6. Consider replacing the arbitrary callback model with a pull-based pattern in which the borrower contract initiates the loan itself and exposes only a narrowly scoped operation.

### Proof of Concept
Deploy a malicious Wasm receiver:

```rust
// Malicious receiver (illustrative Soroban contract)
pub fn execute_flash_loan(
    env: Env,
    initiator: Address,
    asset: Address,
    amount: i128,
    fee: i128,
    pool: Address,
    _data: Bytes,
) {
    // Theft: initiator is the victim/caller passed through by the pool.
    let stolen_token: Address = env.storage().instance().get(&symbol_short!("TOK")).unwrap();
    let attacker: Address = env.storage().instance().get(&symbol_short!("ATK")).unwrap();
    let steal_amount: i128 = env.storage().instance().get(&symbol_short!("AMT")).unwrap();

    token::Client::new(&env, &stolen_token)
        .transfer(&initiator, &attacker, &steal_amount);

    // Preserve protocol settlement so the enclosing call succeeds.
    token::Client::new(&env, &asset).approve(
        &env.current_contract_address(),
        &pool,
        &(amount + fee),
        &env.ledger().sequence().saturating_add(1),
    );
}
```

Then induce the victim to authorize:

```text
Controller.flash_loan(
    caller = victim_address,
    asset = { hub_id: H, asset: FLASHLOANABLE_TOKEN },
    amount = 1_000_000,
    receiver = malicious_receiver_contract,
    data = arbitrary_bytes
)
```

The controller authenticates `victim_address`, accepts the supplied Wasm receiver, and invokes the pool. The pool transfers principal to the malicious contract and calls `execute_flash_loan`. During that callback, the contract attempts `stolen_token.transfer(victim_address, attacker, steal_amount)`. If the victim signs the generated authorization tree, the steal executes as a child authorization while the receiver’s normal approval lets the pool recover `amount + fee`, leaving all protocol settlement checks successful. [11](#0-10) [3](#0-2) [9](#0-8)

### Citations

**File:** contracts/controller/src/lib.rs (L167-179)
```rust
    /// Flash-loans `amount` of `asset` to a deployed Wasm `receiver`, invoking
    /// its callback with `data`. The pool recovers principal plus fee before return.
    /// Permissionless; requires caller authorization.
    #[when_not_paused]
    fn flash_loan(
        env: Env,
        caller: Address,
        asset: HubAssetKey,
        amount: i128,
        receiver: Address,
        data: Bytes,
    ) {
        strategies::flash_loan::process_flash_loan(&env, &caller, &asset, amount, &receiver, &data);
```

**File:** contracts/controller/src/strategies/flash_loan.rs (L22-33)
```rust
    require_authorized_caller(env, caller);
    require_positive_amount(env, amount);
    config::require_hub_active(env, hub_asset.hub_id);

    require_wasm_receiver(env, receiver);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();

    let fee = storage::with_flash_guard(env, || {
        pool_flash_loan_call(env, &pool_addr, hub_asset, caller, receiver, amount, data)
    });
```

**File:** contracts/pool/src/ops/flash.rs (L48-50)
```rust
    let mut cache = prepare(env, hub_asset, amount);
    require_wasm_receiver(env, &receiver);

```

**File:** contracts/pool/src/ops/flash.rs (L60-68)
```rust
    asset.transfer(&pool, &receiver, &amount);
    require_balance(env, &asset, &pool, terms.balance_after_payout);
    invoke_receiver(
        env, &cache, &receiver, initiator, amount, terms.fee, &pool, data,
    );

    require_balance(env, &asset, &pool, terms.balance_after_payout);
    collect_repayment(env, &asset, &pool, &receiver, &terms);

```

**File:** contracts/pool/src/ops/flash.rs (L140-162)
```rust
fn invoke_receiver(
    env: &Env,
    cache: &Cache,
    receiver: &Address,
    initiator: Address,
    amount: i128,
    fee: i128,
    pool: &Address,
    data: Bytes,
) {
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
```

**File:** contracts/pool/src/ops/flash.rs (L173-179)
```rust
    assert_with_error!(
        env,
        asset.allowance(receiver, pool) >= terms.total_repayment,
        FlashLoanError::InvalidFlashloanRepay
    );
    asset.transfer_from(pool, receiver, pool, &terms.total_repayment);
    require_balance(env, asset, pool, terms.balance_after_repayment);
```
