Audit Report

## Title
Global Withdrawal Queue Saturation Enables Sustained DoS on All ckETH/ckERC20 Withdrawals - (File: `rs/ethereum/cketh/minter/src/guard/mod.rs`)

## Summary

The ckETH minter enforces a single global cap of `MAX_PENDING = 100` on pending withdrawal requests with no per-principal sub-limit. An attacker controlling 100 distinct IC principals can fill this queue entirely, causing every subsequent `withdraw_eth` or `withdraw_erc20` call from any user to `ic_cdk::trap` (hard `CANISTER_ERROR` rejection) until the attacker's Ethereum transactions confirm. Because the attacker's ckETH is burned and ETH is recovered after each cycle, the attack can be repeated indefinitely at the cost of Ethereum gas fees alone, constituting a sustained DoS on all ckETH and ckERC20 withdrawals.

## Finding Description

**Root cause — `rs/ethereum/cketh/minter/src/guard/mod.rs`**

`MAX_PENDING` is set to 100 and the guard checks a single global counter with no per-principal breakdown:

```rust
pub const MAX_CONCURRENT: usize = 100;
pub const MAX_PENDING: usize = 100;
``` [1](#0-0) 

`pending_requests_count` delegates to `withdrawal_requests_len()`, which returns the length of the global `pending_withdrawal_requests` VecDeque regardless of who submitted each entry:

```rust
impl RequestsGuardedByPrincipal for PendingWithdrawalRequests {
    fn pending_requests_count(state: &State) -> usize {
        state.eth_transactions.withdrawal_requests_len()
    }
}
``` [2](#0-1) 

The guard gate is a single global check:

```rust
fn new(principal: Principal) -> Result<Self, GuardError> {
    mutate_state(|s| {
        if PR::pending_requests_count(s) >= MAX_PENDING {
            return Err(GuardError::TooManyPendingRequests);
        }
``` [3](#0-2) 

The `AlreadyProcessing` check at line 56 only prevents the same principal from having two *concurrent in-flight calls*; it does not prevent a principal from submitting multiple sequential requests, nor does it prevent 100 distinct principals from each submitting one request to fill the queue. [4](#0-3) 

The `Drop` implementation removes the principal from `pending_withdrawal_principals` when the async call returns, so after a successful withdrawal the same principal can immediately re-submit. [5](#0-4) 

`withdrawal_requests_len()` confirms the global count: [6](#0-5) 

`pending_withdrawal_requests` is a single `VecDeque<WithdrawalRequest>` holding both `CkEth` and `CkErc20` variants, so flooding with one token type blocks the other: [7](#0-6) 

**Hard trap on guard failure — `rs/ethereum/cketh/minter/src/main.rs`**

Both public withdrawal endpoints call `ic_cdk::trap` (not `return Err(...)`) when the guard is denied: [8](#0-7) [9](#0-8) 

The burn happens *after* the guard is acquired, so a trapped call does not burn any tokens — user funds are safe, but the withdrawal is completely blocked. [10](#0-9) 

**Slow queue drain — `rs/ethereum/cketh/minter/src/withdraw.rs`**

The minter processes only `WITHDRAWAL_REQUESTS_BATCH_SIZE = 5` requests per timer tick. Once a request moves from `pending_withdrawal_requests` to `created_tx` it is no longer counted by `withdrawal_requests_len()`, but the attacker can immediately re-submit to refill the freed slots: [11](#0-10) [12](#0-11) 

## Impact Explanation

This is a **High** severity finding matching the allowed ICP bounty impact: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS"* and *"Significant Chain Fusion, ck-token, ledger, Rosetta, boundary/API, XRC, Internet Identity, NNS, SNS, or infrastructure security impact with concrete user or protocol harm."*

All ckETH and ckERC20 withdrawals are completely blocked for the duration of each attack cycle. Legitimate users receive hard `CANISTER_ERROR` rejections on every withdrawal attempt. The ckETH minter is a production financial integration canister; blocking withdrawals prevents users from exiting their ckETH/ckERC20 positions to Ethereum, causing concrete and measurable harm to protocol users.

## Likelihood Explanation

- **No privileged access required.** Any unprivileged IC user can generate 100 distinct key pairs trivially.
- **Capital requirement is modest and fully recovered.** 100 × minimum withdrawal amount (≈ 0.03 ETH each) ≈ 3 ETH (~$10,000), fully returned after Ethereum confirmation.
- **Repeatable indefinitely.** As the minter drains 5 requests per timer tick, the attacker re-submits to keep the queue saturated. The only sustained cost is Ethereum gas fees per cycle.
- **`MAX_CONCURRENT = 100` enables the attack.** The concurrent-call limit is exactly equal to `MAX_PENDING`, so 100 distinct principals can fill the queue in a single round of concurrent calls.

## Recommendation

1. **Add a per-principal pending-request cap** inside `Guard::new`: count how many entries in `pending_withdrawal_requests` belong to the calling principal and reject if it exceeds a small limit (e.g., 3).
2. **Return a graceful error instead of trapping** when `TooManyPendingRequests` is hit, so callers receive a retryable `TemporarilyUnavailable` response rather than a hard `CANISTER_ERROR`.
3. **Raise `MAX_PENDING`** to a value that makes queue saturation economically prohibitive, or tie it to a per-principal sub-quota.
4. **Separate the ckETH and ckERC20 pending counters** so that flooding one token type cannot block the other.

## Proof of Concept

1. Generate 100 IC key pairs → 100 distinct principals `P_1 … P_100`.
2. Fund each principal with ≥ `cketh_minimum_withdrawal_amount` ckETH (≈ 0.03 ETH each) via the ckETH ledger.
3. Concurrently call `withdraw_eth` from each principal with the minimum amount to a valid Ethereum address.
   - IC processes these sequentially within a round; each call passes the `MAX_PENDING` check (queue starts at 0) and the `AlreadyProcessing` check (each principal is unique), burns ckETH, and enqueues the request.
   - After all 100 calls complete, `withdrawal_requests_len() == 100`.
4. Any subsequent `withdraw_eth` or `withdraw_erc20` call from any principal now hits `pending_requests_count(s) >= MAX_PENDING` and `ic_cdk::trap`s with `CANISTER_ERROR`.
5. Wait for the minter to process the batch (5 per tick) and Ethereum to confirm (~12 minutes). Repeat from step 3.

A deterministic integration test using PocketIC can verify this by: initializing the minter, minting ckETH to 100 test principals, submitting 100 concurrent `withdraw_eth` calls, then asserting that the 101st call returns `CANISTER_ERROR` with `TooManyPendingRequests`.

### Citations

**File:** rs/ethereum/cketh/minter/src/guard/mod.rs (L9-10)
```rust
pub const MAX_CONCURRENT: usize = 100;
pub const MAX_PENDING: usize = 100;
```

**File:** rs/ethereum/cketh/minter/src/guard/mod.rs (L27-35)
```rust
impl RequestsGuardedByPrincipal for PendingWithdrawalRequests {
    fn guarded_principals(state: &mut State) -> &mut BTreeSet<Principal> {
        &mut state.pending_withdrawal_principals
    }

    fn pending_requests_count(state: &State) -> usize {
        state.eth_transactions.withdrawal_requests_len()
    }
}
```

**File:** rs/ethereum/cketh/minter/src/guard/mod.rs (L50-54)
```rust
    fn new(principal: Principal) -> Result<Self, GuardError> {
        mutate_state(|s| {
            if PR::pending_requests_count(s) >= MAX_PENDING {
                return Err(GuardError::TooManyPendingRequests);
            }
```

**File:** rs/ethereum/cketh/minter/src/guard/mod.rs (L55-68)
```rust
            let principals = PR::guarded_principals(s);
            if principals.contains(&principal) {
                return Err(GuardError::AlreadyProcessing);
            }
            if principals.len() >= MAX_CONCURRENT {
                return Err(GuardError::TooManyConcurrentRequests);
            }
            principals.insert(principal);
            Ok(Self {
                principal,
                _marker: PhantomData,
            })
        })
    }
```

**File:** rs/ethereum/cketh/minter/src/guard/mod.rs (L71-75)
```rust
impl<PR: RequestsGuardedByPrincipal> Drop for Guard<PR> {
    fn drop(&mut self) {
        mutate_state(|s| PR::guarded_principals(s).remove(&self.principal));
    }
}
```

**File:** rs/ethereum/cketh/minter/src/state/transactions/mod.rs (L35-39)
```rust
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum WithdrawalRequest {
    CkEth(EthWithdrawalRequest),
    CkErc20(Erc20WithdrawalRequest),
}
```

**File:** rs/ethereum/cketh/minter/src/state/transactions/mod.rs (L929-931)
```rust
    pub fn withdrawal_requests_len(&self) -> usize {
        self.pending_withdrawal_requests.len()
    }
```

**File:** rs/ethereum/cketh/minter/src/main.rs (L273-278)
```rust
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_withdraw_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(format!(
            "Failed retrieving guard for principal {caller}: {e:?}"
        ))
    });
```

**File:** rs/ethereum/cketh/minter/src/main.rs (L298-313)
```rust
    let client = read_state(LedgerClient::cketh_ledger_from_state);
    let now = ic_cdk::api::time();
    log!(INFO, "[withdraw]: burning {:?}", amount);
    match client
        .burn_from(
            Account {
                owner: caller,
                subaccount: from_subaccount,
            },
            amount,
            BurnMemo::Convert {
                to_address: destination,
            },
        )
        .await
    {
```

**File:** rs/ethereum/cketh/minter/src/main.rs (L400-405)
```rust
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_withdraw_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(format!(
            "Failed retrieving guard for principal {caller}: {e:?}"
        ))
    });
```

**File:** rs/ethereum/cketh/minter/src/withdraw.rs (L39-41)
```rust
const WITHDRAWAL_REQUESTS_BATCH_SIZE: usize = 5;
const TRANSACTIONS_TO_SIGN_BATCH_SIZE: usize = 5;
const TRANSACTIONS_TO_SEND_BATCH_SIZE: usize = 5;
```

**File:** rs/ethereum/cketh/minter/src/withdraw.rs (L249-253)
```rust
fn create_transactions_batch(gas_fee_estimate: GasFeeEstimate) {
    for request in read_state(|s| {
        s.eth_transactions
            .withdrawal_requests_batch(WITHDRAWAL_REQUESTS_BATCH_SIZE)
    }) {
```
