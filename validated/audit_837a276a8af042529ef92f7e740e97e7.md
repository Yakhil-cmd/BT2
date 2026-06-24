Audit Report

## Title
Unbounded Permanent Allowance Storage Bloat via `icrc2_approve` with No Expiry - (`rs/ledger_suite/common/ledger_core/src/approvals.rs`)

## Summary
The `AllowanceTable::approve()` function inserts a new allowance entry for every unique `(from, spender)` pair with no per-account or global cap. When `expires_at` is `None`, no entry is added to the expiration queue, so `prune()` — which iterates only the expiration queue — never reclaims these entries. Both the ICP and ICRC-1 ledgers back allowances with a `StableBTreeMap` in stable memory, meaning every inserted permanent allowance permanently consumes stable storage and drains the canister's cycle reserves.

## Finding Description
In `rs/ledger_suite/common/ledger_core/src/approvals.rs`, `AllowanceTable::approve()` inserts a new allowance unconditionally for any new `(account, spender)` key:

```rust
if let Some(expires_at) = expires_at {
    table.allowances_data.insert_expiry(expires_at, key.clone());
}
table.allowances_data.set_allowance(key, Allowance { amount, expires_at, arrived_at: now });
```

When `expires_at` is `None`, the `insert_expiry` branch is skipped entirely — no entry is added to the expiration queue. [1](#0-0) 

`prune()` iterates exclusively over `first_expiry()` / `pop_first_expiry()`, which only touch the expiration queue. Permanent allowances have no entry there and are never visited: [2](#0-1) 

`prune()` is called on every transaction via `apply_transaction` with a fixed `APPROVE_PRUNE_LIMIT`, but this only ever processes the expiration queue: [3](#0-2) 

No per-account or global allowance count limit exists anywhere in the call path. A search for `max_allowances`, `allowance.*limit`, `allowance.*cap`, and `MAX_ALLOWANCE` returns zero matches across the entire codebase.

Both the ICP ledger and the ICRC-1 ledger back allowances with a `StableBTreeMap` in stable memory: [4](#0-3) [5](#0-4) 

The `icrc2_approve` endpoint is publicly callable with no rate limiting beyond the transfer fee: [6](#0-5) [7](#0-6) 

The `check_postconditions` invariant explicitly permits more allowances than expirations, confirming the design allows permanent allowances to accumulate without bound: [8](#0-7) 

The only removal paths for a permanent allowance are: (a) the approver explicitly sets `amount = 0`, or (b) `use_allowance` drains it to zero. An attacker has no incentive to trigger either.

## Impact Explanation
This is a High severity finding matching: **"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS"** and **"Significant Chain Fusion, ck-token, ledger, Rosetta, boundary/API, XRC, Internet Identity, NNS, SNS, or infrastructure security impact with concrete user or protocol harm."**

As the allowance table grows without bound in stable memory:
- The ledger canister's cycle reserves are continuously drained by storage costs.
- Upgrade serialization/deserialization time grows, risking upgrade failures for NNS-controlled canisters (ICP ledger, ckBTC, ckETH, ckERC20 ledgers).
- All ledger operations touching the allowance table degrade in performance.
- In the extreme case, the ledger canister becomes unresponsive or unable to upgrade, directly impacting all users of the ICP ledger and chain-key token ledgers.

## Likelihood Explanation
The attack is reachable by any unprivileged ingress sender holding a token balance. For the ICP ledger, the transfer fee is 10,000 e8s ≈ $0.001 per allowance. Creating 1 million permanent allowances costs ~$1,000 USD. For ICRC-1 tokens with lower configured fees (e.g., ckBTC, ckETH), the cost per entry is proportionally lower. The attacker needs only to control a single principal and call `icrc2_approve` with N distinct spender accounts (e.g., different subaccounts of a controlled principal). The attack is repeatable, requires no special privileges, and imposes asymmetric cost: the attacker pays one transfer fee per entry while the canister pays ongoing stable storage costs in cycles.

## Recommendation
1. **Enforce a maximum allowance count per approver account** (e.g., 1,000 entries). In `AllowanceTable::approve()`, before inserting a new allowance for a key that does not yet exist, count existing allowances for the `account` and reject with `GenericError` if the limit is exceeded.
2. **Alternatively, require `expires_at` to be set** for all new allowances, ensuring every entry has an expiration queue entry and `prune()` can reclaim it.
3. **Alternatively, charge a refundable storage deposit** per allowance entry (returned on revocation or expiry), making the attacker bear the full storage cost.

## Proof of Concept
```
1. Attacker controls principal P with balance = N * transfer_fee tokens.
2. For i in 1..=N:
     icrc2_approve({
       from_subaccount: None,
       spender: { owner: attacker_controlled_principal_i, subaccount: None },
       amount: 1,
       expires_at: None,   // permanent — never pruned
       fee: transfer_fee,
       ...
     })
3. Each call succeeds; AllowanceTable inserts (P, spender_i) → Allowance{amount:1, expires_at:None}
   into ALLOWANCES_MEMORY (StableBTreeMap). No expiry queue entry is created.
4. prune() is called on every subsequent transaction but only iterates expiration_queue,
   which has zero entries for these allowances. Nothing is ever removed.
5. After N calls, the ledger's stable storage holds N permanent allowance entries.
   Cycle reserves are drained; all ledger operations degrade.

Reproducible test: PocketIC integration test calling icrc2_approve N times with
expires_at: None and distinct spenders, then asserting ledger.approvals().len() == N
and that prune(now, usize::MAX) returns 0.
```

### Citations

**File:** rs/ledger_suite/common/ledger_core/src/approvals.rs (L199-206)
```rust
    fn check_postconditions(&self) {
        debug_assert!(
            self.allowances_data.len_expirations() <= self.allowances_data.len_allowances(),
            "expiration queue length ({}) larger than allowances length ({})",
            self.allowances_data.len_expirations(),
            self.allowances_data.len_allowances()
        );
    }
```

**File:** rs/ledger_suite/common/ledger_core/src/approvals.rs (L265-275)
```rust
                    if let Some(expires_at) = expires_at {
                        table.allowances_data.insert_expiry(expires_at, key.clone());
                    }
                    table.allowances_data.set_allowance(
                        key,
                        Allowance {
                            amount: amount.clone(),
                            expires_at,
                            arrived_at: now,
                        },
                    );
```

**File:** rs/ledger_suite/common/ledger_core/src/approvals.rs (L372-399)
```rust
    /// Prunes allowances that are expired, removes at most `limit` allowances.
    pub fn prune(&mut self, now: TimeStamp, limit: usize) -> usize {
        self.with_postconditions_check(|table| {
            let mut pruned = 0;
            for _ in 0..limit {
                match table.allowances_data.first_expiry() {
                    Some((ts, _key)) => {
                        if ts > now {
                            return pruned;
                        }
                    }
                    None => {
                        return pruned;
                    }
                }
                if let Some((_, (account, spender))) = table.allowances_data.pop_first_expiry() {
                    let key = (account, spender);
                    if let Some(allowance) = table.allowances_data.get_allowance(&key)
                        && allowance.expires_at.unwrap_or_else(remote_future) <= now
                    {
                        table.allowances_data.remove_allowance(&key);
                        pruned += 1;
                    }
                }
            }
            pruned
        })
    }
```

**File:** rs/ledger_suite/common/ledger_canister_core/src/ledger.rs (L231-231)
```rust
    ledger.approvals_mut().prune(now, APPROVE_PRUNE_LIMIT);
```

**File:** rs/ledger_suite/icp/ledger/src/lib.rs (L136-137)
```rust
    pub static ALLOWANCES_MEMORY: RefCell<StableBTreeMap<(AccountIdentifier, AccountIdentifier), StorableAllowance, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(ALLOWANCES_MEMORY_ID))));
```

**File:** rs/ledger_suite/icrc1/ledger/src/lib.rs (L526-527)
```rust
    pub static ALLOWANCES_MEMORY: RefCell<StableBTreeMap<AccountSpender, StorableAllowance, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(ALLOWANCES_MEMORY_ID))));
```

**File:** rs/ledger_suite/icrc1/ledger/src/main.rs (L893-903)
```rust
#[update]
async fn icrc2_approve(arg: ApproveArgs) -> Result<Nat, ApproveError> {
    let block_idx = icrc2_approve_not_async(ic_cdk::api::msg_caller(), arg)?;

    // NB. we need to set the certified data before the first async call to make sure that the
    // blockchain state agrees with the certificate while archiving is in progress.
    ic_cdk::api::certified_data_set(Access::with_ledger(Ledger::root_hash));

    archive_blocks::<Access>(&LOG, MAX_MESSAGE_SIZE).await;
    Ok(Nat::from(block_idx))
}
```

**File:** rs/ledger_suite/icp/ledger/src/main.rs (L1418-1425)
```rust
#[update]
async fn icrc2_approve(arg: ApproveArgs) -> Result<Nat, ApproveError> {
    let block_index = icrc2_approve_not_async(caller(), arg, None)?;

    let max_msg_size = *MAX_MESSAGE_SIZE_BYTES.read().unwrap();
    archive_blocks::<Access>(DebugOutSink, max_msg_size as u64).await;
    Ok(block_index)
}
```
