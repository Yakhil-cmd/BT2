## Analysis

The exploit hypothesis is confirmed by the code: the upper-bound expiration check is **only wired into the nonce (orderless) replay-protection path**, not the sequence-number path.

In `check_for_replay_protection_orderless_txn`, the nonce-based flow explicitly bounds the expiration: [1](#0-0) 

But `check_for_replay_protection_regular_txn`, used for `ReplayProtector::SequenceNumber`, only validates sequence-number ordering/size — it never touches `txn_expiration_time`: [2](#0-1) 

The only expiration check applied unconditionally to *all* transactions (sequence-number or nonce) is the lower bound in `prologue_common`, which just requires the transaction isn't already expired — there is no upper cap: [3](#0-2) 

`MAX_EXP_TIME_SECONDS_FOR_ORDERLESS_TXNS` and `PROLOGUE_ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE` are declared once and consumed only inside the orderless-nonce branch: [4](#0-3) [5](#0-4) 

The replay-protector dispatch confirms the two paths are mutually exclusive and only one branch enforces the cap: [6](#0-5) 

On the mempool side, admission for sequence-number transactions is governed only by sequence-number ordering (not client-declared expiration), and the effective TTL for consensus/eviction purposes is derived from the node's own `system_transaction_timeout_secs` (default 600s) set at insertion time — not from the huge client-supplied `expiration_timestamp_secs`: [7](#0-6) [8](#0-7) 

This means mempool eviction (`system_transaction_timeout_secs`) is an operator-tunable, best-effort local policy — not a consensus-level or VM-level admission-control invariant. The VM prologue (the actual admission gate that determines whether a transaction *can ever be validly executed*) never rejects a sequence-number transaction merely because its declared expiration is implausibly far in the future.

### Title
Missing upper-bound expiration check for sequence-number transactions in `prologue_common` — ([File: aptos-move/framework/aptos-framework/sources/transaction_validation.move])

### Summary
`PROLOGUE_ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE` / `MAX_EXP_TIME_SECONDS_FOR_ORDERLESS_TXNS` is enforced only in `check_for_replay_protection_orderless_txn` (nonce-based replay protector). `check_for_replay_protection_regular_txn` (sequence-number replay protector) and the shared `prologue_common` never bound `txn_expiration_time` from above. An unprivileged sender can submit an ordinary sequence-number `RawTransaction` with `expiration_timestamp_secs` set arbitrarily far in the future (e.g., year 9999) and it will pass VM prologue validation as long as it isn't already expired.

### Finding Description
`prologue_common` only checks `timestamp::now_seconds() < txn_expiration_time` (lower bound / not-yet-expired) for every transaction, regardless of replay protector kind. The upper-bound sanity check that limits how far in the future an expiration can be set exists solely inside the nonce-based `check_for_replay_protection_orderless_txn` function, which is never invoked for `ReplayProtector::SequenceNumber` transactions. Consequently, sequence-number transactions have no VM-enforced upper limit on `expiration_timestamp_secs`.

### Impact Explanation
A validly signed sequence-number transaction with an extreme expiration remains admissible by the VM/vm-validator indefinitely (until its sequence number is consumed or superseded). The only thing preventing it from sitting in mempool forever is local, per-node mempool configuration (`system_transaction_timeout_secs`, default 600s) — an operational, best-effort GC policy, not a consensus-level admission-control invariant. This corrupts the intended expiry-binding guarantee of the transaction format: `expiration_timestamp_secs` is documented/expected to bound the validity window of a signed authorization, but for sequence-number txns that bound is effectively unenforced at the VM layer. This could allow a signed authorization to be held/replayed by relays or resubmitted to other mempools/nodes (with different or misconfigured `system_transaction_timeout_secs`) well beyond the sender's intended window, and removes a defense-in-depth check that the orderless path deliberately added.

### Likelihood Explanation
High likelihood of triggering: this requires no privileged access — any unprivileged client can construct a standard sequence-number transaction with a far-future `expiration_timestamp_secs`, sign it normally, and submit it via the standard REST/BCS submission path. No authenticator or signature trickery is needed.

### Recommendation
Move the upper-bound expiration check (`txn_expiration_time <= now + MAX_EXP_TIME` or an equivalent, possibly larger, constant appropriate for sequence-number txns) into `prologue_common` so it applies uniformly to both `ReplayProtector::SequenceNumber` and `ReplayProtector::Nonce` paths, or add an explicit symmetric check in `check_for_replay_protection_regular_txn`. Additionally, document/patch that mempool's `system_transaction_timeout_secs` is not a substitute for VM-level admission control, since it is a local/tunable eviction heuristic rather than a network-wide guarantee.

### Proof of Concept
1. Construct a normal `RawTransaction` for an existing account using `ReplayProtector::SequenceNumber(current_seq)`.
2. Set `expiration_timestamp_secs` to a very large value (e.g., `u64::MAX / 2` or year 9999), far beyond `MAX_EXP_TIME_SECONDS_FOR_ORDERLESS_TXNS` (100s).
3. Sign normally with the account's real key and submit via the standard transaction submission path.
4. Observe that `prologue_common`'s only expiration check (`aptos-move/framework/aptos-framework/sources/transaction_validation.move:134-137`) passes (current time < expiration), and `check_for_replay_protection_regular_txn` (`transaction_validation.move:207-242`) never inspects `txn_expiration_time` — so VM validation accepts the transaction.
5. Compare with an equivalent nonce-based orderless transaction with the same far-future expiration: it is rejected with `PROLOGUE_ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE` (`transaction_validation.move:244-255`), demonstrating the asymmetry.
6. Confirm that mempool admission for the sequence-number version only checks sequence-number ordering (`mempool/src/core_mempool/mempool.rs:360-381`) and relies solely on `system_transaction_timeout_secs` for eventual local eviction (`mempool/src/core_mempool/mempool.rs:383-396`, `config/src/config/mempool_config.rs:78-83`), which is a per-node configurable value, not an enforced protocol invariant.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L23-36)
```text
    // We will advertise to the community that max expiration time for orderless txns is 60 seconds.
    // Adding a 40 second slack here as the client's time and the blockchain's time may drift,
    // and to account for any fallen behind fullnodes that are performing simulation on old blockchain state.
    const MAX_EXP_TIME_SECONDS_FOR_ORDERLESS_TXNS: u64 = 100;

    // We need to ensure that a transaction can't be replayed.
    // There are two ways to prevent replay attacks:
    // 1. Use a nonce. Orderless transactions use this.
    // 2. Use a sequence number. Regular transactions use this.
    // A replay protector of a transaction signifies which of the above methods is used.
    enum ReplayProtector {
        Nonce(u64),
        SequenceNumber(u64),
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L61-75)
```text
    /// Prologue errors. These are separated out from the other errors in this
    /// module since they are mapped separately to major VM statuses, and are
    /// important to the semantics of the system.
    const PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY: u64 = 1001;
    const PROLOGUE_ESEQUENCE_NUMBER_TOO_OLD: u64 = 1002;
    const PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW: u64 = 1003;
    const PROLOGUE_EACCOUNT_DOES_NOT_EXIST: u64 = 1004;
    const PROLOGUE_ECANT_PAY_GAS_DEPOSIT: u64 = 1005;
    const PROLOGUE_ETRANSACTION_EXPIRED: u64 = 1006;
    const PROLOGUE_EBAD_CHAIN_ID: u64 = 1007;
    const PROLOGUE_ESEQUENCE_NUMBER_TOO_BIG: u64 = 1008;
    const PROLOGUE_ESECONDARY_KEYS_ADDRESSES_COUNT_MISMATCH: u64 = 1009;
    const PROLOGUE_EFEE_PAYER_NOT_ENABLED: u64 = 1010;
    const PROLOGUE_ENONCE_ALREADY_USED: u64 = 1012;
    const PROLOGUE_ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE: u64 = 1013;
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L132-138)
```text
        let sender_address = signer::address_of(sender);
        let gas_payer_address = signer::address_of(gas_payer);
        assert!(
            timestamp::now_seconds() < txn_expiration_time,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRED),
        );
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L169-185)
```text
        // Check for replay protection
        match (replay_protector) {
            SequenceNumber(txn_sequence_number) => {
                check_for_replay_protection_regular_txn(
                    sender_address,
                    gas_payer_address,
                    txn_sequence_number,
                );
            },
            Nonce(nonce) => {
                check_for_replay_protection_orderless_txn(
                    sender_address,
                    nonce,
                    txn_expiration_time,
                );
            }
        };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L207-242)
```text
    fun check_for_replay_protection_regular_txn(
        sender_address: address,
        gas_payer_address: address,
        txn_sequence_number: u64,
    ) {
        if (
            sender_address == gas_payer_address
                || account::exists_at(sender_address)
                || !features::sponsored_automatic_account_creation_enabled()
                || txn_sequence_number > 0
        ) {
            assert!(account::exists_at(sender_address), error::invalid_argument(PROLOGUE_EACCOUNT_DOES_NOT_EXIST));
            let account_sequence_number = account::get_sequence_number(sender_address);
            assert!(
                txn_sequence_number < (1u64 << 63),
                error::out_of_range(PROLOGUE_ESEQUENCE_NUMBER_TOO_BIG)
            );

            assert!(
                txn_sequence_number >= account_sequence_number,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_OLD)
            );

            assert!(
                txn_sequence_number == account_sequence_number,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW)
            );
        } else {
            // In this case, the transaction is sponsored and the account does not exist, so ensure
            // the default values match.
            assert!(
                txn_sequence_number == 0,
                error::invalid_argument(PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW)
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L244-255)
```text
    fun check_for_replay_protection_orderless_txn(
        sender: address,
        nonce: u64,
        txn_expiration_time: u64,
    ) {
        // prologue_common already checks that the current_time > txn_expiration_time
        assert!(
            txn_expiration_time <= timestamp::now_seconds() + MAX_EXP_TIME_SECONDS_FOR_ORDERLESS_TXNS,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE),
        );
        assert!(nonce_validation::check_and_insert_nonce(sender, nonce, txn_expiration_time), error::invalid_argument(PROLOGUE_ENONCE_ALREADY_USED));
    }
```

**File:** mempool/src/core_mempool/mempool.rs (L360-396)
```rust
        if let ReplayProtector::SequenceNumber(txn_seq_num) = txn.replay_protector() {
            // don't accept old transactions (e.g. seq is less than account's current seq_number)
            match &account_sequence_number {
                Some(account_sequence_number) => {
                    if txn_seq_num < *account_sequence_number {
                        return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber)
                            .with_message(format!(
                                "transaction sequence number is {}, current sequence number is  {}",
                                txn_seq_num, account_sequence_number,
                            ));
                    }
                },
                None => {
                    return MempoolStatus::new(MempoolStatusCode::InvalidSeqNumber).with_message(
                        format!(
                            "transaction has sequence number {}, but not sequence number provided for sender's account",
                            txn_seq_num,
                        ),
                    );
                },
            }
        };

        let now = SystemTime::now();
        let expiration_time =
            aptos_infallible::duration_since_epoch_at(&now) + self.system_transaction_timeout;

        let sender = txn.sender();
        let txn_info = MempoolTransaction::new(
            txn.clone(),
            expiration_time,
            ranking_score,
            timeline_state,
            now,
            client_submitted,
            priority.clone(),
        );
```

**File:** config/src/config/mempool_config.rs (L78-83)
```rust
    /// Number of seconds until the transaction will be removed from the Mempool ignoring if the transaction has expired.
    ///
    /// This ensures that the Mempool isn't just full of non-expiring transactions that are way off into the future.
    pub system_transaction_timeout_secs: u64,
    /// Interval to garbage collect and remove transactions that have expired from the Mempool.
    pub system_transaction_gc_interval_ms: u64,
```
