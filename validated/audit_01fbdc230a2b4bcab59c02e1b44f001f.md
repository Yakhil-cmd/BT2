[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** crates/sui-core/src/randomness_round_receiver.rs (L202-223)
```rust
        let sig: RandomnessSignature = match bcs::from_bytes(&msg.signature_bytes) {
            Ok(sig) => sig,
            Err(e) => {
                warn!(
                    "RandomnessRoundReceiver: failed to deserialize signature \
                     for epoch {} round {}: {e}",
                    msg.epoch, msg.round
                );
                return;
            }
        };

        if let Err(e) =
            ThresholdBls12381MinSig::verify(&vss_pk, &msg.round.signature_message(), &sig)
        {
            warn!(
                "RandomnessRoundReceiver: invalid auxiliary signature \
                 for epoch {} round {}: {e}",
                msg.epoch, msg.round
            );
            return;
        }
```

**File:** crates/sui-core/src/randomness_round_receiver.rs (L250-257)
```rust
        let epoch_store = self.authority_state.load_epoch_store_one_call_per_task();
        if epoch_store.epoch() != epoch {
            warn!(
                "dropping randomness for epoch {epoch}, round {round}, because we are in epoch {}",
                epoch_store.epoch()
            );
            return;
        }
```

**File:** crates/sui-core/src/randomness_round_receiver.rs (L274-302)
```rust
        let key = TransactionKey::RandomnessRound(epoch, round);
        let transaction = VerifiedTransaction::new_randomness_state_update(
            epoch,
            round,
            bytes,
            epoch_store
                .epoch_start_config()
                .randomness_obj_initial_shared_version()
                .expect("randomness state obj must exist"),
        );
        debug!(
            "created randomness state update transaction with digest: {:?}",
            transaction.digest()
        );
        let transaction = VerifiedExecutableTransaction::new_system(transaction, epoch);
        let digest = *transaction.digest();

        // Randomness state updates contain the full bls signature for the random round,
        // which cannot necessarily be reconstructed again later. Therefore we must immediately
        // persist this transaction. If we crash before its outputs are committed, this
        // ensures we will be able to re-execute it.
        self.authority_state
            .get_cache_commit()
            .persist_transaction(&transaction);

        // Notify the scheduler that the transaction key now has a known digest
        if epoch_store.insert_tx_key(key, digest).is_err() {
            warn!("epoch ended while handling new randomness");
        }
```

**File:** crates/sui-types/src/executable_transaction.rs (L42-44)
```rust
    pub fn new_system(epoch: EpochId) -> Self {
        Self::SystemTransaction(epoch)
    }
```
