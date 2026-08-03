No vulnerability found for this question.

**Analysis supporting this conclusion:**

The described path in `TrustedState::verify_and_ratchet_inner` is real code, but it does not constitute an admission-boundary exploit:

1. **`epoch_change_li` is always cryptographically verified before the branching logic runs.** `epoch_change_proof.verify(self)` on line 163 validates the full BLS-signed chain of epoch-change ledger infos against the current trusted validator set before `epoch_change_li` is ever used. [1](#0-0)  An unprivileged "StateProof responder" cannot forge a legitimate `epoch_change_li`; it can only supply one that already carries valid validator signatures, or the call fails.

2. **The `more == true` fallback branch is intentional, documented behavior, not a bypass.** When `latest_li`'s epoch exceeds `new_epoch` and `more` is true, the code deliberately falls back to the already-verified `epoch_change_li` instead of trusting the unverified `latest_li`. [2](#0-1)  This is exactly the scenario exercised by the existing test `test_ratchet_succeeds_with_more`, which asserts this is the *correct* outcome when there's a gap between the proof and the claimed latest ledger info, and separately asserts the `bail!` path triggers only when `more == false` with a gap. [3](#0-2)  There is no scenario where a falsely-set `more=true` flag causes acceptance of unverified or attacker-controlled data — the fallback value (`epoch_change_li`) is always the legitimately verified ledger info, so no "corruption" occurs; at worst the light client stays at a validated-but-older epoch state, matching the intended semantics of the "more proof needed" case.

3. **This file has no chain-id binding at all.** There is no `chain_id` field or logic anywhere in `trusted_state.rs`. [4](#0-3)  Chain-id used for transaction expiry checks belongs to the separate `ChainId`/transaction-prologue validation path in mempool/vm-validator, and is not read from or influenced by `TrustedState`/`EpochChangeProof`/`StateProof`. The premise that this code "corrupts chain-id binding" has no basis in the actual data flow.

4. **This is state-sync/light-client code, not the transaction admission stack.** `verify_and_ratchet_inner` is invoked from state-sync/full-node bootstrapping and light-client verification flows, not from mempool, vm-validator, or VM transaction validation. [5](#0-4)  There is no unprivileged-transaction entrypoint that routes through this code, so the finding falls outside the review's required boundary condition (must start from unprivileged transaction/authenticator/API/proof input and affect the admission stack).

Given the review's decision standard — that a valid finding must show unprivileged input causing a transaction to be wrongly admitted or rebound in a way that breaks sender/signer/replay/domain guarantees — this finding does not qualify: the code behaves as designed, uses only cryptographically verified data for its fallback, and has no connection to chain-id-based transaction expiry checks or transaction admission at all.

### Citations

**File:** types/src/trusted_state.rs (L1-20)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

#![allow(clippy::arc_with_non_send_sync)]

use crate::{
    epoch_change::{EpochChangeProof, Verifier},
    epoch_state::EpochState,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    proof::TransactionAccumulatorSummary,
    state_proof::StateProof,
    transaction::Version,
    waypoint::Waypoint,
};
use anyhow::{bail, ensure, format_err, Result};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

```

**File:** types/src/trusted_state.rs (L161-172)
```rust
        if self.epoch_change_verification_required(latest_li.ledger_info().next_block_epoch()) {
            // Verify the EpochChangeProof to move us into the latest epoch.
            let epoch_change_li = epoch_change_proof.verify(self)?;
            let new_epoch_state = epoch_change_li
                .ledger_info()
                .next_epoch_state()
                .cloned()
                .ok_or_else(|| {
                    format_err!(
                        "A valid EpochChangeProof will never return a non-epoch change ledger info"
                    )
                })?;
```

**File:** types/src/trusted_state.rs (L174-187)
```rust
            // If the latest ledger info is in the same epoch as the new verifier, verify it and
            // use it as latest state, otherwise fallback to the epoch change ledger info.
            let new_epoch = new_epoch_state.epoch;

            let verified_ledger_info = if epoch_change_li == latest_li {
                latest_li
            } else if latest_li.ledger_info().epoch() == new_epoch {
                new_epoch_state.verify(latest_li)?;
                latest_li
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
            };
```

**File:** types/src/unit_tests/trusted_state_test.rs (L386-399)
```rust

        // ratcheting with more = false should fail, since the state proof claims
        // we're done syncing epoch changes but doesn't get us all the way to the
        // latest ledger info
        let mut change_proof = EpochChangeProof::new(lis_with_sigs, false /* more */);
        trusted_state
            .verify_and_ratchet_inner(&latest_li, &change_proof)
            .expect_err("Should return Err when more is false and there's a gap");

        // ratcheting with more = true is fine
        change_proof.more = true;
        let trusted_state_change = trusted_state
            .verify_and_ratchet_inner(&latest_li, &change_proof)
            .expect("Should succeed with more in EpochChangeProof");
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L562-587)
```rust
    fn get_state_proof_with_ledger_info(
        &self,
        known_version: u64,
        ledger_info_with_sigs: LedgerInfoWithSignatures,
    ) -> Result<StateProof> {
        gauged_api("get_state_proof_with_ledger_info", || {
            let ledger_info = ledger_info_with_sigs.ledger_info();
            ensure!(
                known_version <= ledger_info.version(),
                "Client known_version {} larger than ledger version {}.",
                known_version,
                ledger_info.version(),
            );
            let known_epoch = self.ledger_db.metadata_db().get_epoch(known_version)?;
            let end_epoch = ledger_info.next_block_epoch();
            let epoch_change_proof = if known_epoch < end_epoch {
                let (ledger_infos_with_sigs, more) =
                    self.get_epoch_ending_ledger_infos(known_epoch, end_epoch)?;
                EpochChangeProof::new(ledger_infos_with_sigs, more)
            } else {
                EpochChangeProof::new(vec![], /* more = */ false)
            };

            Ok(StateProof::new(ledger_info_with_sigs, epoch_change_proof))
        })
    }
```
