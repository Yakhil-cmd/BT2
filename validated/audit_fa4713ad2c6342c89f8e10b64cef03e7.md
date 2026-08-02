No vulnerability found for this question.

**Reasoning:**

`block_prologue`, `block_prologue_ext`, and their variants are private, non-`entry` Move functions that take `vm: signer` by value and immediately call `system_addresses::assert_vm(vm)` inside the shared helper `block_prologue_common` [1](#0-0) . None of these functions are declared `public entry`, so they are not reachable via any user-submitted BCS/REST transaction, script, or entry-function call — they can only be invoked directly by the Rust block executor as part of the internally-constructed `BlockMetadata`/`BlockMetadataExt` system transaction, which fabricates the `@vm_reserved` signer natively; no unprivileged account can obtain or forge that signer [2](#0-1) [3](#0-2) .

Since the boundary conditions require the exploit path to start from unprivileged transaction/authenticator/API/proof input, and the decision standard explicitly rejects anything requiring a privileged signer, this scenario is out of scope regardless of whether `block_prologue_common`'s dedup logic is sound.

For completeness on the technical claim itself: even if both entry points were reachable by the VM, there is no persistent dedup keyed on `(hash, round)` — `height` is derived fresh each call from `event::counter(&block_metadata_ref.new_block_events)` before emission [4](#0-3) , and the assertion in `emit_new_block_event` merely checks that the event handle's counter matches the just-computed height at emission time, not that a given `(hash, round)` pair hasn't been seen before [5](#0-4) . So a second call would simply advance to the next height rather than being "rejected" — but this is irrelevant here since the entrypoint is unreachable by unprivileged callers, which is the disqualifying factor under the admission gate.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/block.move (L153-170)
```text
    fun block_prologue_common(
        vm: &signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ): u64 acquires BlockResource, CommitHistory {
        // Operational constraint: can only be invoked by the VM.
        system_addresses::assert_vm(vm);

        // Blocks can only be produced by a valid proposer or by the VM itself for Nil blocks (no user txs).
        assert!(
            proposer == @vm_reserved || stake::is_current_epoch_validator(proposer),
            error::permission_denied(EINVALID_PROPOSER)
        );
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L177-184)
```text
        let block_metadata_ref = borrow_global_mut<BlockResource>(@aptos_framework);
        block_metadata_ref.height = event::counter(&block_metadata_ref.new_block_events);

        let new_block_event = NewBlockEvent {
            hash,
            epoch,
            round,
            height: block_metadata_ref.height,
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L204-231)
```text
    fun block_prologue(
        vm: signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ) acquires BlockResource, CommitHistory {
        let epoch_interval =
            block_prologue_common(
                &vm,
                hash,
                epoch,
                round,
                proposer,
                failed_proposer_indices,
                previous_block_votes_bitvec,
                timestamp
            );
        randomness::on_new_block(&vm, epoch, round, option::none());
        decryption::on_new_block(&vm, epoch, round, option::none());

        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration::reconfigure();
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L234-263)
```text
    fun block_prologue_ext(
        vm: signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64,
        randomness_seed: Option<vector<u8>>
    ) acquires BlockResource, CommitHistory {
        let epoch_interval =
            block_prologue_common(
                &vm,
                hash,
                epoch,
                round,
                proposer,
                failed_proposer_indices,
                previous_block_votes_bitvec,
                timestamp
            );
        randomness::on_new_block(&vm, epoch, round, randomness_seed);
        decryption::on_new_block(&vm, epoch, round, option::none());

        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration_with_dkg::try_start();
            reconfiguration_with_dkg::try_advance_reconfig();
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L374-378)
```text
        assert!(
            event::counter(event_handle) == new_block_event.height,
            error::invalid_argument(ENUM_NEW_BLOCK_EVENTS_DOES_NOT_MATCH_BLOCK_HEIGHT)
        );
        event::emit_event<NewBlockEvent>(event_handle, new_block_event);
```
