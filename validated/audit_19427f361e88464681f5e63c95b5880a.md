No vulnerability found for this question.

**Analysis:**

The premise doesn't hold. `DKGTrait::new_public_params` (and its implementations in `RealDKG`/`DummyDKG`) is never fed attacker-controlled `DKGSessionMetadata`. In the only production call site relevant to consensus/on-chain verification, `AptosVM::process_dkg_result_inner` fetches the metadata directly from the authoritative on-chain `DKGState` resource via `OnChainConfig::fetch_config(resolver)`, then calls `DefaultDKG::new_public_params(&in_progress_session_state.metadata)` — there is no code path where an unprivileged caller supplies or mutates `randomness_config` inside that struct before it reaches `new_public_params`. [1](#0-0) 

The only attacker-influenced input on this path is `dkg_transcript` (the `DKGTranscript` containing `transcript_bytes`), which is a validator-produced artifact submitted as a `ValidatorTransaction`, not a user/API transaction, and it is checked against the epoch fetched from `ConfigurationResource` before verification. [2](#0-1) 

`DKGSessionMetadata` itself, including `randomness_config`, is set on-chain in `dkg.move` only through `friend`-restricted entry points (`aptos_framework::reconfiguration_with_dkg` and `aptos_framework::block`), which are not reachable by an ordinary unprivileged transaction sender: [3](#0-2) 

Since `new_public_params` always derives `PublicParams` from the on-chain `DKGSessionMetadata` fetched by the VM resolver — never from a user-supplied or forged struct — there is no admission path by which an unprivileged actor can substitute a tampered `randomness_config` and have `verify_transcript` validate against attacker-controlled parameters. This falls outside the required boundary (no unprivileged transaction/authenticator/API path exists to inject a forged `DKGSessionMetadata` into this verification flow), so it does not meet the admission-impact gate.

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L91-116)
```rust
        let dkg_state = OnChainConfig::fetch_config(resolver)
            .ok()
            .flatten()
            .ok_or(Expected(MissingResourceDKGState))?;
        let config_resource = ConfigurationResource::fetch_config(resolver)
            .ok()
            .flatten()
            .ok_or(Expected(MissingResourceConfiguration))?;
        let DKGState { in_progress, .. } = dkg_state;
        let in_progress_session_state =
            in_progress.ok_or(Expected(MissingResourceInprogressDKGSession))?;

        // Check epoch number.
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }

        // Deserialize transcript and verify it.
        let pub_params = DefaultDKG::new_public_params(&in_progress_session_state.metadata);
        let transcript = bcs::from_bytes::<<DefaultDKG as DKGTrait>::Transcript>(
            dkg_node.transcript_bytes.as_slice(),
        )
        .map_err(|_| Expected(TranscriptDeserializationFailed))?;

        DefaultDKG::verify_transcript(&pub_params, &transcript)
            .map_err(|_| Expected(TranscriptVerificationFailed))?;
```

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L1-23)
```text
/// DKG on-chain states and helper functions.
module aptos_framework::dkg {
    use std::error;
    use std::option;
    use std::option::Option;
    use aptos_framework::event::emit;
    use aptos_framework::randomness_config::RandomnessConfig;
    use aptos_framework::system_addresses;
    use aptos_framework::timestamp;
    use aptos_framework::validator_consensus_info::ValidatorConsensusInfo;
    friend aptos_framework::block;
    friend aptos_framework::reconfiguration_with_dkg;

    const EDKG_IN_PROGRESS: u64 = 1;
    const EDKG_NOT_IN_PROGRESS: u64 = 2;

    /// This can be considered as the public input of DKG.
    struct DKGSessionMetadata has copy, drop, store {
        dealer_epoch: u64,
        randomness_config: RandomnessConfig,
        dealer_validator_set: vector<ValidatorConsensusInfo>,
        target_validator_set: vector<ValidatorConsensusInfo>,
    }
```
