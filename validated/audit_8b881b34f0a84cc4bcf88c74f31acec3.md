### Title
Silent Discarding of EIP-6110/7002/7251 Processing Errors Causes Forward/Proving Divergence and Incorrect `requests_hash` - (`basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs`)

---

### Summary

In the Ethereum sequencing mode's `post_op` function, the return values of `eip6110_events_parser`, `eip7002_system_part`, and `eip7251_system_part` are silently discarded with `let _ =`. In the proving mode counterpart, the identical calls use `.expect(...)` and panic on error. This creates two compounding problems: (1) a forward/proving divergence where the sequencer accepts blocks the prover cannot verify, and (2) a different `requests_hash` algorithm between the two modes, causing the prover's header consistency assertion to fail on any block that contains actual EIP-7002/7251 requests.

---

### Finding Description

**Root cause — silent error discard in sequencing mode:**

In `post_tx_op_sequencing.rs` lines 89–92, all three EIP request-processing functions have their `Result<bool, SystemError>` return values thrown away:

```rust
// Environment may have no such contracts predeployed for tests or sequencing purposes
let _ = eip6110_events_parser(&system, &mut requests_hasher);
let _ = eip7002_system_part(&mut system, &mut requests_hasher);
let _ = eip7251_system_part(&mut system, &mut requests_hasher);
``` [1](#0-0) 

In the proving mode counterpart, the same three functions are called with `.expect(...)` that panics on any error:

```rust
if eip6110_events_parser(&*system, &mut intermediate_hasher)
    .expect("must filter EIP-6110 deposit requests") { ... }
if eip7002_system_part(system, &mut intermediate_hasher)
    .expect("withdrawal requests must be processed") { ... }
if eip7251_system_part(system, &mut intermediate_hasher)
    .expect("consolidation requests must be processed") { ... }
``` [2](#0-1) 

Both `eip7002_system_part` and `eip7251_system_part` explicitly return `Err(SystemError::LeafDefect(...))` when their respective predeploy contracts are not deployed: [3](#0-2) [4](#0-3) 

**Root cause — different hash algorithm between modes:**

Beyond error handling, the two modes use structurally different algorithms to compute `requests_hash`. In sequencing mode, a single `requests_hasher` is passed directly to all three functions, so each function appends its `type_byte || data` directly into the outer SHA-256 state:

```
requests_hash = SHA256(type_0 || data_0 || type_1 || data_1 || type_2 || data_2)
``` [5](#0-4) 

In proving mode, a fresh `intermediate_hasher` is used per function, and only if the function returns `Ok(true)` is the intermediate digest folded into the outer hasher:

```
requests_hash = SHA256(SHA256(type_0 || data_0) || SHA256(type_1 || data_1) || SHA256(type_2 || data_2))
``` [6](#0-5) 

The proving mode then asserts the computed hash equals the header's `requests_hash` field: [7](#0-6) 

---

### Impact Explanation

**Forward/proving divergence (primary impact):** When the EIP-7002 or EIP-7251 predeploy contracts are absent from the chain state, the sequencer silently ignores the `Err` return and seals the block normally. The prover re-executes the identical block and hits `.expect("withdrawal requests must be processed")`, causing a panic. The block produced by the sequencer is permanently unprovable. This is a direct state-transition / forward-proving divergence.

**Incorrect `requests_hash` in header (secondary impact):** For any block that contains actual EIP-7002 or EIP-7251 requests, the sequencer computes a flat-concatenation SHA-256 while the prover computes a two-level SHA-256. The prover's `assert_eq!(requests_hash, system.metadata.block_level.header.requests_hash, "requests hash diverged")` will fail, again making the block unprovable.

**Partial state mutation on mid-function error (tertiary impact):** `eip7002_system_part` writes the EIP-7685 type byte into the hasher at line 177 before reading queue elements. If a storage read inside the queue-element loop fails, the function returns `Err` after partially updating the hasher but before writing the updated queue-head pointer or resetting the excess-count slot. In sequencing mode this partial mutation is silently accepted, leaving the withdrawal-request queue in an inconsistent state across blocks. [8](#0-7) 

---

### Likelihood Explanation

The most realistic trigger is a chain environment where the EIP-7002 or EIP-7251 predeploy contracts have not yet been deployed (e.g., early chain bootstrap, a test network, or a chain that has not yet activated Pectra). Any unprivileged user submitting a transaction in such an environment causes the sequencer to seal a block that the prover will panic on. The EIP-7685 type-byte / two-level hash divergence is triggered by any block that contains at least one withdrawal or consolidation request, which any user can produce by calling the predeploy contract once it is deployed.

---

### Recommendation

1. Replace the three `let _ =` discards in `post_tx_op_sequencing.rs` with the same two-level intermediate-hasher pattern used in `post_tx_op_proving.rs`. If the intent is to tolerate absent predeploy contracts, match the error explicitly (`SystemError::LeafDefect`) and only suppress that specific variant, propagating all other errors.

2. Align the `requests_hash` computation algorithm between the two modes so that both produce `SHA256(SHA256(type_0 || data_0) || ...)` as required by EIP-7685.

3. Consider wrapping the entire EIP-7002/7251 system-part calls in a global frame so that any partial storage mutations are rolled back on error, preventing queue-state inconsistency.

---

### Proof of Concept

1. Deploy a ZKsync OS Ethereum-mode chain without the EIP-7002 predeploy contract at `0x00000961Ef480Eb55e80D19ad83579A64c007002`.
2. Submit any transaction. The sequencer calls `eip7002_system_part` in `post_op`, which reads account properties for the predeploy address, finds `nonce != 1 || bytecode_len == 0`, and returns `Err(SystemError::LeafDefect(...))`.
3. In sequencing mode the `let _ =` discards the error; `post_op` returns `Ok(())` and the block is sealed.
4. The prover re-executes the same block. It calls `eip7002_system_part(...).expect("withdrawal requests must be processed")`, which panics because the same `Err` is returned.
5. The block is permanently unprovable, halting proof generation for the chain. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L87-95)
```rust
        let mut requests_hasher = crypto::sha256::Sha256::new();

        // Environment may have no such contracts predeployed for tests or sequencing purposes
        let _ = eip6110_events_parser(&system, &mut requests_hasher);
        let _ = eip7002_system_part(&mut system, &mut requests_hasher);
        let _ = eip7251_system_part(&mut system, &mut requests_hasher);

        let requests_hash = Bytes32::from_array(requests_hasher.finalize().into());
        system_log!(system, "Requests hash = {:?}\n", &requests_hash);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_proving.rs (L204-240)
```rust
        use crypto::sha256::Digest;
        let mut requests_hasher = crypto::sha256::Sha256::new();
        let mut intermediate_hasher = crypto::sha256::Sha256::new();
        if eip6110_events_parser(&*system, &mut intermediate_hasher)
            .expect("must filter EIP-6110 deposit requests")
        {
            let requests_hash = intermediate_hasher.finalize_reset();
            system_log!(
                system,
                "EIP-6110 ops hash = {:?}\n",
                Bytes32::from_array(requests_hash.into())
            );
            requests_hasher.update(requests_hash);
        }
        if eip7002_system_part(system, &mut intermediate_hasher)
            .expect("withdrawal requests must be processed")
        {
            let requests_hash = intermediate_hasher.finalize_reset();
            system_log!(
                system,
                "EIP-7002 ops hash = {:?}\n",
                Bytes32::from_array(requests_hash.into())
            );
            requests_hasher.update(requests_hash);
        }
        if eip7251_system_part(system, &mut intermediate_hasher)
            .expect("consolidation requests must be processed")
        {
            let requests_hash = intermediate_hasher.finalize_reset();
            system_log!(
                system,
                "EIP-7251 ops hash = {:?}\n",
                Bytes32::from_array(requests_hash.into())
            );
            requests_hasher.update(requests_hash);
        }
        let requests_hash = Bytes32::from_array(requests_hasher.finalize().into());
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_proving.rs (L267-271)
```rust
        // - requests
        assert_eq!(
            requests_hash, system.metadata.block_level.header.requests_hash,
            "requests hash diverged",
        );
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L49-76)
```rust
pub fn eip7002_system_part<S: EthereumLikeTypes>(
    system: &mut System<S>,
    requests_hasher: &mut impl crypto::sha256::Digest,
) -> Result<bool, SystemError>
where
    S::IO: IOSubsystemExt,
{
    let mut resources = S::Resources::from_native(
        <S::Resources as Resources>::Native::from_computational(u64::MAX),
    );

    let props = resources.with_infinite_ergs(|resources| {
        system.io.read_account_properties(
            ExecutionEnvironmentType::NoEE,
            resources,
            &WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            AccountDataRequest::empty()
                .with_nonce()
                .with_observable_bytecode_len(),
        )
    })?;

    let is_contract = props.nonce.0 == 1 && props.observable_bytecode_len.0 > 0;
    if is_contract == false {
        return Err(SystemError::LeafDefect(internal_error!(
            "EIP-7002 withdrawal contract is not deployed"
        )));
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7002_withdrawal_contract/mod.rs (L169-177)
```rust
    if num_dequeued == 0 {
        // we do not even need to reset the queue pointers as it's a hard invariant
        assert!(queue_head_index.is_zero());
        assert!(queue_tail_index.is_zero());
        update_excess_withdrawal_requests_and_reset_count(system)?;
        return Ok(false);
    }

    requests_hasher.update([WITHDRAWAL_REQUEST_EIP_7685_TYPE]);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_7251_consolidation_contract/mod.rs (L63-68)
```rust
    let is_contract = props.nonce.0 == 1 && props.observable_bytecode_len.0 > 0;
    if is_contract == false {
        return Err(SystemError::LeafDefect(internal_error!(
            "EIP-7251 consolidation contract is not deployed"
        )));
    }
```
