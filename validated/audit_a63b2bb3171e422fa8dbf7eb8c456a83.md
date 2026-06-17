### Title
Unguarded `panic!` in `eip6110_events_parser` on Malformed Deposit Events Enables Block Processing Halt — (File: `basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs`)

---

### Summary

`eip6110_events_parser` iterates over every event emitted during a block and unconditionally `panic!`s when any event originating from `DEPOSIT_CONTRACT_ADDRESS` with the correct topic signature contains malformed ABI data. This function is invoked in **both** the sequencing path (`post_tx_op_sequencing.rs`) and the proving path (`post_tx_op_proving.rs`). An unprivileged user who deploys a contract at `DEPOSIT_CONTRACT_ADDRESS` — possible when the deposit contract is not pre-deployed, as the codebase itself acknowledges — can emit a single malformed deposit event and cause the entire block finalization to abort via `panic!` in both execution modes.

---

### Finding Description

In `eip6110_events_parser`, the loop over all block events contains an unconditional `panic!`:

```rust
for event in system.io.events_iterator() {
    if event.address != &DEPOSIT_CONTRACT_ADDRESS { continue; }
    if event.topics.len() > 0 && event.topics[0] == DEPOSIT_EVENT_SIGNATURE_HASH {
        ...
        let Ok(_) = validate_and_write_event_data(event, requests_hasher, &mut logger) else {
            panic!("invalid deposit event structure");   // ← hard abort
        };
    }
}
```

`validate_and_write_event_data` returns `Err(())` — triggering the `panic!` — whenever:
- `data.len() != 576`, or
- any of the five ABI-encoded u16 offset/length words does not exactly match the expected constant (160, 256, 320, 384, 512 / 48, 32, 8, 96, 8).

A contract deployed at `DEPOSIT_CONTRACT_ADDRESS` can trivially emit a `LOG1` with topic `DEPOSIT_EVENT_SIGNATURE_HASH` and any data payload that violates those constraints (e.g., 32 bytes instead of 576).

Critically, this function is called in **both** execution modes:

- **Proving mode** (`post_tx_op_proving.rs` line 207–208):
  ```rust
  if eip6110_events_parser(&*system, &mut intermediate_hasher)
      .expect("must filter EIP-6110 deposit requests")
  ```
- **Sequencing mode** (`post_tx_op_sequencing.rs` line 90):
  ```rust
  // Environment may have no such contracts predeployed for tests or sequencing purposes
  let _ = eip6110_events_parser(&system, &mut requests_hasher);
  ```

The `let _ = ...` in the sequencing path discards the `Result` return value, but the `panic!` is **inside** the function body and propagates unconditionally regardless of how the caller handles the return value. Both paths therefore abort.

The comment on line 89 of `post_tx_op_sequencing.rs` — *"Environment may have no such contracts predeployed"* — explicitly acknowledges that `DEPOSIT_CONTRACT_ADDRESS` may be unoccupied, making it a deployable target for any unprivileged sender.

---

### Impact Explanation

When the `panic!` fires:

1. The Rust process executing the bootloader aborts (no `Result` propagation, no graceful error path).
2. In the **sequencing mode**, the block cannot be sealed; all transactions in the block are lost.
3. In the **proving mode**, the prover aborts; the block can never be proven, creating a permanent forward/proving divergence for that block.

A single attacker-controlled transaction — deploying a contract at `DEPOSIT_CONTRACT_ADDRESS` and emitting one malformed event — is sufficient to permanently stall block finalization for every transaction co-included in that block.

---

### Likelihood Explanation

The codebase itself documents that `DEPOSIT_CONTRACT_ADDRESS` may not be pre-deployed (`post_tx_op_sequencing.rs` line 89). When it is absent, `DEPOSIT_CONTRACT_ADDRESS` is an ordinary, unoccupied address reachable via a standard `CREATE` or `CREATE2` deployment from any unprivileged EOA. The attacker needs only:

1. One deployment transaction targeting `DEPOSIT_CONTRACT_ADDRESS`.
2. One call transaction that emits `LOG1(DEPOSIT_EVENT_SIGNATURE_HASH, <malformed_data>)`.

No privileged access, governance control, oracle manipulation, or key compromise is required. Likelihood is **medium-high** in any deployment where the deposit contract is not part of the genesis state.

---

### Recommendation

Replace the `panic!` with a recoverable error return so the block can be rejected gracefully rather than aborting the process:

```rust
// Before (panics unconditionally):
let Ok(_) = validate_and_write_event_data(event, requests_hasher, &mut logger) else {
    panic!("invalid deposit event structure");
};

// After (propagates as a recoverable error):
validate_and_write_event_data(event, requests_hasher, &mut logger)
    .map_err(|_| SystemError::LeafDefect(internal_error!("invalid deposit event structure")))?;
```

Additionally, ensure `DEPOSIT_CONTRACT_ADDRESS` is included in the genesis / pre-deployed contract set so that no unprivileged user can deploy arbitrary code there.

---

### Proof of Concept

```
// Step 1 – deploy a malicious contract at DEPOSIT_CONTRACT_ADDRESS
// (only possible when the address is unoccupied)
contract MaliciousDeposit {
    bytes32 constant DEPOSIT_SIG =
        0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5;

    function trigger() external {
        // Emit LOG1 with correct topic but data length != 576 (e.g., 32 bytes)
        bytes memory bad = new bytes(32);
        assembly {
            log1(add(bad, 32), 32, DEPOSIT_SIG)
        }
    }
}

// Step 2 – call trigger() in the same or a subsequent block
// Result: eip6110_events_parser hits `data.len() != 576`, returns Err(()),
//         the `panic!` fires, and the entire block finalization aborts.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs (L15-19)
```rust
pub const DEPOSIT_CONTRACT_ADDRESS: B160 =
    B160::from_limbs([0x9cbe05303d7705fa, 0x219ab540356cbb83, 0x00000000]);

const DEPOSIT_EVENT_SIGNATURE_HASH: Bytes32 =
    Bytes32::from_hex("649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5");
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs (L36-48)
```rust
    for event in system.io.events_iterator() {
        if event.address != &DEPOSIT_CONTRACT_ADDRESS {
            continue;
        }
        if event.topics.len() > 0 && event.topics[0] == DEPOSIT_EVENT_SIGNATURE_HASH {
            if event_encountered == false {
                event_encountered = true;
                requests_hasher.update(&[DEPOSIT_REQUEST_EIP_7685_TYPE]);
            }
            let Ok(_) = validate_and_write_event_data(event, requests_hasher, &mut logger) else {
                panic!("invalid deposit event structure");
            };
        }
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/eip_6110_deposit_events_parser/mod.rs (L67-75)
```rust
fn validate_and_write_event_data(
    event: GenericEventContentWithTxRef<'_, MAX_EVENT_TOPICS, EthereumIOTypesConfig>,
    requests_hasher: &mut impl crypto::sha256::Digest,
    logger: &mut impl Logger,
) -> Result<(), ()> {
    let data = event.data;
    if data.len() != 576 {
        return Err(());
    }
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_sequencing.rs (L89-92)
```rust
        // Environment may have no such contracts predeployed for tests or sequencing purposes
        let _ = eip6110_events_parser(&system, &mut requests_hasher);
        let _ = eip7002_system_part(&mut system, &mut requests_hasher);
        let _ = eip7251_system_part(&mut system, &mut requests_hasher);
```

**File:** basic_bootloader/src/bootloader/block_flow/ethereum/post_tx_op_proving.rs (L207-209)
```rust
        if eip6110_events_parser(&*system, &mut intermediate_hasher)
            .expect("must filter EIP-6110 deposit requests")
        {
```
