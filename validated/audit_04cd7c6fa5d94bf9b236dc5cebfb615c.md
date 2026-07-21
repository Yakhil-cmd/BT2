### Title
Events Silently Dropped in P2P Protobuf Receipt Deserialization — (`crates/apollo_protobuf/src/converters/receipt.rs`)

### Summary

All five `TryFrom<protobuf::receipt::*> for *TransactionOutput` implementations in the P2P protobuf receipt converter unconditionally hardcode `events = vec![]`. The serialization direction (`From<*TransactionOutput> for protobuf::receipt::*`) also silently discards events because the `protobuf::receipt::Common` message has no events field. Any node that syncs blocks via P2P stores transaction outputs with permanently empty event lists. Every subsequent RPC call that reads those outputs returns an authoritative-looking but completely wrong value.

### Finding Description

In `crates/apollo_protobuf/src/converters/receipt.rs`, every deserialization path from the P2P wire format to a `TransactionOutput` hardcodes an empty events vector:

```rust
// The output will have an empty events vec
impl TryFrom<protobuf::receipt::Invoke> for InvokeTransactionOutput {
    fn try_from(value: protobuf::receipt::Invoke) -> Result<Self, Self::Error> {
        let (actual_fee, messages_sent, execution_status, execution_resources) =
            parse_common_receipt_fields(value.common)?;
        let events = vec![];   // ← always empty
        Ok(Self { actual_fee, messages_sent, events, execution_status, execution_resources })
    }
}
```

The same pattern appears for `DeployAccount` (line 79), `Deploy` (line 127), `Declare` (line 174), `Invoke` (line 202), and `L1Handler` (line 230). [1](#0-0) [2](#0-1) [3](#0-2) 

The serialization side is equally broken. `create_proto_receipt_common_from_txn_output_fields` builds a `protobuf::receipt::Common` that contains `actual_fee`, `messages_sent`, `execution_resources`, and `revert_reason` — but no events field — because the protobuf schema itself has no events field in `Common` or in any per-type receipt message. [4](#0-3) [5](#0-4) 

The P2P sync client has no separate event-sync channel. The `P2pSyncClientChannels::new` constructor accepts `header_sender`, `state_diff_sender`, `transaction_sender`, and `class_sender` — there is no `event_sender`. [6](#0-5) 

The P2P sync server does have an `event_receiver`, but the client never requests events, so they are never transmitted. [7](#0-6) 

The transaction sync test explicitly works around this by forcing zero events per transaction with `get_test_body(i, Some(0), ...)` and a TODO comment: `// TODO(shahak): remove Some(0) once we separate events from transactions correctly.` [8](#0-7) 

When the empty-events `TransactionOutput` is written to storage, `write_events` iterates over `tx_output.events()` and writes nothing to the events table. [9](#0-8) 

### Impact Explanation

Every node that syncs blocks via P2P (i.e., any non-proposer node catching up) stores transaction outputs with `events = []` for every transaction in every synced block. This produces wrong values on three RPC surfaces:

1. `starknet_getEvents` — returns an empty result set for any event query over P2P-synced blocks.
2. `starknet_getTransactionReceipt` — returns a receipt with an empty `events` array.
3. `starknet_getBlockWithReceipts` — returns all receipts with empty `events` arrays.

The `event_commitment` field in the block header is received and stored correctly from the header-sync protocol, so the stored block hash is not corrupted. However, any code path that recomputes `event_commitment` from stored `TransactionOutput` objects — such as `calculate_block_commitments` which iterates `transaction_data.transaction_output.events` — would produce a zero-event commitment that disagrees with the header. [10](#0-9) 

This matches the allowed impact: **High — RPC execution returns an authoritative-looking wrong value** (`starknet_getEvents`, `starknet_getTransactionReceipt`, `starknet_getBlockWithReceipts` all return empty events for all P2P-synced blocks).

### Likelihood Explanation

The defect is unconditional and structural: every P2P-synced block is affected, for every transaction type, with no configuration or attacker action required. Any deployed node that is not the block proposer and relies on P2P sync is affected immediately upon syncing its first block.

### Recommendation

1. Add a `repeated Event events` field to `Receipt.Common` (or to each per-type receipt message) in `crates/apollo_protobuf/src/proto/p2p/proto/sync/receipt.proto`.
2. Update `create_proto_receipt_common_from_txn_output_fields` to serialize `value.events` into the new field.
3. Update all five `TryFrom<protobuf::receipt::*>` implementations to deserialize events from the wire message instead of hardcoding `vec![]`.
4. Alternatively, implement the separate events-sync channel that the server already supports (`event_receiver`) and wire it into the client's `P2pSyncClientChannels`.
5. Remove the `Some(0)` workaround in `transaction_test.rs` and add a test that verifies events round-trip correctly through P2P sync.

### Proof of Concept

1. Start two nodes: node A as sequencer/proposer, node B as P2P sync client.
2. On node A, submit an invoke transaction that emits at least one event (e.g., an ERC-20 transfer, which emits a `Transfer` event).
3. Wait for node A to include the transaction in a block and for node B to sync that block via P2P.
4. Query node B via `starknet_getTransactionReceipt` for that transaction hash.
5. **Observed**: `"events": []` — empty.
6. **Expected**: the `Transfer` event emitted by the ERC-20 contract.
7. Query node B via `starknet_getEvents` with the block range and the ERC-20 contract address as filter.
8. **Observed**: `{"events": [], "continuation_token": null}` — no events found.
9. **Expected**: the `Transfer` event.

The root cause is confirmed at:
- Serialization: `From<InvokeTransactionOutput> for protobuf::receipt::Invoke` calls `create_proto_receipt_common_from_txn_output_fields` which does not include `value.events`. [11](#0-10) 
- Deserialization: `TryFrom<protobuf::receipt::Invoke> for InvokeTransactionOutput` sets `let events = vec![]`. [12](#0-11)

### Citations

**File:** crates/apollo_protobuf/src/converters/receipt.rs (L72-100)
```rust
// The output will have an empty events vec
impl TryFrom<protobuf::receipt::DeployAccount> for DeployAccountTransactionOutput {
    type Error = ProtobufConversionError;
    fn try_from(value: protobuf::receipt::DeployAccount) -> Result<Self, Self::Error> {
        let (actual_fee, messages_sent, execution_status, execution_resources) =
            parse_common_receipt_fields(value.common)?;

        let events = vec![];

        let contract_address =
            value.contract_address.ok_or(missing("DeployAccount::contract_address"))?;
        let felt = Felt::try_from(contract_address)?;
        let contract_address = ContractAddress(PatriciaKey::try_from(felt).map_err(|_| {
            ProtobufConversionError::OutOfRangeValue {
                type_description: "PatriciaKey",
                value_as_str: format!("{felt:?}"),
            }
        })?);

        Ok(Self {
            actual_fee,
            messages_sent,
            events,
            contract_address,
            execution_status,
            execution_resources,
        })
    }
}
```

**File:** crates/apollo_protobuf/src/converters/receipt.rs (L195-206)
```rust
// The output will have an empty events vec
impl TryFrom<protobuf::receipt::Invoke> for InvokeTransactionOutput {
    type Error = ProtobufConversionError;
    fn try_from(value: protobuf::receipt::Invoke) -> Result<Self, Self::Error> {
        let (actual_fee, messages_sent, execution_status, execution_resources) =
            parse_common_receipt_fields(value.common)?;

        let events = vec![];

        Ok(Self { actual_fee, messages_sent, events, execution_status, execution_resources })
    }
}
```

**File:** crates/apollo_protobuf/src/converters/receipt.rs (L208-221)
```rust
impl From<InvokeTransactionOutput> for protobuf::receipt::Invoke {
    /// The returned price_unit isn't correct.
    /// It can be fixed by calling set_price_unit_based_on_transaction
    fn from(value: InvokeTransactionOutput) -> Self {
        let common = create_proto_receipt_common_from_txn_output_fields(
            value.actual_fee,
            value.messages_sent,
            value.execution_resources,
            value.execution_status,
        );

        protobuf::receipt::Invoke { common: Some(common) }
    }
}
```

**File:** crates/apollo_protobuf/src/converters/receipt.rs (L223-234)
```rust
// The output will have an empty events vec
impl TryFrom<protobuf::receipt::L1Handler> for L1HandlerTransactionOutput {
    type Error = ProtobufConversionError;
    fn try_from(value: protobuf::receipt::L1Handler) -> Result<Self, Self::Error> {
        let (actual_fee, messages_sent, execution_status, execution_resources) =
            parse_common_receipt_fields(value.common)?;

        let events = vec![];

        Ok(Self { actual_fee, messages_sent, events, execution_status, execution_resources })
    }
}
```

**File:** crates/apollo_protobuf/src/converters/receipt.rs (L441-463)
```rust
fn create_proto_receipt_common_from_txn_output_fields(
    actual_fee: Fee,
    messages_sent: Vec<MessageToL1>,
    execution_resources: ExecutionResources,
    execution_status: TransactionExecutionStatus,
) -> protobuf::receipt::Common {
    let actual_fee = Felt::from(actual_fee).into();
    let messages_sent = messages_sent.into_iter().map(protobuf::MessageToL1::from).collect();
    let execution_resources = execution_resources.into();
    let revert_reason =
        if let TransactionExecutionStatus::Reverted(reverted_status) = execution_status {
            Some(reverted_status.revert_reason)
        } else {
            None
        };
    protobuf::receipt::Common {
        actual_fee: Some(actual_fee),
        price_unit: 0,
        messages_sent,
        execution_resources: Some(execution_resources),
        revert_reason,
    }
}
```

**File:** crates/apollo_protobuf/src/proto/p2p/proto/sync/receipt.proto (L47-53)
```text
  message Common {
    Felt252 actual_fee = 2;
    PriceUnit price_unit = 3;
    repeated MessageToL1 messages_sent = 4;
    ExecutionResources execution_resources = 5;
    optional string revert_reason = 6;
  }
```

**File:** crates/apollo_p2p_sync/src/client/mod.rs (L81-133)
```rust
impl P2pSyncClientChannels {
    pub fn new(
        header_sender: HeaderSqmrSender,
        state_diff_sender: StateSqmrDiffSender,
        transaction_sender: TransactionSqmrSender,
        class_sender: ClassSqmrSender,
    ) -> Self {
        Self { header_sender, state_diff_sender, transaction_sender, class_sender }
    }
    pub(crate) fn create_stream(
        self,
        storage_reader: StorageReader,
        config: P2pSyncClientConfig,
        internal_blocks_receivers: InternalBlocksReceivers,
    ) -> impl Stream<Item = BlockDataResult> + Send + 'static {
        let header_stream = HeaderStreamBuilder::create_stream(
            self.header_sender,
            storage_reader.clone(),
            Some(internal_blocks_receivers.header_receiver),
            config.wait_period_for_new_data,
            config.wait_period_for_other_protocol,
            config.num_headers_per_query,
        );

        let state_diff_stream = StateDiffStreamBuilder::create_stream(
            self.state_diff_sender,
            storage_reader.clone(),
            Some(internal_blocks_receivers.state_diff_receiver),
            config.wait_period_for_new_data,
            config.wait_period_for_other_protocol,
            config.num_block_state_diffs_per_query,
        );

        let transaction_stream = TransactionStreamFactory::create_stream(
            self.transaction_sender,
            storage_reader.clone(),
            Some(internal_blocks_receivers.transaction_receiver),
            config.wait_period_for_new_data,
            config.wait_period_for_other_protocol,
            config.num_block_transactions_per_query,
        );

        let class_stream = ClassStreamBuilder::create_stream(
            self.class_sender,
            storage_reader.clone(),
            Some(internal_blocks_receivers.class_receiver),
            config.wait_period_for_new_data,
            config.wait_period_for_other_protocol,
            config.num_block_classes_per_query,
        );

        header_stream.merge(state_diff_stream).merge(transaction_stream).merge(class_stream)
    }
```

**File:** crates/apollo_p2p_sync/src/server/mod.rs (L77-107)
```rust
type HeaderReceiver = SqmrServerReceiver<HeaderQuery, DataOrFin<SignedBlockHeader>>;
type StateDiffReceiver = SqmrServerReceiver<StateDiffQuery, DataOrFin<StateDiffChunk>>;
type TransactionReceiver = SqmrServerReceiver<TransactionQuery, DataOrFin<FullTransaction>>;
type ClassReceiver = SqmrServerReceiver<ClassQuery, DataOrFin<(ApiContractClass, ClassHash)>>;
type EventReceiver = SqmrServerReceiver<EventQuery, DataOrFin<(Event, TransactionHash)>>;

pub struct P2pSyncServerChannels {
    header_receiver: HeaderReceiver,
    state_diff_receiver: StateDiffReceiver,
    transaction_receiver: TransactionReceiver,
    class_receiver: ClassReceiver,
    event_receiver: EventReceiver,
}

impl P2pSyncServerChannels {
    pub fn new(
        header_receiver: HeaderReceiver,
        state_diff_receiver: StateDiffReceiver,
        transaction_receiver: TransactionReceiver,
        class_receiver: ClassReceiver,
        event_receiver: EventReceiver,
    ) -> Self {
        Self {
            header_receiver,
            state_diff_receiver,
            transaction_receiver,
            class_receiver,
            event_receiver,
        }
    }
}
```

**File:** crates/apollo_p2p_sync/src/client/transaction_test.rs (L28-38)
```rust
    let block_bodies = (0..NUM_BLOCKS)
        // TODO(shahak): remove Some(0) once we separate events from transactions correctly.
        .map(|i| {
            let mut body = get_test_body(i.try_into().unwrap(), Some(0), None, None);
            // get_test_body returns transaction hash in the range 0..num_transactions. We want to
            // avoid collisions in transaction hash.
            for transaction_hash in &mut body.transaction_hashes {
                *transaction_hash = TransactionHash(transaction_hash.0 + NUM_BLOCKS * i);
            }
            body
        })
```

**File:** crates/apollo_storage/src/body/mod.rs (L643-663)
```rust
// This function assumes that the `transaction_index` is the last index used to call it.
fn write_events<'env>(
    tx_output: &TransactionOutput,
    txn: &DbTransaction<'env, RW>,
    events_table: &'env EventsTable<'env>,
    transaction_index: TransactionIndex,
) -> StorageResult<()> {
    let mut contract_addresses_set = HashSet::new();

    for event in tx_output.events().iter() {
        contract_addresses_set.insert(event.from_address);
    }

    for contract_address in contract_addresses_set {
        let key = (contract_address, transaction_index);
        // Here, we use the function assumption; the append will fail if an older transaction_index
        // is a table.
        events_table.append_greater_sub_key(txn, &key, &NoValue)?;
    }
    Ok(())
}
```

**File:** crates/starknet_api/src/block_hash/block_hash_calculator.rs (L305-313)
```rust
    let event_leaf_elements: Vec<EventLeafElement> = transactions_data
        .iter()
        .flat_map(|transaction_data| {
            transaction_data.transaction_output.events.iter().map(|event| EventLeafElement {
                event: event.clone(),
                transaction_hash: transaction_data.transaction_hash,
            })
        })
        .collect();
```
