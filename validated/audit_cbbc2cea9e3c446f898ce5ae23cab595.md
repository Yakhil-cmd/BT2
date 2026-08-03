No vulnerability found for this question.

**Analysis:**

`CollectionUriMutate` in [1](#0-0)  is a plain BCS-(de)serializable struct representing a Move event emitted by the `0x3::token_event_store::CollectionUriMutate` on-chain type [2](#0-1) . It is consumed exclusively by `event_v2_translator.rs`'s `CollectionUriMutateTranslator`-style translators, which deserialize `event_data()` from an already-committed `ContractEventV2` produced by the local node's own executed ledger, and look up the corresponding on-chain resource via `engine.get_state_value_bytes_for_resource(...)` before regenerating a `ContractEventV1` [3](#0-2) .

This code path is not reachable from unprivileged transaction submission, mempool, vm-validator, the authenticator, or any REST/BCS transaction-admission entrypoint — it runs strictly as part of the indexer's post-execution processing of a node's own already-committed events, sourced from `main_db_reader` (the node's local DB) [4](#0-3) . There is no ingestion API that accepts externally supplied BCS bytes labeled as a `CollectionUriMutate` event and injects them into this translation pipeline; the only way an event of this type reaches the translator is by being genuinely emitted by the `0x3::token_event_store` Move module during real transaction execution on that specific chain, which already enforces sender/authorization checks inside the VM itself.

Because there's no unprivileged, externally-controlled entrypoint that lets an attacker inject or replay an event payload into this component across different "chain-id contexts" (events aren't independently transmitted or re-verified against a chain-id the way transactions are — they only exist as a byproduct of already-validated execution on a single ledger), this does not meet the review's required boundary conditions (must start from unprivileged transaction/authenticator/API/proof input and affect the transaction-admission boundary). The struct's lack of a `chain_id` field is not a vulnerability, since events are not independently authenticated or replayed — they are artifacts of already-admitted, already-chain-bound transactions.

### Citations

**File:** types/src/account_config/events/collection_uri_mutate.rs (L16-22)
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct CollectionUriMutate {
    creator_addr: AccountAddress,
    collection_name: String,
    old_uri: String,
    new_uri: String,
}
```

**File:** types/src/account_config/events/collection_uri_mutate.rs (L60-74)
```rust
impl MoveStructType for CollectionUriMutate {
    const MODULE_NAME: &'static IdentStr = ident_str!("token_event_store");
    const STRUCT_NAME: &'static IdentStr = ident_str!("CollectionUriMutate");
}

impl MoveEventV2Type for CollectionUriMutate {}

pub static COLLECTION_URI_MUTATE_TYPE: Lazy<TypeTag> = Lazy::new(|| {
    TypeTag::Struct(Box::new(StructTag {
        address: TOKEN_ADDRESS,
        module: ident_str!("token_event_store").to_owned(),
        name: ident_str!("CollectionUriMutate").to_owned(),
        type_args: vec![],
    }))
});
```

**File:** storage/indexer/src/event_v2_translator.rs (L68-74)
```rust
pub struct EventV2TranslationEngine {
    pub main_db_reader: Arc<dyn DbReader>,
    pub internal_indexer_db: Arc<DB>,
    // Map from event type to translator
    pub translators: HashMap<TypeTag, Box<dyn EventV2Translator + Send + Sync>>,
    event_sequence_number_cache: DashMap<EventKey, u64>,
}
```

**File:** storage/indexer/src/event_v2_translator.rs (L1079-1117)
```rust
struct CollectionMaximumMutateTranslator;
impl EventV2Translator for CollectionMaximumMutateTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let collection_max_mutate = CollectionMaximumMutate::try_from_bytes(v2.event_data())?;
        let struct_tag = StructTag::from_str("0x3::token_event_store::TokenEventStoreV1")?;
        let (key, sequence_number) = if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_resource(collection_max_mutate.creator_addr(), &struct_tag)?
        {
            let object_resource: TokenEventStoreV1Resource = bcs::from_bytes(&state_value_bytes)?;
            let key = *object_resource.collection_maximum_mutate_events().key();
            let sequence_number = engine.get_next_sequence_number(
                &key,
                object_resource.collection_maximum_mutate_events().count(),
            )?;
            (key, sequence_number)
        } else {
            // If the TokenEventStoreV1 resource is not found, we skip the event translation to
            // avoid panic because the creation number cannot be decided.
            return Err(AptosDbError::from(anyhow::format_err!(
                "TokenEventStoreV1 resource not found"
            )));
        };
        let collection_mutation_event = CollectionMaximumMutateEvent::new(
            *collection_max_mutate.creator_addr(),
            collection_max_mutate.collection_name().clone(),
            *collection_max_mutate.old_maximum(),
            *collection_max_mutate.new_maximum(),
        );
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            COLLECTION_MAXIMUM_MUTATE_EVENT_TYPE.clone(),
            bcs::to_bytes(&collection_mutation_event)?,
        )?)
    }
```
