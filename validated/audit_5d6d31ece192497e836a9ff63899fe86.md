### Title
`simulate_transactions` and `estimate_fee` Return Wrong State Diff and Transaction Hash for Declare V1 — (`crates/apollo_rpc/src/v0_8/api/mod.rs`)

### Summary

The `TryFrom<BroadcastedDeclareTransaction> for ExecutableTransactionInput` implementation unconditionally sets `class_hash: ClassHash::default()` (`Felt::ZERO`) for every `BroadcastedDeclareV1Transaction`. This zero class hash propagates into two concrete wrong values returned by the public `starknet_estimateFee` and `starknet_simulateTransactions` RPC endpoints: (1) the transaction hash is computed with `class_hash=0` instead of the actual class hash, and (2) the `deprecated_declared_classes` field in the simulation state diff is `[0x0]` instead of the actual class hash.

### Finding Description

`BroadcastedDeclareV1Transaction` carries no `class_hash` field — it only carries `contract_class`, `sender_address`, `nonce`, `max_fee`, and `signature`. [1](#0-0) 

When `estimate_fee` or `simulate_transactions` receives a `BroadcastedTransaction::Declare(V1)`, it calls `.try_into()` to produce an `ExecutableTransactionInput`. [2](#0-1) [3](#0-2) 

That conversion hardcodes `class_hash: ClassHash::default()` with the comment "The blockifier doesn't need the class hash": [4](#0-3) 

**Wrong transaction hash.** `execute_transactions` calls `calc_tx_hashes`, which calls `get_declare_transaction_v1_hash`. That function chains `transaction.class_hash.0` into the Pedersen hash: [5](#0-4) 

Because `class_hash = Felt::ZERO`, the computed `tx_hash` is wrong for every declare V1 submitted to these endpoints. This hash is passed to `BlockifierTransaction::from_api` and becomes the value returned by `get_execution_info` inside the simulated execution. [6](#0-5) 

**Wrong state diff.** Before calling the blockifier, `execute_transactions` extracts `deprecated_declared_class_hash` directly from `DeclareTransactionV0V1.class_hash`: [7](#0-6) 

This value (`ClassHash::default()` = `0x0`) is then passed to `induced_state_diff`, which uses it to populate the `deprecated_declared_classes` list in the returned `ThinStateDiff`: [8](#0-7) 

The blockifier's own `CommitmentStateDiff` does not include deprecated declared classes — the code relies entirely on this manually supplied value. So `simulate_transactions` returns a state diff with `deprecated_declared_classes: [0x0]` regardless of the actual class submitted.

### Impact Explanation

Every call to `starknet_simulateTransactions` with a Declare V1 transaction returns an authoritative-looking state diff claiming the class was declared under hash `0x0`. Tooling, wallets, and developers relying on this state diff to determine the declared class hash receive a concretely wrong value. Additionally, the wrong transaction hash is exposed via `get_execution_info` during simulated validation, which can cause account contracts that verify the transaction hash (e.g., for replay protection or custom validation logic) to behave incorrectly during simulation, producing misleading revert/success results.

### Likelihood Explanation

This is triggered unconditionally by any `BroadcastedDeclareV1Transaction` submitted to `estimate_fee` or `simulate_transactions`. No special attacker capability is required — any unprivileged RPC caller can trigger it. The code path is deterministic and has no conditional guards.

### Recommendation

Compute the actual class hash from the submitted `contract_class` before constructing the `DeclareTransactionV0V1`. For Cairo 0 (deprecated) classes, the class hash is the Pedersen hash of the contract class definition. The correct hash should be computed from `sn_api_contract_class` (already available in the conversion) and used in place of `ClassHash::default()`.

### Proof of Concept

```rust
// In TryFrom<BroadcastedDeclareTransaction> for ExecutableTransactionInput (api/mod.rs ~line 494)
// The conversion always produces class_hash = 0x0:
Ok(Self::DeclareV1(
    starknet_api::transaction::DeclareTransactionV0V1 {
        max_fee,
        signature,
        nonce,
        class_hash: ClassHash::default(), // <-- always Felt::ZERO
        sender_address,
    },
    sn_api_contract_class,
    abi_length,
    false,
))

// In execute_transactions (lib.rs ~line 740), this zero is extracted:
ExecutableTransactionInput::DeclareV1(
    DeclareTransactionV0V1 { class_hash, .. }, // class_hash = 0x0
    _, _, _,
) => Some(*class_hash),

// And passed to induced_state_diff, which returns:
// ThinStateDiff { deprecated_declared_classes: [ClassHash(0x0)], ... }
// regardless of the actual submitted contract class.
```

A Rust unit test confirming the behavior:
```rust
let tx = BroadcastedDeclareTransaction::V1(BroadcastedDeclareV1Transaction {
    contract_class: some_non_trivial_class,
    sender_address: some_address,
    nonce: Nonce::default(),
    max_fee: Fee(1000),
    signature: TransactionSignature::default(),
    r#type: DeclareType::Declare,
});
let executable: ExecutableTransactionInput = tx.try_into().unwrap();
if let ExecutableTransactionInput::DeclareV1(declare_tx, ..) = executable {
    assert_eq!(declare_tx.class_hash, ClassHash::default()); // always passes
}
```

### Citations

**File:** crates/apollo_rpc/src/v0_8/broadcasted_transaction.rs (L70-79)
```rust
#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BroadcastedDeclareV1Transaction {
    pub r#type: DeclareType,
    pub contract_class: DeprecatedContractClass,
    pub sender_address: ContractAddress,
    pub nonce: Nonce,
    pub max_fee: Fee,
    pub signature: TransactionSignature,
}
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1018-1019)
```rust
        let executable_txns =
            transactions.into_iter().map(|tx| tx.try_into()).collect::<Result<_, _>>()?;
```

**File:** crates/apollo_rpc/src/v0_8/api/api_impl.rs (L1074-1075)
```rust
        let executable_txns =
            transactions.into_iter().map(|tx| tx.try_into()).collect::<Result<_, _>>()?;
```

**File:** crates/apollo_rpc/src/v0_8/api/mod.rs (L494-508)
```rust
                Ok(Self::DeclareV1(
                    starknet_api::transaction::DeclareTransactionV0V1 {
                        max_fee,
                        signature,
                        nonce,
                        // The blockifier doesn't need the class hash, but it uses the SN_API
                        // DeclareTransactionV0V1 which requires it.
                        class_hash: ClassHash::default(),
                        sender_address,
                    },
                    sn_api_contract_class,
                    abi_length,
                    // TODO(yair): pass the right value for only_query field.
                    false,
                ))
```

**File:** crates/starknet_api/src/transaction_hash.rs (L545-562)
```rust
pub(crate) fn get_declare_transaction_v1_hash(
    transaction: &DeclareTransactionV0V1,
    chain_id: &ChainId,
    transaction_version: &TransactionVersion,
) -> Result<TransactionHash, StarknetApiError> {
    Ok(TransactionHash(
        HashChain::new()
        .chain(&DECLARE)
        .chain(&transaction_version.0)
        .chain(transaction.sender_address.0.key())
        .chain(&Felt::ZERO) // No entry point selector in declare transaction.
        .chain(&HashChain::new().chain(&transaction.class_hash.0).get_pedersen_hash())
        .chain(&transaction.max_fee.0.into())
        .chain(&Felt::try_from(chain_id)?)
        .chain(&transaction.nonce.0)
        .get_pedersen_hash(),
    ))
}
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L740-746)
```rust
            ExecutableTransactionInput::DeclareV1(
                DeclareTransactionV0V1 { class_hash, .. },
                _,
                _,
                _,
            ) => Some(*class_hash),
            _ => None,
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L890-898)
```rust
            BlockifierTransaction::from_api(
                Transaction::Declare(DeclareTransaction::V1(declare_tx)),
                tx_hash,
                Some(class_info),
                None,
                None,
                execution_flags,
            )
            .map_err(|err| ExecutionError::from((transaction_index, err)))
```

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L130-145)
```rust
pub fn induced_state_diff(
    transactional_state: &mut CachedState<MutRefState<'_, CachedState<ExecutionStateReader>>>,
    deprecated_declared_class_hash: Option<ClassHash>,
) -> ExecutionResult<ThinStateDiff> {
    let blockifier_state_diff =
        CommitmentStateDiff::from(transactional_state.to_state_diff()?.state_maps);

    Ok(ThinStateDiff {
        deployed_contracts: blockifier_state_diff.address_to_class_hash,
        storage_diffs: blockifier_state_diff.storage_updates,
        class_hash_to_compiled_class_hash: blockifier_state_diff.class_hash_to_compiled_class_hash,
        deprecated_declared_classes: deprecated_declared_class_hash
            .map_or_else(Vec::new, |class_hash| vec![class_hash]),
        nonces: blockifier_state_diff.address_to_nonce,
    })
}
```
