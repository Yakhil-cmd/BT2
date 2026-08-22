### Title
Wallet Contract's hardcoded per-network `CHAIN_ID` enables replay of signed Ethereum-style transactions across a NEAR chain split/hard fork - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs`)

### Summary
The Wallet Contract (used for ETH-implicit accounts) bakes a fixed EVM `CHAIN_ID` constant into its compiled WASM at build time, one value per NEAR network (397 for mainnet, 398 for testnet, 399 for localnet), and uses it as the sole chain-binding check when validating signed Ethereum-style transactions relayed through `rlp_execute`. This mirrors the reported Golom pattern of baking `chainId` into a fixed value at deploy/construction time: if the underlying NEAR network the contract is deployed on ever undergoes a chain split ("hard fork"), the identical contract code with the identical hardcoded `CHAIN_ID` would run unmodified on both resulting chains, and a signed Ethereum-style transaction valid on one chain would remain fully valid and replayable on the other.

### Finding Description
The `CHAIN_ID` used by the Wallet Contract is generated once at build time via `build.rs` and embedded directly into the contract WASM per network: [1](#0-0) [2](#0-1) 

This constant is then compared against the `chain_id` field of the user-signed RLP Ethereum transaction inside `validate_tx_relayer_data`, which is the core relayer-data validation used by `rlp_execute` to authorize execution of the emulated Ethereum action on behalf of the account: [3](#0-2) 

The check is a strict equality against the fixed, compile-time `CHAIN_ID` - it is not derived from any NEAR runtime chain state (e.g. genesis hash, `chain_id()` host function value, or block hash) and cannot distinguish between two chains that share the same network identity/genesis but have diverged (a hard fork/chain split). This is functionally identical to the Golom bug: the value meant to bind a signature's validity to "this specific chain" is fixed once and can become stale/ambiguous after a fork, because both forked chains would run byte-identical Wallet Contract code with the same `CHAIN_ID`.

Additional confirmation of the intended purpose (chain binding for signature validity) comes from the test suite, which explicitly treats a chain_id mismatch as fraud/replay prevention (banning the relayer): [4](#0-3) 

By contrast, this is unlike NEAR's native `Transaction`/`SignedTransaction`, whose hash-and-sign scheme is bound only to `signer_id`, `public_key`, `nonce`, `receiver_id`, `block_hash`, `actions` - no chain identifier is signed over at all, and freshness protection instead relies purely on `block_hash` + `transaction_validity_period`: [5](#0-4) [6](#0-5) 

For the Wallet Contract's *inner* Ethereum-emulated transaction, the only replay protections are: (1) the fixed `CHAIN_ID` (which does not differentiate forks of the same network) and (2) an on-chain nonce tracked per Wallet Contract account, incremented as part of `inner_rlp_execute`: [7](#0-6) 

If a chain split occurs before a given signed Ethereum-style transaction's on-chain nonce is consumed (e.g. it is in-flight, matching the contract's own documented "only one in-flight tx at a time" invariant), both post-fork chains start from the same account nonce state and accept the exact same `CHAIN_ID`, so the same signed transaction can be submitted and executed on both chains by any relayer, in effect double-spending the single user authorization across the fork.

### Impact Explanation
This allows a signed Ethereum-style transaction (transfer, ERC-20 emulated transfer, function call, add/delete key, etc., submitted through any relayer with `rlp_execute` access) to be validly re-executed on a diverged/forked chain that shares the same `CHAIN_ID`-embedded Wallet Contract code and pre-fork account state. This is unauthorized re-execution of a user's signed action on a chain the user did not intend it for, resulting in unauthorized state or balance change (e.g., duplicate transfers or duplicate access-key management from a single signed authorization) - matching the "unauthorized state or balance change" impact class.

### Likelihood Explanation
This requires an external factor (a NEAR chain split/hard fork) similar to the original Golom finding, which the original judge also rated as Medium for the same reason (high impact, but conditioned on an infrequent external event). It also requires a signed transaction to be pending/in-flight at the moment of the fork and a relayer/attacker willing to replay it on the other branch, which is plausible in NEAR's wallet-contract relayer model where any account with an authorized function-call access key can act as relayer.

### Recommendation
Bind the Wallet Contract's chain check to a value that is guaranteed to diverge across a hard fork, rather than a fixed compile-time constant shared by all chains derived from the same genesis. For example, derive/include the current NEAR `chain_id()` (host function) or genesis hash as part of the signed message context validated in `validate_tx_relayer_data`, or otherwise ensure `CHAIN_ID` is re-derived/re-registered per resulting chain after any fork so that pre-fork signed transactions cannot be replayed on a subsequently diverged chain.

### Proof of Concept
1. Deploy the Wallet Contract to mainnet; it is compiled with `CHAIN_ID = 397` baked in (`build.rs`, `internal.rs::CHAIN_ID`).
2. A user signs an Ethereum-style RLP transaction (e.g. `Transaction2930`) with `chain_id: 397`, e.g. a transfer to another wallet, and hands it to a relayer, which calls `rlp_execute`. Suppose the transaction has not yet been executed (still in-flight).
3. Suppose mainnet then experiences a hard fork/chain split, producing chain A and chain B, both starting from identical pre-fork state (same Wallet Contract WASM, same account nonce state, same `CHAIN_ID = 397`).
4. The relayer submits the same signed RLP transaction to chain A via `rlp_execute` on chain A's copy of the account; `validate_tx_relayer_data` passes (`tx.chain_id == Some(397)`, nonce matches), and the transfer executes.
5. The relayer (or a different relayer holding the transaction) submits the identical signed RLP transaction to chain B's copy of the account; because chain B independently has the same nonce state and the same `CHAIN_ID = 397`, `validate_tx_relayer_data` passes there as well, and the transfer executes a second time - on a chain the signer never intended the transaction for.

### Citations

**File:** runtime/near-wallet-contract/build.rs (L7-16)
```rust
const IMAGE_TAG: &str = "13430592a7be246dd5a29439791f4081e0107ff3";

/// See https://chainlist.org/chain/397
const MAINNET_CHAIN_ID: u64 = 397;

/// See https://chainlist.org/chain/398
const TESTNET_CHAIN_ID: u64 = 398;

/// Not officially registered on chainlist.org because this is for local testing only.
const LOCALNET_CHAIN_ID: u64 = 399;
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L16-20)
```rust
/// The chain ID is pulled from a file to allow this contract to be easily
/// compiled with the appropriate value for the network it will be deployed on.
/// The chain ID for Near mainnet is [397](https://chainlist.org/chain/397)
/// while the value for testnet is [398](https://chainlist.org/chain/398).
pub const CHAIN_ID: u64 = std::include!("CHAIN_ID");
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/internal.rs (L312-331)
```rust
/// Validates the transaction is following the Wallet Contract protocol.
/// This includes checks for:
/// - from address matches current account address
/// - to address is present and matches the target address (or hash of target account ID)
/// - nonce matches expected nonce
/// If this validation fails then the relayer that sent it is faulty and should be banned.
fn validate_tx_relayer_data<'a>(
    tx: &NormalizedEthTransaction,
    target: &'a AccountId,
    context: &ExecutionContext,
    expected_nonce: u64,
) -> Result<TargetKind<'a>, Error> {
    if tx.address.raw() != context.current_address {
        return Err(Error::Relayer(RelayerError::InvalidSender));
    }

    if tx.chain_id != Some(CHAIN_ID) {
        return Err(Error::Relayer(RelayerError::InvalidChainId));
    }

```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/tests/relayer.rs (L242-276)
```rust
// A relayer sending a transaction signed with the wrong chain id is a ban-worthy offense.
#[tokio::test]
async fn test_relayer_wrong_chain_id() -> anyhow::Result<()> {
    let TestContext { worker, mut wallet_contract, wallet_sk, wallet_address, .. } =
        TestContext::new().await?;

    let relayer_pk = wallet_contract.register_relayer(&worker).await?;

    let transaction = aurora_engine_transactions::eip_2930::Transaction2930 {
        nonce: 0.into(),
        gas_price: 0.into(),
        gas_limit: 0.into(),
        to: Some(Address::new(wallet_address)),
        value: Wei::zero(),
        data: [
            crate::eth_emulation::ERC20_BALANCE_OF_SELECTOR.to_vec(),
            ethabi::encode(&[ethabi::Token::Address(wallet_address)]),
        ]
        .concat(),
        chain_id: CHAIN_ID + 1,
        access_list: Vec::new(),
    };
    let signed_transaction = crypto::sign_transaction(transaction, &wallet_sk);

    let result = wallet_contract
        .rlp_execute(wallet_contract.inner.id().as_str(), &signed_transaction)
        .await?;

    assert!(!result.success);
    assert_eq!(result.error.as_deref(), Some("Error: faulty relayer"));

    assert_revoked_key(&wallet_contract.inner, &relayer_pk).await;

    Ok(())
}
```

**File:** core/primitives/src/transaction.rs (L30-48)
```rust
#[derive(
    BorshSerialize, BorshDeserialize, serde::Serialize, PartialEq, Eq, Debug, Clone, ProtocolSchema,
)]
pub struct TransactionV0 {
    /// An account on which behalf transaction is signed
    pub signer_id: AccountId,
    /// A public key of the access key which was used to sign an account.
    /// Access key holds permissions for calling certain kinds of actions.
    pub public_key: PublicKey,
    /// Nonce is used to determine order of transaction in the pool.
    /// It increments for a combination of `signer_id` and `public_key`
    pub nonce: Nonce,
    /// Receiver account for this transaction
    pub receiver_id: AccountId,
    /// The hash of the block in the blockchain on top of which the given transaction is valid
    pub block_hash: CryptoHash,
    /// A list of actions to be applied
    pub actions: Vec<Action>,
}
```

**File:** core/primitives/src/transaction.rs (L139-144)
```rust
impl Transaction {
    /// Computes a hash of the transaction for signing and size of serialized transaction
    pub fn get_hash_and_size(&self) -> (CryptoHash, u64) {
        let bytes = borsh::to_vec(&self).expect("Failed to deserialize");
        (hash(&bytes), bytes.len() as u64)
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L330-365)
```rust
fn inner_rlp_execute(
    current_account_id: AccountId,
    predecessor_account_id: AccountId,
    target: AccountId,
    tx_bytes_b64: String,
    nonce: &mut u64,
) -> Result<Promise, Error> {
    if *nonce == u64::MAX {
        return Err(Error::AccountNonceExhausted);
    }
    let context = ExecutionContext::new(
        current_account_id.clone(),
        predecessor_account_id,
        env::attached_deposit(),
    )?;
    let caller_deposit = CallerDeposit::new(&context);

    let parsing_result = internal::parse_rlp_tx_to_action(&tx_bytes_b64, &target, &context, *nonce);
    let (action, transaction_kind) = match parsing_result {
        Ok((action, transaction_kind)) => {
            // Increment nonce for all cases where the registrar contract is not needed
            // to prevent replay of those transactions. For transactions that go through
            // the registrar we still do not know if the transaction has a relayer error
            // or not, therefore we must delay incrementing the nonce.
            //
            // Note: relayers with access keys cannot use this delay to needlessly spend
            // the users tokens because only one transaction is allowed to be in-flight
            // at a time.
            if let TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
                address_check: Some(_),
                ..
            }) = &transaction_kind
            {
            } else {
                *nonce = nonce.saturating_add(1);
            }
```
