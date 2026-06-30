### Title
Pre-EIP-155 Legacy Transaction Cross-Chain Replay Accepted Without Chain ID Validation - (`engine/src/engine.rs`, `engine-transactions/src/legacy.rs`)

### Summary

Aurora Engine explicitly accepts pre-EIP-155 legacy transactions (those with `v = 27` or `v = 28`) whose signed payload contains no chain ID. The engine's chain ID guard is conditioned on `chain_id` being `Some`, so it is silently skipped for these transactions. Any pre-EIP-155 transaction broadcast on Ethereum mainnet (or any other EVM chain) can be replayed verbatim on Aurora by any unprivileged caller of the `submit` entrypoint, draining the sender's Aurora ETH balance if the nonce matches.

### Finding Description

`LegacyEthSignedTransaction::sender()` in `engine-transactions/src/legacy.rs` decodes the recovery ID from `v`:

```rust
27..=28 => (
    None,   // ← chain_id absent from signed payload
    u8::try_from(self.v - 27).map_err(|_e| Error::InvalidV)?,
),
```

When `v` is 27 or 28, `chain_id()` returns `None` and the signed message is `keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data]))` — identical across every EVM chain. [1](#0-0) 

`NormalizedEthTransaction` propagates this `None` directly:

```rust
Legacy(tx) => Self {
    address: tx.sender()?,
    chain_id: tx.chain_id(),   // ← None for pre-EIP-155
    ...
``` [2](#0-1) 

The engine's only replay guard is:

```rust
if let Some(chain_id) = transaction.chain_id
    && U256::from(chain_id) != U256::from_big_endian(&state.chain_id)
{
    return Err(EngineErrorKind::InvalidChainId.into());
}
```

Because the pattern `if let Some(chain_id)` short-circuits when `chain_id` is `None`, the entire check is bypassed for pre-EIP-155 transactions. [3](#0-2) 

The `submit` entrypoint is publicly callable by any NEAR account: [4](#0-3) 

### Impact Explanation

An attacker who observes a pre-EIP-155 signed transaction on Ethereum mainnet (or any other EVM chain) can submit the identical RLP-encoded bytes to Aurora's `submit` method. If the originating address holds ETH on Aurora and the nonce matches, the transaction executes and transfers ETH out of the victim's Aurora account to the destination encoded in the original transaction. This constitutes direct theft of user funds at rest.

**Impact: Critical — direct theft of user funds.**

### Likelihood Explanation

Pre-EIP-155 transactions remain in use (hardware wallets, legacy tooling, and some dApps still produce them). Aurora shares the same address space as Ethereum, so any user who has bridged ETH to Aurora and whose Aurora nonce matches a pre-EIP-155 transaction they signed elsewhere is vulnerable. The attack requires no special privilege: any NEAR account can call `submit`. The nonce-match requirement reduces but does not eliminate likelihood, particularly for accounts with nonce 0 that have never transacted on Aurora.

**Likelihood: Medium.**

### Recommendation

Reject pre-EIP-155 legacy transactions (those with `v = 27` or `v = 28`) at the engine boundary. The simplest fix is to treat a `None` chain ID as a validation failure in `submit_transaction`:

```rust
// Validate the chain ID, if provided inside the signature:
match transaction.chain_id {
    None => return Err(EngineErrorKind::InvalidChainId.into()),
    Some(chain_id) if U256::from(chain_id) != U256::from_big_endian(&state.chain_id) => {
        return Err(EngineErrorKind::InvalidChainId.into());
    }
    _ => {}
}
```

This aligns with the comment on the `submit` entrypoint itself: *"Must match `CHAIN_ID` to make sure it's signed for given chain vs replayed from another chain."* [5](#0-4) 

### Proof of Concept

1. On Ethereum mainnet, Alice signs a pre-EIP-155 transfer of 1 ETH to address `B` with nonce 0 (producing `v = 27`). The signed bytes contain no chain ID.
2. Alice bridges 1 ETH to Aurora; her Aurora address is identical to her Ethereum address and her Aurora nonce is 0.
3. Attacker calls Aurora's `submit` with the identical RLP-encoded transaction bytes.
4. `LegacyEthSignedTransaction::sender()` recovers Alice's address correctly (the signature is valid on any chain).
5. `transaction.chain_id` is `None`; the `if let Some(chain_id)` guard is skipped.
6. `check_nonce` passes (nonce 0 matches).
7. The EVM executes the transfer: 1 ETH leaves Alice's Aurora account and is credited to address `B` on Aurora — which the attacker controls. [6](#0-5) [7](#0-6)

### Citations

**File:** engine-transactions/src/legacy.rs (L63-84)
```rust
impl LegacyEthSignedTransaction {
    /// Returns sender of given signed transaction by doing ecrecover on the signature.
    pub fn sender(&self) -> Result<Address, Error> {
        let mut rlp_stream = RlpStream::new();
        // See details of CHAIN_ID computation here - https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#specification
        let (chain_id, rec_id) = match self.v {
            0..=26 | 29..=34 => return Err(Error::InvalidV),
            27..=28 => (
                None,
                u8::try_from(self.v - 27).map_err(|_e| Error::InvalidV)?,
            ),
            _ => (
                Some((self.v - 35) / 2),
                u8::try_from((self.v - 35) % 2).map_err(|_e| Error::InvalidV)?,
            ),
        };
        self.transaction
            .rlp_append_unsigned(&mut rlp_stream, chain_id);
        let message_hash = sdk::keccak(rlp_stream.as_raw());
        sdk::ecrecover(message_hash, &super::vrs_to_arr(rec_id, self.r, self.s))
            .map_err(|_| Error::EcRecover)
    }
```

**File:** engine-transactions/src/lib.rs (L106-118)
```rust
            Legacy(tx) => Self {
                address: tx.sender()?,
                chain_id: tx.chain_id(),
                nonce: tx.transaction.nonce,
                gas_limit: tx.transaction.gas_limit,
                max_priority_fee_per_gas: tx.transaction.gas_price,
                max_fee_per_gas: tx.transaction.gas_price,
                to: tx.transaction.to,
                value: tx.transaction.value,
                data: tx.transaction.data,
                access_list: vec![],
                authorization_list: vec![],
            },
```

**File:** engine/src/engine.rs (L1054-1063)
```rust
    // Validate the chain ID, if provided inside the signature:
    if let Some(chain_id) = transaction.chain_id
        && U256::from(chain_id) != U256::from_big_endian(&state.chain_id)
    {
        return Err(EngineErrorKind::InvalidChainId.into());
    }

    sdk::log!("signer_address {:?}", sender);

    check_nonce(&io, &sender, &transaction.nonce)?;
```

**File:** engine/src/contract_methods/evm_transactions.rs (L73-103)
```rust
#[named]
pub fn submit<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let tx_data = io.read_input().to_vec();
        let current_account_id = env.current_account_id();
        let relayer_address = predecessor_address(&env.predecessor_account_id());
        let args = SubmitArgs {
            tx_data,
            ..Default::default()
        };
        let result = engine::submit(
            io,
            env,
            &args,
            state,
            current_account_id,
            relayer_address,
            handler,
        )?;
        let result_bytes = borsh::to_vec(&result).map_err(|_| errors::ERR_SERIALIZE)?;
        io.return_output(&result_bytes);

        Ok(result)
    })
}
```

**File:** engine/src/lib.rs (L272-282)
```rust
    /// Process signed Ethereum transaction.
    /// Must match `CHAIN_ID` to make sure it's signed for given chain vs replayed from another chain.
    #[unsafe(no_mangle)]
    pub extern "C" fn submit() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::submit(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
