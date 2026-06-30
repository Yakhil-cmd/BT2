### Title
Pre-EIP-155 Legacy Transactions Accepted Without Chain ID Validation Enables Cross-Chain Replay Attacks - (File: `engine/src/engine.rs`)

### Summary

The Aurora Engine's `submit` entrypoint accepts pre-EIP-155 legacy Ethereum transactions (those with `v = 27` or `v = 28`) without any chain ID validation. Because these transactions carry no chain ID in their signature, a signed transaction from Ethereum mainnet (or any other EVM chain) can be replayed verbatim on Aurora to drain the sender's Aurora ETH balance.

### Finding Description

The chain ID guard in `submit_with_alt_modexp` is written as an `if let Some(chain_id)` pattern: [1](#0-0) 

This guard fires **only** when `chain_id` is `Some`. It is entirely skipped when `chain_id` is `None`.

`chain_id` becomes `None` for any legacy transaction whose `v` field is `27` or `28`. The `sender()` function in `LegacyEthSignedTransaction` explicitly accepts these values and recovers the sender address without error: [2](#0-1) 

The companion `chain_id()` method returns `None` for the entire range `v = 0..=34`, which covers both `27` and `28`: [3](#0-2) 

When the `Legacy` variant is normalized into a `NormalizedEthTransaction`, `chain_id` is set directly from `tx.chain_id()`, propagating `None` into the engine: [4](#0-3) 

The result is that any pre-EIP-155 transaction — including every transaction ever broadcast on Ethereum before EIP-155 was activated — passes all validation in `submit_with_alt_modexp` and is executed by the EVM if the sender's nonce and balance on Aurora match.

Notably, `CHANGES.md` records that a fix for this exact class of issue was shipped in version 2.4.0: [5](#0-4) 

The current codebase does not enforce that fix: the `if let Some(chain_id)` guard is the only chain-ID check, and it is a no-op for `chain_id = None`.

### Impact Explanation

**Critical — Direct theft of user funds.**

An attacker who observes any pre-EIP-155 signed transaction on Ethereum (all such transactions are public on-chain) can submit the identical raw bytes to Aurora's `submit` or `submit_with_args` entrypoints. If the original sender holds ETH on Aurora and the nonce matches, the transaction executes: ETH is transferred, or an arbitrary contract call is made, without the sender's knowledge or consent. The attacker does not need the sender's private key.

### Likelihood Explanation

Pre-EIP-155 transactions are permanently recorded on Ethereum mainnet and are trivially retrievable. Any Aurora user whose address was active on Ethereum before EIP-155 (block 2,675,000, October 2016) and who also holds ETH on Aurora is a potential victim. The nonce requirement is a partial mitigant but is not a security guarantee: nonces reset to zero for new Aurora accounts, and many addresses have low nonces on both chains. The attack requires no special privileges, no private key material, and no on-chain setup beyond submitting a raw transaction.

### Recommendation

Reject legacy transactions that carry no chain ID. The simplest fix is to change the guard in `submit_with_alt_modexp` from an optional check to a mandatory one:

```rust
// Current (vulnerable):
if let Some(chain_id) = transaction.chain_id
    && U256::from(chain_id) != U256::from_big_endian(&state.chain_id)
{
    return Err(EngineErrorKind::InvalidChainId.into());
}

// Fixed:
match transaction.chain_id {
    None => return Err(EngineErrorKind::InvalidChainId.into()),
    Some(chain_id) if U256::from(chain_id) != U256::from_big_endian(&state.chain_id) => {
        return Err(EngineErrorKind::InvalidChainId.into());
    }
    _ => {}
}
```

Alternatively, `LegacyEthSignedTransaction::sender()` can be made to return `Err(Error::InvalidV)` for `v = 27` and `v = 28`, so that pre-EIP-155 transactions are rejected at parse time before they ever reach the engine.

### Proof of Concept

1. Locate any pre-EIP-155 Ethereum transaction (e.g., the genesis transaction `0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060`, which has `v = 28`).
2. Fund the sender address on Aurora with sufficient ETH and ensure the nonce matches.
3. Submit the raw transaction bytes unchanged to Aurora's `submit` endpoint:
   ```
   curl <aurora-rpc> -X POST -H "Content-Type: application/json" \
     --data '{"jsonrpc":"2.0","method":"eth_sendRawTransaction",
              "params":["<raw_pre_eip155_tx_hex>"],"id":1}'
   ```
4. The transaction executes successfully, transferring ETH from the victim's Aurora balance to the attacker's address, despite the attacker never possessing the victim's private key.

The `v = 27/28` path in `sender()` recovers the correct signer address, the nonce check passes, and the `if let Some(chain_id)` guard is skipped entirely because `chain_id` is `None`. [6](#0-5) [7](#0-6)

### Citations

**File:** engine/src/engine.rs (L1023-1059)
```rust
    #[cfg(feature = "contract")]
    let transaction = NormalizedEthTransaction::try_from(
        EthTransactionKind::try_from(args.tx_data.as_slice())
            .map_err(EngineErrorKind::FailedTransactionParse)?,
    )
    .map_err(|_e| EngineErrorKind::InvalidSignature)?;

    #[cfg(not(feature = "contract"))]
    // The standalone engine must use the backwards compatible parser to reproduce the NEAR state,
    // but the contract itself does not need to make such checks because it never executes historical
    // transactions.
    let transaction: NormalizedEthTransaction = {
        let adapter =
            aurora_engine_transactions::backwards_compatibility::EthTransactionKindAdapter::new(
                ZERO_ADDRESS_FIX_HEIGHT,
            );
        let block_height = env.block_height();
        let tx: EthTransactionKind = adapter
            .try_parse_bytes(args.tx_data.as_slice(), block_height)
            .map_err(EngineErrorKind::FailedTransactionParse)?;
        tx.try_into()
            .map_err(|_e| EngineErrorKind::InvalidSignature)?
    };
    // Retrieve the signer of the transaction:
    let sender = transaction.address;

    let fixed_gas = silo::get_fixed_gas(&io);

    // Check if the sender has rights to submit transactions or deploy code.
    assert_access(&io, env, &transaction)?;

    // Validate the chain ID, if provided inside the signature:
    if let Some(chain_id) = transaction.chain_id
        && U256::from(chain_id) != U256::from_big_endian(&state.chain_id)
    {
        return Err(EngineErrorKind::InvalidChainId.into());
    }
```

**File:** engine-transactions/src/legacy.rs (L68-78)
```rust
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
```

**File:** engine-transactions/src/legacy.rs (L88-93)
```rust
    pub const fn chain_id(&self) -> Option<u64> {
        match self.v {
            0..=34 => None,
            _ => Some((self.v - 35) / 2),
        }
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

**File:** CHANGES.md (L646-646)
```markdown
- Security improvement: Engine will no longer accept EVM transactions without a chain ID as part of their signature by [@birchmd]. This should have no impact on users as all modern Ethereum tooling includes the chain ID. ([#432])
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
