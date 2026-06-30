### Title
Cross-Chain Replay of Pre-EIP-155 Legacy Transactions Accepted Without Chain-ID Binding - (File: engine/src/engine.rs)

### Summary

Aurora Engine intentionally accepts pre-EIP-155 legacy transactions (those with `v = 27` or `v = 28`) that carry no chain-ID in their signed message. The chain-ID validation gate in `submit_with_alt_modexp` is guarded by `if let Some(chain_id) = transaction.chain_id`, so when `chain_id` is `None` the check is silently skipped. Because Aurora is deployed on three distinct networks (mainnet chain-ID 1313161554, testnet 1313161555, local 1313161556), a signed pre-EIP-155 transaction that is valid on one network is cryptographically identical and immediately replayable on every other Aurora network where the sender's nonce matches.

### Finding Description

`LegacyEthSignedTransaction::sender()` in `engine-transactions/src/legacy.rs` decodes the `v` field and, for `v ∈ {27, 28}`, sets `chain_id = None` and reconstructs the signing hash from only the six-field RLP tuple `(nonce, gas_price, gas_limit, to, value, data)` — no chain identifier is included. [1](#0-0) 

`NormalizedEthTransaction::chain_id` is therefore `None` for these transactions. [2](#0-1) 

In `submit_with_alt_modexp`, the only chain-ID enforcement is:

```rust
if let Some(chain_id) = transaction.chain_id
    && U256::from(chain_id) != U256::from_big_endian(&state.chain_id)
{
    return Err(EngineErrorKind::InvalidChainId.into());
}
``` [3](#0-2) 

When `chain_id` is `None` the entire block is skipped; the engine proceeds to `check_nonce` and then executes the transaction. The nonce check prevents replay on the *same* network, but provides no protection across the three distinct Aurora deployments.

The decision to re-allow pre-EIP-155 transactions was made in v2.6.0 for EIP-1820 compatibility: [4](#0-3) 

### Impact Explanation

**Critical — Direct theft of user funds.**

If a user signs a pre-EIP-155 legacy transaction on Aurora testnet (e.g., to deploy EIP-1820 or interact with a contract that requires it) and that transaction is observed by an attacker, the attacker can submit the identical raw bytes to Aurora mainnet. If the sender's nonce on mainnet equals the nonce in the transaction, the engine will execute it — transferring ETH or invoking arbitrary contract logic — without the user's consent on mainnet. The victim's mainnet ETH balance is directly at risk.

### Likelihood Explanation

**Low-to-Medium.** Pre-EIP-155 transactions are uncommon with modern tooling, but they are explicitly supported and documented as valid inputs. Developers deploying EIP-1820 or using legacy tooling will produce them. Aurora mainnet and testnet share the same address space (same private keys, same derivation paths), so a user who has interacted on testnet at nonce N and later reaches nonce N on mainnet is immediately vulnerable if an attacker captured the testnet transaction. The attacker's only requirement is to observe a pre-EIP-155 transaction on any Aurora network and submit it to another.

### Recommendation

1. **Reject pre-EIP-155 transactions at the `submit` entry point** unless a specific, separately-gated method (e.g., `submit_eip1820`) is used, so the attack surface is minimised.
2. Alternatively, if pre-EIP-155 support must remain, add a secondary check: if `transaction.chain_id` is `None`, verify that the transaction's `to` address is the canonical EIP-1820 deployer address and that the sender is the known EIP-1820 key, rejecting all other chain-ID-free transactions.
3. Document the cross-chain replay risk prominently so integrators are aware.

### Proof of Concept

1. On Aurora **testnet** (chain-ID 1313161555), sign a legacy ETH transfer with `v = 27` (no EIP-155):
   ```
   tx = { nonce: N, gas_price: P, gas_limit: G, to: VICTIM, value: V, data: [] }
   signed_bytes = rlp(nonce, gas_price, gas_limit, to, value, data, 27, r, s)
   ```
2. Submit `signed_bytes` to Aurora **mainnet** (chain-ID 1313161554) via `submit`.
3. `EthTransactionKind::try_from` parses it as `Legacy` with `v = 27`.
4. `sender()` recovers the address using the six-field hash (no chain-ID).
5. `transaction.chain_id` is `None`; the `if let Some(chain_id)` guard at `engine.rs:1055` is not entered.
6. `check_nonce` passes if the sender's mainnet nonce equals `N`.
7. The engine executes the transfer, draining `V` ETH from the sender's mainnet account. [5](#0-4) [6](#0-5)

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

**File:** CHANGES.md (L586-586)
```markdown
- Original ETH transactions which do not contain a Chain ID are allowed again to allow for use of [EIP-1820] by [@joshuajbouw]. ([#520])
```
