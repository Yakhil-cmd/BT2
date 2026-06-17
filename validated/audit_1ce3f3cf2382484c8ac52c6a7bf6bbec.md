### Title
Cross-Chain Replay of Pre-EIP-155 (Unprotected) Legacy Transactions Accepted Without Chain-ID Binding — (`File: basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/legacy_tx.rs`)

---

### Summary

ZKsync OS explicitly accepts pre-EIP-155 ("unprotected") legacy transactions whose signing hash contains no chain ID. A transaction signed on Ethereum mainnet (or any other EVM chain) without EIP-155 protection can be submitted to ZKsync OS and will be accepted and executed if the sender's nonce and balance match, constituting a cross-chain replay attack that can drain user funds.

---

### Finding Description

In `LegacyPayloadParser::try_parse_and_hash_for_signature_verification`, the code branches on whether the signature is EIP-155-protected:

```rust
let sig_hash: Bytes32 = if legacy_signature.is_eip155() == false {
    // Unprotected legacy — NO chain ID in the hash
    let mut hasher = crypto::sha3::Keccak256::new();
    apply_list_concatenation_encoding_to_hash(inner_slice.len() as u32, &mut hasher);
    hasher.update(inner_slice);
    hasher.finalize_reset().into()
} else {
    // EIP-155 protected: chain ID is included
    ...
}
``` [1](#0-0) 

`is_eip155()` returns `false` when `v == 27 || v == 28`, i.e., the pre-EIP-155 case: [2](#0-1) 

The unprotected signing hash is `keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data]))` — identical to the original Ethereum pre-EIP-155 format, with no chain ID, no network identifier, and no ZKsync OS-specific domain separator. The parsed transaction is stored as the `RlpEncodedTxInner::Legacy` variant and proceeds through full validation and execution: [3](#0-2) 

The signature is then verified against this chain-ID-free hash in the Ethereum validation flow: [4](#0-3) 

---

### Impact Explanation

An attacker who obtains a pre-EIP-155 transaction previously broadcast on Ethereum mainnet (or any other EVM chain) can replay it verbatim on ZKsync OS. If the victim's ZKsync OS account nonce matches the nonce in the old transaction and the account holds sufficient balance, the transaction executes — transferring value or invoking contracts as if the victim had authorized it on ZKsync OS. This results in direct, unauthorized loss of user funds on ZKsync OS.

The attack is especially realistic for fresh ZKsync OS accounts (nonce = 0): any pre-EIP-155 transaction with nonce = 0 signed on any chain is immediately replayable.

---

### Likelihood Explanation

Pre-EIP-155 transactions are rare but not absent. They were common before 2016 and are still producible by wallets that do not enforce EIP-155. The attacker's entry path is fully unprivileged: submit a raw transaction to the ZKsync OS sequencer. No special access, oracle manipulation, or governance control is required. The only constraint is finding a victim whose ZKsync OS nonce matches a pre-EIP-155 transaction they previously signed on another chain.

---

### Recommendation

Reject pre-EIP-155 (unprotected) legacy transactions at the parsing stage. ZKsync OS is a new chain with no historical pre-EIP-155 transaction history, so there is no backward-compatibility reason to accept them. The `RlpEncodedTxInner::Legacy` variant (unprotected) should be treated as `InvalidTransaction::InvalidChainId` or a new `MissingChainId` error, while `RlpEncodedTxInner::LegacyWithEIP155` continues to be accepted normally.

---

### Proof of Concept

1. On Ethereum mainnet (or any EVM chain), sign a legacy transaction with `v = 27` or `v = 28` (pre-EIP-155) from address `A` with nonce `N`, sending ETH to address `B`.
2. Fund address `A` on ZKsync OS such that its nonce is also `N`.
3. Submit the raw RLP-encoded transaction bytes to ZKsync OS.
4. ZKsync OS parses it as `RlpEncodedTxInner::Legacy`, computes the same chain-ID-free signing hash, recovers address `A` via `ecrecover`, and executes the transaction — transferring funds from `A` to `B` on ZKsync OS without `A`'s consent.

The root cause is at: [5](#0-4)

### Citations

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/legacy_tx.rs (L89-115)
```rust
        let sig_hash: Bytes32 = if legacy_signature.is_eip155() == false {
            // Unprotected legacy
            let mut hasher = crypto::sha3::Keccak256::new();
            apply_list_concatenation_encoding_to_hash(inner_slice.len() as u32, &mut hasher);
            hasher.update(inner_slice);
            hasher.finalize_reset().into()
        } else {
            // EIP-155 protected legacy: v must match 35 + 2*chainId (+ {0,1})
            let min_v = U256::from(35) + U256::from(expected_chain_id) * U256::from(2);
            if !(legacy_signature.v == min_v || legacy_signature.v == min_v + U256::ONE) {
                return Err(InvalidTransaction::InvalidEncoding.into());
            }

            // Compute signing hash over the 6-field payload plus chainId and two empty strings.
            let chain_id = expected_chain_id;
            let chain_id_encoding_len = u64_encoding_len(chain_id);

            let mut hasher = crypto::sha3::Keccak256::new();
            apply_list_concatenation_encoding_to_hash(
                (inner_slice.len() + chain_id_encoding_len + 2) as u32, // 0x80, 0x80 for r/s
                &mut hasher,
            );
            hasher.update(inner_slice);
            apply_u64_encoding_to_hash(chain_id, &mut hasher);
            hasher.update(&[0x80, 0x80]);
            hasher.finalize_reset().into()
        };
```

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/transaction_types/legacy_tx.rs (L128-131)
```rust
impl<'a> LegacySignatureData<'a> {
    pub fn is_eip155(&self) -> bool {
        self.v != 27 && self.v != 28
    }
```

**File:** basic_bootloader/src/bootloader/transaction/rlp_encoded/mod.rs (L127-134)
```rust
            let tx = if sig_data.is_eip155() {
                Self::LegacyWithEIP155(tx, sig_data)
            } else {
                Self::Legacy(tx, sig_data)
            };

            Ok((tx, sig_hash))
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L201-245)
```rust
    if !Config::VALIDATE_EOA_SIGNATURE | Config::SIMULATION {
        // No native for Eth STF
    } else {
        if U256::from_be_slice(s) > U256::from_be_bytes(SECP256K1N_HALF) {
            return Err(InvalidTransaction::MalleableSignature.into());
        }

        let mut ecrecover_input = [0u8; 128];
        ecrecover_input[0..32].copy_from_slice(suggested_signed_hash.as_u8_array_ref());
        ecrecover_input[63] = (parity as u8) + 27;
        ecrecover_input[64..96][(32 - r.len())..].copy_from_slice(r);
        ecrecover_input[96..128][(32 - s.len())..].copy_from_slice(s);

        let mut ecrecover_output = ArrayBuilder::default();
        // We already charged gas for ecrecover in intrinsic cost, so we only need to charge native resources here.
        tx_resources
            .main_resources
            .with_infinite_ergs(|resources| {
                S::SystemFunctions::secp256k1_ec_recover(
                    ecrecover_input.as_slice(),
                    &mut ecrecover_output,
                    resources,
                    system.get_allocator(),
                )
                .map_err(SystemError::from)
            })?;

        if ecrecover_output.is_empty() {
            return Err(InvalidTransaction::IncorrectFrom {
                recovered: B160::ZERO,
                tx: from,
            }
            .into());
        }

        let recovered_from = B160::try_from_be_slice(&ecrecover_output.build()[12..])
            .ok_or(internal_error!("Invalid ecrecover return value"))?;

        if recovered_from != from {
            return Err(InvalidTransaction::IncorrectFrom {
                recovered: recovered_from,
                tx: from,
            }
            .into());
        }
```
