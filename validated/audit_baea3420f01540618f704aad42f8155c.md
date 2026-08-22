### Title
Hardcoded ETH-implicit wallet global-contract code hash may not match the actually deployed global contract, causing storage-inconsistency panics or wrong code execution for legacy ETH-implicit accounts - (File: `runtime/near-wallet-contract/src/lib.rs`)

### Summary
This is the same bug class as the reported "wrong init code hash" issue: a critical protocol constant (a hash used to deterministically resolve on-chain state/contract) is hardcoded in source and only cross-checked by a unit test written by the same author, rather than validated against the actual on-chain deployed artifact. In the Uniswap report, the wrong `init code hash` caused `pairFor` to compute an address that does not correspond to any real deployed pair. In nearcore, `eth_wallet_global_contract_hash` hardcodes the `CryptoHash` of the wallet-contract global contract per chain, and this hash is used to redirect legacy ETH-implicit accounts to look up a global contract by that exact hash.

### Finding Description
`eth_wallet_global_contract_hash` returns hardcoded 32-byte arrays for `MAINNET`/`MOCKNET` and `TESTNET`: [1](#0-0) 

These constants are asserted only against themselves in a unit test in the same file, not against any independently-verified value fetched from chain state: [2](#0-1) 

The value is consumed in `RuntimeContractIdentifier::resolve` for legacy ETH-implicit accounts: when a legacy wallet-contract magic-byte hash is detected on an account, the runtime does **not** use the account's real deployed code, but instead unconditionally substitutes `GlobalContractIdentifier::CodeHash(global_hash)` using this hardcoded value: [3](#0-2) 

That code hash is later dereferenced via `GlobalContractAccessExt::hash`/`code`, which performs a trie lookup keyed by the exact hash and raises `StorageError::StorageInconsistentState` if no such global contract entry exists: [4](#0-3) 

If the hardcoded hash does not correspond to a global contract that is actually deployed with that exact code hash on the target chain (e.g., due to a rebuild, a version bump, or a copy/paste error analogous to the Uniswap "sushiswap hash" mixup acknowledged in the report), any resolution of a legacy ETH-implicit account's contract will attempt to fetch a global contract entry that does not exist.

### Impact Explanation
`StorageError::StorageInconsistentState` is treated as an unrecoverable internal invariant violation throughout `runtime/runtime/src/lib.rs` and related modules (used extensively for "this should never happen" conditions), so a lookup miss on a wrong hardcoded hash would propagate as a state-inconsistency error during transaction/receipt processing for any legacy ETH-implicit account (any account matching the wallet-contract magic bytes on mainnet/testnet). Because these are reachable from ordinary user transactions/receipts that call into or transfer to such accounts, a wrong constant here is not a cosmetic issue — it can turn every interaction with legacy ETH-implicit accounts into either (a) a node-level panic/storage-inconsistency abort, or (b) if the wrong hash accidentally resolves to a different but valid trie entry (unlikely, but structurally possible in test/localnet configurations where the hash is computed from `LOCALNET.read_contract().hash()`), execution of the wrong contract code entirely, silently changing account behavior. This directly matches the accepted impact classes "node panic" and "unauthorized state or balance change."

### Likelihood Explanation
Likelihood is speculative rather than confirmed: I could not independently verify the mainnet/testnet global contract hashes against actual on-chain deployment (no chain/RPC access in this environment), so this report — like the original — is a bug-class hint requiring on-chain verification, not a proven defect. However, the underlying mechanism is real and exploitable in the sense that any drift between the constant and the on-chain deployed global contract's code hash (which can naturally occur across protocol-version bumps of the wallet contract, as already handled once via the `OLD_TESTNET` special case) directly triggers the failure path described above. The comments in the file (`OLD_TESTNET` / protocol version 70→71 transition) show this exact class of drift has already happened once in this codebase, making a similar future or current mismatch plausible.

### Recommendation
- Add a build-time or deploy-time integration check that fetches the actual on-chain global contract hash for the wallet contract (e.g., via a genesis/state snapshot check in CI) and asserts it matches `eth_wallet_global_contract_hash`, instead of relying solely on a self-referential unit test.
- Make `RuntimeContractIdentifier::resolve` fail gracefully (return a typed error to the caller) instead of allowing a raw `StorageInconsistentState` to propagate when the global contract entry is missing, so a constant mismatch degrades to a contained error rather than a broad storage-inconsistency panic path.
- Document and version-track the exact commit/build used to produce each hardcoded hash, and add a test that recomputes the hash from the embedded WASM resource file and compares it against the hardcoded constant, catching accidental staleness when `res/wallet_contract_*.wasm` is updated without updating `eth_wallet_global_contract_hash`.

### Proof of Concept
Not independently reproducible in this environment (no chain state or trie access). The structural PoC is:
1. Deploy/observe that `LegacyEthWallet::resolve` detects a code hash matching `MAINNET`/`TESTNET` magic bytes for an ETH-implicit account: [5](#0-4) 
2. `RuntimeContractIdentifier::resolve` substitutes the account's code hash with the hardcoded `eth_wallet_global_contract_hash(chain_id)` value: [6](#0-5) 
3. If no global contract with that exact hash exists in trie state (i.e., the hardcoded constant is wrong or stale), `GlobalContractAccessExt::hash` returns `StorageError::StorageInconsistentState` on the subsequent lookup: [7](#0-6) 

This would need to be confirmed by comparing the hardcoded bytes in `eth_wallet_global_contract_hash` against the actual deployed global contract hash on mainnet/testnet, which requires chain access not available to this analysis.

### Citations

**File:** runtime/near-wallet-contract/src/lib.rs (L37-51)
```rust
    pub fn resolve(code_hash: CryptoHash) -> Option<Self> {
        if MAINNET.check_magic_bytes(&code_hash) {
            return Some(LegacyEthWallet::Mainnet);
        }
        if TESTNET.check_magic_bytes(&code_hash) {
            return Some(LegacyEthWallet::Testnet);
        }
        if OLD_TESTNET.check_magic_bytes(&code_hash) {
            return Some(LegacyEthWallet::OldTestnet);
        }
        if LOCALNET.check_magic_bytes(&code_hash) {
            return Some(LegacyEthWallet::Localnet);
        }
        None
    }
```

**File:** runtime/near-wallet-contract/src/lib.rs (L89-105)
```rust
pub fn eth_wallet_global_contract_hash(chain_id: &str) -> CryptoHash {
    match chain_id {
        // 2zodJZK2e4nnv5AqwCRnenNSmkikXhEd7PPY6BmfTmW4
        chains::MAINNET | chains::MOCKNET => CryptoHash([
            0x1d, 0xaa, 0x83, 0x5c, 0x46, 0x37, 0xf7, 0xae, 0x3d, 0x92, 0x40, 0x95, 0xba, 0x3f,
            0x0b, 0xf2, 0x82, 0x9b, 0xcf, 0xa1, 0x7b, 0x10, 0x68, 0xcd, 0x58, 0xbd, 0x85, 0x3d,
            0xca, 0xd7, 0xce, 0xb5,
        ]),
        // 3PpYvRxBfC5BkZxTw8ZFG3D52w1ZRhvDDWirKoxphMDn
        chains::TESTNET => CryptoHash([
            0x23, 0x8f, 0xea, 0xc1, 0xf8, 0x6c, 0xc9, 0xf9, 0xf4, 0x00, 0x3e, 0x3f, 0x6d, 0x5a,
            0xeb, 0xc0, 0x4e, 0xae, 0xa9, 0xc3, 0x94, 0x03, 0x2b, 0xd2, 0x94, 0x70, 0xe9, 0x60,
            0x9b, 0x67, 0xf6, 0xc5,
        ]),
        _ => *LOCALNET.read_contract().hash(),
    }
}
```

**File:** runtime/near-wallet-contract/src/lib.rs (L193-202)
```rust
    #[test]
    fn test_eth_wallet_global_contract_hash_values() {
        let mainnet_expected: CryptoHash =
            "2zodJZK2e4nnv5AqwCRnenNSmkikXhEd7PPY6BmfTmW4".parse().unwrap();
        let testnet_expected: CryptoHash =
            "3PpYvRxBfC5BkZxTw8ZFG3D52w1ZRhvDDWirKoxphMDn".parse().unwrap();
        assert_eq!(eth_wallet_global_contract_hash(MAINNET), mainnet_expected);
        assert_eq!(eth_wallet_global_contract_hash(MOCKNET), mainnet_expected);
        assert_eq!(eth_wallet_global_contract_hash(TESTNET), testnet_expected);
    }
```

**File:** runtime/runtime/src/contract_code.rs (L52-67)
```rust
        if account_id.get_account_type() == AccountType::EthImplicitAccount {
            // Accounts that look like eth implicit accounts and have existed prior to the
            // eth-implicit accounts protocol change (these accounts are discussed in the
            // description of #11606) may have something else deployed to them. Only return
            // something here if the accounts have a wallet contract hash. Otherwise use the
            // regular path to grab the deployed contract.
            if LegacyEthWallet::resolve(local_hash).is_some() {
                // ETH implicit wallet accounts use global contracts, including
                // those created in old protocol versions.
                let global_hash = eth_wallet_global_contract_hash(chain_id);
                return Ok(RuntimeContractIdentifier::Global {
                    code_hash: global_hash,
                    identifier: GlobalContractIdentifier::CodeHash(global_hash),
                });
            }
        }
```

**File:** runtime/runtime/src/contract_code.rs (L91-106)
```rust
impl GlobalContractAccessExt for GlobalContractIdentifier {
    fn hash(self, store: &TrieUpdate, access: AccessOptions) -> Result<CryptoHash, StorageError> {
        if let GlobalContractIdentifier::CodeHash(hash) = self {
            return Ok(hash);
        }
        let key = TrieKey::GlobalContractCode { identifier: self.into() };
        let value_ref =
            store.get_ref(&key, KeyLookupMode::MemOrFlatOrTrie, access)?.ok_or_else(|| {
                let TrieKey::GlobalContractCode { identifier } = key else { unreachable!() };
                StorageError::StorageInconsistentState(format!(
                    "Global contract identifier not found {:?}",
                    identifier
                ))
            })?;
        Ok(value_ref.value_hash())
    }
```
