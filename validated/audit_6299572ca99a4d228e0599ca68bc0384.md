### Title
Hardcoded `ADDRESS_REGISTRAR_ACCOUNT_ID` in the ETH Wallet Contract is immutable and can DOS the address-check/EOA base-token-transfer path if the registrar account is ever redeployed - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

### Summary
The near-wallet-contract (the code deployed on every ETH-implicit account, per NEP-518) hardcodes the account ID of the address registrar contract as a compile-time constant baked into the contract's WASM binary, with no way to update it once deployed.

### Finding Description
`ADDRESS_REGISTRAR_ACCOUNT_ID` is loaded at compile time from a static file and used as a literal string constant inside the wallet contract logic: `const ADDRESS_REGISTRAR_ACCOUNT_ID: &str = std::include_str!("ADDRESS_REGISTRAR_ACCOUNT_ID");` [1](#0-0) , with the file itself containing the fixed value `address-map.near` [2](#0-1) .

This constant is parsed and used inside `inner_rlp_execute`, which is reached by any unprivileged user calling `rlp_execute` on their wallet contract (their own ETH-implicit account) to relay an Ethereum-emulated transaction. When the transaction kind is `EOABaseTokenTransfer` with a non-`None` `address_check`, the code builds a cross-contract call to the hardcoded registrar account: `let account_id = ADDRESS_REGISTRAR_ACCOUNT_ID.trim().parse().unwrap_or_else(|_| env::panic_str("Invalid address registrar")); ext_registrar::ext(account_id).with_static_gas(REGISTRAR_LOOKUP_GAS)` [3](#0-2) .

Unlike the `NOTE`/`cNote.underlying()` pattern recommended in the referenced report — where a mutable, on-chain-resolvable reference is used instead of a hardcoded address — here the registrar's account ID is fully static, baked directly into every deployed instance of the wallet-contract WASM across the network (mainnet, testnet, localnet — each with its own embedded binary and precomputed global-contract hash) [4](#0-3) [5](#0-4) . There is no on-chain indirection (such as a `CToken.underlying()`-style lookup) that would let the registrar's location be resolved dynamically; the only way to change it is to publish an entirely new wallet-contract WASM build and get the network to adopt the new global-contract hash via a protocol upgrade.

### Impact Explanation
If the `address-map.near` account is ever migrated, redeployed under a different account ID, or becomes unavailable, every call into the `EOABaseTokenTransfer` address-check branch across every ETH-implicit account on the network would fail (the cross-contract call to the now-stale/invalid account would error out), degrading that feature to a permanent no-op/failure until a new wallet-contract WASM version is shipped and adopted network-wide via a protocol upgrade. This is a network-wide DOS of a specific transaction path (base-token transfers to a target requiring an address check) rather than a single dApp being affected, since the wallet contract is used by potentially many ETH-implicit accounts and the constant cannot be patched per-account.

### Likelihood Explanation
Low probability event (the registrar account being redeployed elsewhere is a deliberate governance/ops decision, not something that happens spontaneously), but if it does happen the impact is deterministic and unavoidable without a full protocol-level contract redeploy — mirroring exactly the judged severity reasoning in the referenced report (rare event, but real design risk called out explicitly, and contract-upgradability is not accepted as a severity mitigant).

### Recommendation
Avoid hardcoding the registrar account ID directly in contract logic. Consider resolving the registrar address through a mutable on-chain reference (e.g., a small on-chain "current registrar" pointer contract/account maintained by protocol governance, analogous to `CToken.underlying()`), or make the wallet-contract aware of registrar migrations through a protocol-governed constant that can be updated without requiring a full wallet-contract WASM redeploy and hash-remap for every chain.

### Proof of Concept
Not applicable in the traditional sense — this is a design/config immutability issue rather than an exploitable state-manipulation bug. The reachable path is: any account holder submits an `rlp_execute` transaction whose decoded Ethereum transaction is a base-token transfer requiring an address check `TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer { address_check: Some(address), .. })` [6](#0-5) ; this deterministically triggers a call to the fixed `ADDRESS_REGISTRAR_ACCOUNT_ID`, which would fail network-wide for this transaction kind if that account were ever moved/redeployed.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L26-27)
```rust
const MICRO_NEAR: u128 = 10_u128.pow(18);
const ADDRESS_REGISTRAR_ACCOUNT_ID: &str = std::include_str!("ADDRESS_REGISTRAR_ACCOUNT_ID");
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L413-416)
```rust
        TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
            address_check: Some(address),
            ..
        }) => {
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L418-425)
```rust
            let ext = WalletContract::ext(current_account_id).with_static_gas(callback_gas);
            let address_registrar = {
                let account_id = ADDRESS_REGISTRAR_ACCOUNT_ID
                    .trim()
                    .parse()
                    .unwrap_or_else(|_| env::panic_str("Invalid address registrar"));
                ext_registrar::ext(account_id).with_static_gas(REGISTRAR_LOOKUP_GAS)
            };
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/ADDRESS_REGISTRAR_ACCOUNT_ID (L1-1)
```text
address-map.near
```

**File:** runtime/near-wallet-contract/src/lib.rs (L6-20)
```rust
static MAINNET: WalletContract =
    WalletContract::new(include_bytes!("../res/wallet_contract_mainnet.wasm"));

static TESTNET: WalletContract =
    WalletContract::new(include_bytes!("../res/wallet_contract_testnet.wasm"));

/// Initial version of WalletContract. It was released to testnet, but not mainnet.
/// We still use this one on testnet protocol version 70 for consistency.
/// Example account:
/// https://testnet.nearblocks.io/address/0xcc5a584f545b2ca3ebacc1346556d1f5b82b8fc6
static OLD_TESTNET: WalletContract =
    WalletContract::new(include_bytes!("../res/wallet_contract_testnet_pv70.wasm"));

static LOCALNET: WalletContract =
    WalletContract::new(include_bytes!("../res/wallet_contract_localnet.wasm"));
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
