### Title
NEP-141 to ERC-20 Token Mapping Is Immutable and Cannot Be Updated or Removed - (File: `engine/src/engine.rs`)

### Summary

The Aurora Engine enforces a one-time-only registration of NEP-141 ↔ ERC-20 token mappings. Once a NEP-141 token is mapped to an ERC-20 address, neither the owner nor any admin can update or remove the mapping. If the underlying NEP-141 contract on NEAR is deprecated, replaced, or becomes non-functional, users holding the corresponding ERC-20 tokens on Aurora will be permanently unable to bridge their tokens back to NEAR, resulting in a permanent freeze of those funds.

### Finding Description

The `register_token` method in `Engine` explicitly rejects any attempt to re-register a NEP-141 token that already has a mapping: [1](#0-0) 

```rust
match get_erc20_from_nep141(&self.io, &nep141_token) {
    ...
    Ok(_) => return Err(RegisterTokenError::TokenAlreadyRegistered),
}
```

The underlying storage structure is `BijectionMap` (`engine/src/map.rs`), which only exposes `insert`, `lookup_left`, and `lookup_right` — there is **no `remove` or `update` method**: [2](#0-1) 

There is no contract-level admin function to remove or update the NEP-141 ↔ ERC-20 mapping. The `TransactionKind` enum lists every supported admin operation and contains no `RemoveErc20Token` or `UpdateErc20Token` variant: [3](#0-2) 

The `ExitToNear` precompile's `exit_erc20_token_to_near` function resolves the NEP-141 account from the immutable mapping and then calls `ft_transfer` (or `ft_transfer_call`) on it: [4](#0-3) [5](#0-4) 

Similarly, `receive_erc20_tokens` (called from `ft_on_transfer`) resolves the ERC-20 address from the same immutable mapping: [6](#0-5) 

### Impact Explanation

If a NEP-141 token contract on NEAR is deprecated, replaced, or becomes non-functional after its ERC-20 mirror has been deployed on Aurora:

1. The `ExitToNear` precompile will continue to call `ft_transfer` on the stale NEP-141 account, which will fail.
2. Users holding ERC-20 tokens on Aurora cannot bridge them back to NEAR.
3. There is no admin path to update or remove the stale mapping.
4. The ERC-20 tokens are permanently frozen on Aurora with no recovery mechanism.

**Impact: High — Permanent freezing of user funds.**

### Likelihood Explanation

NEP-141 contracts on NEAR can be deprecated, migrated to new account IDs, or become non-functional due to governance decisions, contract upgrades, or account deletion. This is a realistic operational scenario for any long-lived bridged token. The probability is non-trivial over the lifetime of the protocol.

### Recommendation

1. Add a `remove` method to `BijectionMap` in `engine/src/map.rs` that deletes both the forward (`Nep141Erc20Map`) and reverse (`Erc20Nep141Map`) storage entries.
2. Add an owner-only `remove_erc20_token` (or `update_erc20_token`) contract method that calls this `remove` (or `remove` + `insert`) on the bijection map.
3. Remove or relax the `TokenAlreadyRegistered` guard in `register_token`, or introduce a separate `update_token` path that bypasses it for the owner.

### Proof of Concept

1. Owner calls `deploy_erc20_token` with NEP-141 account `token.near`; ERC-20 is deployed at `0xABC` and the mapping `token.near → 0xABC` is written to storage.
2. Users bridge tokens from NEAR to Aurora via `ft_on_transfer`; ERC-20 balances accumulate at `0xABC`.
3. The NEP-141 contract `token.near` is deprecated on NEAR (e.g., migrated to `token-v2.near`).
4. A user calls the `ExitToNear` precompile to bridge their ERC-20 tokens back to NEAR.
5. `exit_erc20_token_to_near` calls `get_nep141_from_erc20(0xABC)` → returns `token.near` from the immutable mapping.
6. The precompile schedules `ft_transfer` on `token.near`, which fails because the contract is deprecated.
7. The user's ERC-20 tokens are burned (or the call reverts), but no NEP-141 tokens are received — funds are frozen.
8. The owner attempts to fix this by calling `deploy_erc20_token` again with `token-v2.near` pointing to `0xABC`, but `register_token` returns `ERR_NEP141_TOKEN_ALREADY_REGISTERED` for the old mapping and there is no remove path. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** engine/src/engine.rs (L722-741)
```rust
    pub fn register_token(
        &mut self,
        erc20_token: Address,
        nep141_token: AccountId,
    ) -> Result<(), RegisterTokenError> {
        match get_erc20_from_nep141(&self.io, &nep141_token) {
            Err(GetErc20FromNep141Error::Nep141NotFound) => (),
            Err(GetErc20FromNep141Error::InvalidNep141AccountId) => {
                return Err(RegisterTokenError::InvalidNep141AccountId);
            }
            Err(GetErc20FromNep141Error::InvalidAddress) => {
                return Err(RegisterTokenError::InvalidAddress);
            }
            Ok(_) => return Err(RegisterTokenError::TokenAlreadyRegistered),
        }

        let erc20_token = ERC20Address(erc20_token);
        let nep141_token = NEP141Account(nep141_token);
        nep141_erc20_map(self.io).insert(&nep141_token, &erc20_token);
        Ok(())
```

**File:** engine/src/engine.rs (L824-824)
```rust
        let erc20_token = get_erc20_from_nep141(&self.io, token)?;
```

**File:** engine/src/map.rs (L1-58)
```rust
use aurora_engine_sdk::io::{IO, StorageIntermediate};
use aurora_engine_types::storage::KeyPrefix;

pub use crate::prelude::{PhantomData, Vec, bytes_to_key};

/// A map storing a 1:1 relation between elements of types L and R.
/// The map is backed by storage of type I.
pub struct BijectionMap<L, R, I> {
    left_prefix: KeyPrefix,
    right_prefix: KeyPrefix,
    io: I,
    left_phantom: PhantomData<L>,
    right_phantom: PhantomData<R>,
}

impl<L: AsRef<[u8]> + TryFrom<Vec<u8>>, R: AsRef<[u8]> + TryFrom<Vec<u8>>, I: IO>
    BijectionMap<L, R, I>
{
    pub const fn new(left_prefix: KeyPrefix, right_prefix: KeyPrefix, io: I) -> Self {
        Self {
            left_prefix,
            right_prefix,
            io,
            left_phantom: PhantomData,
            right_phantom: PhantomData,
        }
    }

    pub fn insert(&mut self, left: &L, right: &R) {
        let key = self.left_key(left);
        self.io.write_storage(&key, right.as_ref());

        let key = self.right_key(right);
        self.io.write_storage(&key, left.as_ref());
    }

    pub fn lookup_left(&self, left: &L) -> Option<R> {
        let key = self.left_key(left);
        self.io
            .read_storage(&key)
            .and_then(|v| v.to_vec().try_into().ok())
    }

    pub fn lookup_right(&self, right: &R) -> Option<L> {
        let key = self.right_key(right);
        self.io
            .read_storage(&key)
            .and_then(|v| v.to_vec().try_into().ok())
    }

    fn left_key(&self, left: &L) -> Vec<u8> {
        bytes_to_key(self.left_prefix, left.as_ref())
    }

    fn right_key(&self, right: &R) -> Vec<u8> {
        bytes_to_key(self.right_prefix, right.as_ref())
    }
}
```

**File:** engine-standalone-storage/src/sync/types.rs (L88-182)
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum TransactionKind {
    /// Raw Ethereum transaction submitted to the engine
    Submit(EthTransactionKind),
    /// Raw Ethereum transaction with additional arguments submitted to the engine
    SubmitWithArgs(engine::SubmitArgs),
    /// Ethereum transaction triggered by a NEAR account
    Call(engine::CallArgs),
    /// Administrative method that makes a subset of precompiles paused
    PausePrecompiles(engine::PausePrecompilesCallArgs),
    /// Administrative method that resumes previously paused subset of precompiles
    ResumePrecompiles(engine::PausePrecompilesCallArgs),
    /// Input here represents the EVM code used to create the new contract
    Deploy(Vec<u8>),
    /// New bridged token
    DeployErc20(engine::DeployErc20TokenArgs),
    /// Callback for the `deploy_erc20_token` method
    DeployErc20Callback(AccountId),
    /// This type of transaction can impact the aurora state because of the bridge
    FtOnTransfer(connector::FtOnTransferArgs),
    /// Bytes here will be parsed into `aurora_engine::proof::Proof`
    Deposit(Vec<u8>),
    /// This can change balances on aurora in the case that `receiver_id == aurora`.
    /// Example: <https://explorer.mainnet.near.org/transactions/DH6iNvXCt5n5GZBZPV1A6sLmMf1EsKcxXE4uqk1cShzj>
    FtTransferCall(connector::FtTransferCallArgs),
    /// FinishDeposit-type receipts are created by calls to `deposit`
    FinishDeposit(connector::FinishDepositArgs),
    /// ResolveTransfer-type receipts are created by calls to `ft_on_transfer`
    ResolveTransfer(connector::FtResolveTransferArgs, types::PromiseResult),
    /// `ft_transfer` (related to eth-connector)
    FtTransfer(connector::FtTransferArgs),
    /// Function to take ETH out of Aurora
    Withdraw(connector::WithdrawCallArgs),
    /// FT storage standard method
    StorageDeposit(connector::StorageDepositArgs),
    /// FT storage standard method
    StorageUnregister(Option<bool>),
    /// FT storage standard method
    StorageWithdraw(connector::StorageWithdrawArgs),
    /// Admin only method; used to transfer administration
    SetOwner(engine::SetOwnerArgs),
    /// Admin only method; used to change upgrade delay blocks
    SetUpgradeDelayBlocks(engine::SetUpgradeDelayBlocksArgs),
    /// Set pause flags to eth-connector
    SetPausedFlags(connector::PauseEthConnectorArgs),
    /// Ad entry mapping from address to relayer NEAR account
    RegisterRelayer(Address),
    /// Callback called by `ExitToNear` precompile, also can refund on fail
    ExitToNear(Option<connector::ExitToNearPrecompileCallbackArgs>),
    /// Update eth-connector config
    SetConnectorData(connector::SetContractDataCallArgs),
    /// Initialize eth-connector
    NewConnector(connector::InitCallArgs),
    /// Set account id of the external eth-connector.
    SetEthConnectorContractAccount(connector::SetEthConnectorContractAccountArgs),
    /// Initialize Engine
    NewEngine(engine::NewCallArgs),
    /// Update xcc-router bytecode
    FactoryUpdate(Vec<u8>),
    /// Update the version of a deployed xcc-router contract
    FactoryUpdateAddressVersion(AddressVersionUpdateArgs),
    FactorySetWNearAddress(Address),
    FundXccSubAccount(FundXccArgs),
    /// Self-call used during XCC flow to move wNEAR tokens to user's XCC account
    WithdrawWnearToRouter(WithdrawWnearToRouterArgs),
    /// Pause the contract
    PauseContract,
    /// Resume the contract
    ResumeContract,
    /// Set the relayer key manager
    SetKeyManager(engine::RelayerKeyManagerArgs),
    /// Add a new relayer public function call access key
    AddRelayerKey(engine::RelayerKeyArgs),
    /// Callback which stores the relayer public function call access key into the storage
    StoreRelayerKeyCallback(engine::RelayerKeyArgs),
    /// Remove the relayer public function call access key
    RemoveRelayerKey(engine::RelayerKeyArgs),
    StartHashchain(engine::StartHashchainArgs),
    /// Set metadata of ERC-20 contract.
    SetErc20Metadata(connector::SetErc20MetadataArgs),
    /// Silo operations
    SetFixedGas(silo::FixedGasArgs),
    SetErc20FallbackAddress(silo::Erc20FallbackAddressArgs),
    SetSiloParams(Option<silo::SiloParamsArgs>),
    AddEntryToWhitelist(silo::WhitelistArgs),
    AddEntryToWhitelistBatch(Vec<silo::WhitelistArgs>),
    RemoveEntryFromWhitelist(silo::WhitelistArgs),
    SetWhitelistStatus(silo::WhitelistStatusArgs),
    SetWhitelistsStatuses(Vec<silo::WhitelistStatusArgs>),
    /// Callback which mirrors existed ERC-20 contract deployed on the main contract.
    MirrorErc20TokenCallback(connector::MirrorErc20TokenArgs),
    /// Sentinel kind for cases where a NEAR receipt caused a
    /// change in Aurora state, but we failed to parse the Action.
    Unknown,
```

**File:** engine-precompiles/src/native.rs (L302-309)
```rust
fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            .map(|s| s.to_vec())
            .ok_or(ExitError::Other(Cow::Borrowed(ERR_TARGET_TOKEN_NOT_FOUND)))?,
    )
    .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_INVALID_NEP141_ACCOUNT")))
}
```

**File:** engine-precompiles/src/native.rs (L582-584)
```rust
    let erc20_address = context.caller; // because ERC-20 contract calls the precompile.
    let nep141_account_id = get_nep141_from_erc20(erc20_address.as_bytes(), io)?;

```

**File:** engine/src/errors.rs (L28-28)
```rust
pub const ERR_NEP141_TOKEN_ALREADY_REGISTERED: &[u8] = b"ERR_NEP141_TOKEN_ALREADY_REGISTERED";
```
