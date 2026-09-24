No vulnerability found for this question.

The original report describes a configuration-only issue in a Go-Ethereum fork (Overprotocol): default `ChainID` values matching Ethereum mainnet/testnets and hardcoded Ethereum bootnode ENRs in `params/config.go` and `params/bootnodes.go`, which could allow transaction replay between chains due to shared chain identifiers in an EVM-style signing scheme.

This bug class does not translate to Polkadot SDK for two independent reasons:

1. **Structural mismatch**: Substrate/FRAME does not use an EVM-style numeric `ChainID` for replay protection. Instead, `frame_system::CheckGenesis` binds every signed extrinsic's implicit payload to the actual genesis block hash of the chain [1](#0-0) , combined with `CheckSpecVersion`/`CheckTxVersion`/`CheckMortality` extensions [2](#0-1) . Since genesis hashes are cryptographically derived from actual chain state rather than a hardcoded small integer, there is no equivalent "default value collision" surface — two independently created chains cannot accidentally share a genesis hash the way they can share a small default `ChainID` constant.

2. **Category exclusion**: Any residual analog in Polkadot SDK would only manifest as hardcoded bootnode multiaddrs/peer IDs in JSON chain-spec files (e.g. `cumulus/parachains/chain-specs/*.json`, `cumulus/scripts/create_*_spec.sh`) [3](#0-2)  or CLI defaults for bootnodes/build-spec [4](#0-3) . These are all config/chain-spec data, explicitly excluded under the scan method's rule against "config-only... dependency-only findings," and they carry no attacker-controlled input, no user-facing extrinsic/XCM entry point, and no reachable mutation of consensus state.

No demonstrable FRAME/XCM analog with an attacker-controlled entry point, missing check, and measurable loss was found.

### Citations

**File:** substrate/frame/system/src/extensions/check_genesis.rs (L27-61)
```rust
/// Genesis hash check to provide replay protection between different networks.
///
/// # Transaction Validity
///
/// Note that while a transaction with invalid `genesis_hash` will fail to be decoded,
/// the extension does not affect any other fields of `TransactionValidity` directly.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CheckGenesis<T: Config + Send + Sync>(core::marker::PhantomData<T>);

impl<T: Config + Send + Sync> core::fmt::Debug for CheckGenesis<T> {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "CheckGenesis")
	}

	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut core::fmt::Formatter) -> core::fmt::Result {
		Ok(())
	}
}

impl<T: Config + Send + Sync> CheckGenesis<T> {
	/// Creates new `TransactionExtension` to check genesis hash.
	pub fn new() -> Self {
		Self(core::marker::PhantomData)
	}
}

impl<T: Config + Send + Sync> TransactionExtension<T::RuntimeCall> for CheckGenesis<T> {
	const IDENTIFIER: &'static str = "CheckGenesis";
	type Implicit = T::Hash;
	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		Ok(<Pallet<T>>::block_hash(BlockNumberFor::<T>::zero()))
	}
```

**File:** docs/sdk/src/reference_docs/transaction_extensions.rs (L8-24)
```rust
//! - [`CheckGenesis`](frame_system::CheckGenesis): Ensures that a transaction was sent for the same
//!   network. Determined based on genesis.
//!
//! - [`CheckMortality`](frame_system::CheckMortality): Extends a transaction with a configurable
//!   mortality.
//!
//! - [`CheckNonZeroSender`](frame_system::CheckNonZeroSender): Ensures that the sender of a
//!   transaction is not the *all zero account* (all bytes of the accountid are zero).
//!
//! - [`CheckNonce`](frame_system::CheckNonce): Extends a transaction with a nonce to prevent replay
//!   of transactions and to provide ordering of transactions.
//!
//! - [`CheckSpecVersion`](frame_system::CheckSpecVersion): Ensures that a transaction was built for
//!   the currently active runtime.
//!
//! - [`CheckTxVersion`](frame_system::CheckTxVersion): Ensures that the transaction signer used the
//!   correct encoding of the call.
```

**File:** cumulus/parachains/chain-specs/people-westend.json (L1-12)
```json
{
  "name": "Westend People",
  "id": "people-westend",
  "chainType": "Live",
  "bootNodes": [
    "/dns/westend-people-collator-node-0.parity-testnet.parity.io/tcp/30333/p2p/12D3KooWDcLjDLTu9fNhmas9DTWtqdv8eUbFMWQzVwvXRK7QcjHD",
    "/dns/westend-people-collator-node-1.parity-testnet.parity.io/tcp/30333/p2p/12D3KooWM56JbKWAXsDyWh313z73aKYVMp1Hj2nSnAKY3q6MnoC9",
    "/dns/westend-people-collator-node-0.parity-testnet.parity.io/tcp/30335/ws/p2p/12D3KooWDcLjDLTu9fNhmas9DTWtqdv8eUbFMWQzVwvXRK7QcjHD",
    "/dns/westend-people-collator-node-1.parity-testnet.parity.io/tcp/30335/ws/p2p/12D3KooWM56JbKWAXsDyWh313z73aKYVMp1Hj2nSnAKY3q6MnoC9",
    "/dns/westend-people-collator-node-0.parity-testnet.parity.io/tcp/443/wss/p2p/12D3KooWDcLjDLTu9fNhmas9DTWtqdv8eUbFMWQzVwvXRK7QcjHD",
    "/dns/westend-people-collator-node-1.parity-testnet.parity.io/tcp/443/wss/p2p/12D3KooWM56JbKWAXsDyWh313z73aKYVMp1Hj2nSnAKY3q6MnoC9"
  ],
```

**File:** substrate/client/cli/src/commands/build_spec_cmd.rs (L40-44)
```rust
	/// Disable adding the default bootnode to the specification.
	/// By default the `/ip4/127.0.0.1/tcp/30333/p2p/NODE_PEER_ID` bootnode is added to the
	/// specification when no bootnode exists.
	#[arg(long)]
	pub disable_default_bootnode: bool,
```
