## Analog Found: Static `pallet_revive::Config::ChainId` in EIP-712 Domain Separator Enables Cross-Fork Permit Replay

The reported DODO bug is a EIP-712 `DOMAIN_SEPARATOR` computed once from `chainid` and hardcoded, so it silently becomes wrong (and replayable) if the network hard-forks. The `pallet-assets-precompiles` crate in this repo reimplements EIP-2612 `permit()` for ERC-20 precompiles and has the exact same structural flaw: the chain ID baked into the domain separator is a Rust-level `Get<u64>` compile-time constant, not anything tied to the specific network instance (unlike `frame_system::CheckGenesis`, which re-reads the live genesis hash on every validation).

### Title
Hard-fork replay of EIP-2612 `permit()` signatures in `pallet-assets-precompiles` due to static `ChainId` constant in `DOMAIN_SEPARATOR` - ([File: substrate/frame/assets/precompiles/src/permit.rs])

### Summary
`permit::Pallet::compute_domain_separator` builds the EIP-712 domain separator using `T::ChainId::get()` [1](#0-0) , where `ChainId` is a pallet-constant fixed by the runtime's `Config` impl, e.g. `ConstU64<420_420_421>` for Asset Hub Westend [2](#0-1) . This value is baked into the compiled runtime WASM itself, not derived from any chain-specific, at-genesis or at-runtime state such as the genesis hash. If two independently operating chains ever share this runtime code (a governance/consensus hard fork that splits one network into two, both continuing to run the identical spec), both chains carry the identical `ChainId` constant, so a `permit()` signature valid on one side remains fully valid — and replayable — on the other.

### Finding Description
`pallet_revive::Config::ChainId` is documented as "a unique identifier assigned to each blockchain network, preventing replay attacks" [3](#0-2) , and is indeed used for EIP-155-style anti-replay when validating raw Ethereum transactions dispatched through `eth_transact`: `if chain_id != <T as Config>::ChainId::get().into() { ... return Err(InvalidTransaction::Call) }` [4](#0-3) .

The same constant is reused, unmodified, as the `chainId` component of the EIP-2612 permit domain separator computed by `permit::Pallet::<Runtime>::compute_domain_separator`:
```
let chain_id = T::ChainId::get();
data.extend_from_slice(&DOMAIN_TYPEHASH);
data.extend_from_slice(&name_hash);
data.extend_from_slice(&version_hash);
data.extend_from_slice(&chain_id.to_be_bytes());   // static, compile-time constant
data.extend_from_slice(verifying_contract.as_bytes());
``` [1](#0-0) 

Unlike native signed extrinsics, which are protected from cross-fork replay by `frame_system::CheckGenesis`, whose `implicit()` re-reads the *live* genesis block hash at validation time (`Pallet::block_hash(BlockNumberFor::<T>::zero())`) [5](#0-4) , the `permit()` precompile path performs signature verification entirely inside `permit::Pallet` with no dependency whatsoever on genesis hash, spec version, or any other chain-instance-specific value — only on the static `ChainId` constant, the `verifying_contract` address, and the token `name`. Both are compiled into the runtime and are therefore identical across any two chains running the same runtime binary, exactly as the reported EVM contract's `DOMAIN_SEPARATOR` remains identical across two forked EVM chains sharing the same deployed bytecode/storage.

`permit()` is reachable by anyone: it is invoked as an ERC20 precompile call (`IERC20Calls::permit`) with no signed-extrinsic origin requirement — any caller can submit any third party's previously-observed signed `permit` payload [6](#0-5) . Its state is guarded only by a `Nonces` double-map keyed on `(verifying_contract, owner)` [7](#0-6) , which is ordinary chain storage — it diverges independently on the two sides of a fork, so a not-yet-consumed nonce/signature pair remains simultaneously valid and unused on both post-fork chains.

### Impact Explanation
If a governance/community hard fork splits a Parity-maintained chain (e.g. an Asset Hub) into two independently operating networks that both continue to run the same runtime code (and hence the identical static `ChainId` constant), any previously signed but not-yet-submitted (or submitted-only-on-one-side) `permit()` approval remains valid on the sibling chain. An observer/relayer (no privileged role, no stolen keys) can simply resubmit the intercepted signature+payload on the other chain to grant the same spender the same allowance there, potentially enabling unauthorized token transfers on the side the signer never intended to authorize. This mirrors the cited report's medium-severity rationale: impact is real but contingent on the external, rare event of a hard fork.

### Likelihood Explanation
Low likelihood, matching the cited report: it requires an actual governance/consensus-level hard fork event splitting the chain while the runtime binary (and thus the compiled `ChainId` constant) stays identical on both sides — an event outside attacker control, exactly as in the original report's "contingent on external factors such as a hard fork" framing.

### Recommendation
Bind the EIP-712 domain separator (and/or the permit nonce namespace) to something that actually diverges across a fork — e.g., incorporate the live genesis hash (as `frame_system::CheckGenesis` already does for ordinary extrinsics) or the current block/finalized state root into `compute_domain_separator`, rather than relying solely on the compile-time `T::ChainId::get()` constant.

### Proof of Concept
No PoC was executed. This finding is a structural code-level analog derived purely from static analysis of `compute_domain_separator`'s exclusive reliance on the compile-time `ChainId` constant [1](#0-0)  and the absence of any genesis-hash/instance-specific binding compared to `CheckGenesis` [5](#0-4) . Reproducing it end-to-end would require actually forking a live chain (out of scope per the task's "do not execute against public networks" constraint), so this is reported as an unverified, code-evidenced analog rather than a demonstrated exploit.

### Citations

**File:** substrate/frame/assets/precompiles/src/permit.rs (L94-110)
```rust
	/// Nonces for permit signatures.
	/// Mapping: (verifying_contract, owner_address) => nonce
	///
	/// Uses Blake2_128Concat for the first key to prevent storage collision attacks
	/// when the verifying_contract address could be influenced by an attacker.
	///
	/// Note: EIP-2612 specifies uint256 nonce. We store as U256 for compatibility.
	#[pallet::storage]
	pub type Nonces<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		H160, // verifying contract address (precompile address)
		Blake2_128Concat,
		H160, // owner ethereum address
		U256, // nonce (EIP-2612 uses uint256)
		ValueQuery,
	>;
```

**File:** substrate/frame/assets/precompiles/src/permit.rs (L160-178)
```rust
		pub fn compute_domain_separator(verifying_contract: &H160, name: &[u8]) -> H256 {
			let name_hash = keccak_256(name);
			let version_hash = keccak_256(b"1");
			let chain_id = T::ChainId::get();

			// Encode: typehash || name_hash || version_hash || chainId || verifyingContract
			let mut data = Vec::with_capacity(DOMAIN_SEPARATOR_ENCODED_LEN);
			data.extend_from_slice(&DOMAIN_TYPEHASH);
			data.extend_from_slice(&name_hash);
			data.extend_from_slice(&version_hash);
			// Pad chain_id to 32 bytes (big-endian)
			data.extend_from_slice(&[0u8; 24]);
			data.extend_from_slice(&chain_id.to_be_bytes());
			// Pad address to 32 bytes
			data.extend_from_slice(&[0u8; 12]);
			data.extend_from_slice(verifying_contract.as_bytes());

			H256(keccak_256(&data))
		}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1418-1418)
```rust
	type ChainId = ConstU64<420_420_421>;
```

**File:** substrate/frame/revive/src/lib.rs (L330-335)
```rust
		/// The [EIP-155](https://eips.ethereum.org/EIPS/eip-155) chain ID.
		///
		/// This is a unique identifier assigned to each blockchain network,
		/// preventing replay attacks.
		#[pallet::constant]
		type ChainId: Get<u64>;
```

**File:** substrate/frame/revive/src/evm/call.rs (L85-97)
```rust
		match (self.chain_id, self.r#type.as_ref()) {
			(None, Some(super::Byte(TYPE_LEGACY))) => {},
			(Some(chain_id), ..) => {
				if chain_id != <T as Config>::ChainId::get().into() {
					log::debug!(target: LOG_TARGET, "Invalid chain_id {chain_id:?}");
					return Err(InvalidTransaction::Call);
				}
			},
			(None, ..) => {
				log::debug!(target: LOG_TARGET, "Invalid chain_id None");
				return Err(InvalidTransaction::Call);
			},
		}
```

**File:** substrate/frame/system/src/extensions/check_genesis.rs (L56-61)
```rust
impl<T: Config + Send + Sync> TransactionExtension<T::RuntimeCall> for CheckGenesis<T> {
	const IDENTIFIER: &'static str = "CheckGenesis";
	type Implicit = T::Hash;
	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		Ok(<Pallet<T>>::block_hash(BlockNumberFor::<T>::zero()))
	}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L196-200)
```rust
			IERC20Calls::permit(call) => Self::permit(asset_id, contract_addr, call, env),
			IERC20Calls::nonces(call) => Self::nonces(contract_addr, call, env),
			IERC20Calls::DOMAIN_SEPARATOR(_) => {
				Self::domain_separator(asset_id, contract_addr, env)
			},
```
