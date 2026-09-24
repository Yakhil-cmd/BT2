No vulnerability found for this question.

Explanation of the investigation: the report concerns EIP-712 `DOMAIN_SEPARATOR` being computed with a hardcoded `chainId` that becomes stale after a chain hard-fork (an EVM-specific mechanic where `block.chainid` can legitimately change post-fork).

Looking for a Polkadot SDK analog, the closest structural match is the ERC-2612-style permit implementation in `pallet-assets-precompiles`, where the EIP-712 domain separator is computed using a compile-time runtime constant `T::ChainId: Get<u64>` rather than any dynamic on-chain value: [1](#0-0) 

This `ChainId` is set identically to `pallet_revive::Config::ChainId`, which is documented as an EIP-155-style identifier "preventing replay attacks," but is a fixed `Get<u64>` constant baked into the runtime at compile time: [2](#0-1) 

Different production runtimes deliberately use distinct constants (e.g., `ConstU64<420_420_421>` on Asset Hub Westend, `ConstU64<420_420_999>` on Penpal), so signature collisions across live networks are not attacker-reachable without a governance/config choice to reuse identical values: [3](#0-2) [4](#0-3) 

Separately, FRAME's actual signed-extrinsic replay protection (`frame_system::CheckGenesis`, `CheckSpecVersion`, `CheckTxVersion`, `CheckMortality`) is already computed dynamically from live chain state at signing/validation time rather than being a hardcoded constant, so the exact vulnerability class described in the report (a domain separator frozen at an earlier point that becomes invalid after a fork) does not apply there: [5](#0-4) [6](#0-5) 

The only place where a chain identifier is "hardcoded" (the permit `ChainId`) requires either (a) a governance/runtime-upgrade action to change it post-fork, which is a privileged prerequisite explicitly excluded from scope, or (b) two independently-operated chains coincidentally choosing the same `ChainId` plus matching `verifying_contract`/token name — a config-only/deployment-choice scenario, also excluded. No attacker-controlled, privilege-free, reachable path produces a demonstrable loss under the stated constraints.

### Citations

**File:** substrate/frame/assets/precompiles/src/permit.rs (L148-178)
```rust
		/// Compute the EIP-712 domain separator for a given verifying contract.
		///
		/// DOMAIN_SEPARATOR = keccak256(abi.encode(
		///   keccak256("EIP712Domain(string name,string version,uint256 chainId,address
		/// verifyingContract)"),
		///   keccak256(name),
		///   keccak256("1"),
		///   chainId,
		///   verifyingContract
		/// ))
		///
		/// The `name` parameter should be the token name per EIP-2612 specification.
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

**File:** substrate/frame/revive/src/lib.rs (L330-339)
```rust
		/// The [EIP-155](https://eips.ethereum.org/EIPS/eip-155) chain ID.
		///
		/// This is a unique identifier assigned to each blockchain network,
		/// preventing replay attacks.
		#[pallet::constant]
		type ChainId: Get<u64>;

		/// The ratio between the decimal representation of the native token and the ETH token.
		#[pallet::constant]
		type NativeToEthRatio: Get<u32>;
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1418-1418)
```rust
	type ChainId = ConstU64<420_420_421>;
```

**File:** cumulus/parachains/runtimes/testing/penpal/src/lib.rs (L789-789)
```rust
	type ChainId = ConstU64<420_420_999>;
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

**File:** substrate/frame/system/src/extensions/check_mortality.rs (L60-72)
```rust
impl<T: Config + Send + Sync> TransactionExtension<T::RuntimeCall> for CheckMortality<T> {
	const IDENTIFIER: &'static str = "CheckMortality";
	type Implicit = T::Hash;

	fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
		let current_u64 = <Pallet<T>>::block_number().saturated_into::<u64>();
		let n = self.0.birth(current_u64).saturated_into::<BlockNumberFor<T>>();
		if !<BlockHash<T>>::contains_key(n) {
			Err(InvalidTransaction::AncientBirthBlock.into())
		} else {
			Ok(<Pallet<T>>::block_hash(n))
		}
	}
```
