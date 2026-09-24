No vulnerability found for this question.

Investigation summary: the reported bug class requires a contract that (1) computes an expected counterparty address via a hash of parameters, (2) truncates that hash to fewer bits than are attacker-controlled (Uniswap V3: `keccak256` truncated from 256 bits to a 160-bit address), and (3) trusts `msg.sender` as being that counterparty solely because it matches the truncated address, without checking pool deployment/registration. I looked for an analogous pattern in `polkadot-sdk`:

- `pallet_asset_conversion`'s pool address derivation (`AccountIdConverter`/`AccountIdConverterNoSeed` in `substrate/frame/asset-conversion/src/types.rs:147-171`) hashes the `PoolId` with `blake2_256` (full 256-bit output) and decodes it directly into `AccountId`, with no truncation to a smaller identifier space comparable to EVM's `uint256`→`uint160` truncation. [1](#0-0) [2](#0-1) 
- Swaps are executed by the pallet calling `T::Assets::transfer`/`resolve` directly against the pool account it just computed (`credit_swap` in `substrate/frame/asset-conversion/src/lib.rs:1194-1243`); there is no external callback where an untrusted contract asserts "I am the pool" via `msg.sender` and the caller trusts that claim to release funds. [3](#0-2) 
- In `pallet-revive` precompiles (`ERC20`, `AssetConversion`), caller identity comes from `env.caller()`, which is supplied by the trusted execution stack itself, not from a self-reported address checked against a locally recomputed hash. [4](#0-3) [5](#0-4) 
- `pallet-revive`'s own address derivation (`create1`/`create2` in `substrate/frame/revive/src/address.rs:264-285`) is used for contract addresses, not for authenticating a counterparty in a flash-swap-style callback, and there is no code path where a contract's identity is trusted based on comparing `msg.sender` to a locally recomputed truncated hash.

There is no FRAME/XCM/pallet-revive entry point where an attacker-controlled contract can spoof a "pool" identity via a hash-truncation collision to drain allowances, so this Solidity-callback-trust bug class does not have a demonstrable Polkadot SDK analog.

### Citations

**File:** substrate/frame/asset-conversion/src/types.rs (L154-157)
```rust
	fn try_convert(id: &PoolId) -> Result<AccountId, &PoolId> {
		sp_io::hashing::blake2_256(&Encode::encode(&(Seed::get(), id))[..])
			.using_encoded(|e| Decode::decode(&mut TrailingZeroInput::new(e)).map_err(|_| id))
	}
```

**File:** substrate/frame/asset-conversion/src/types.rs (L167-170)
```rust
	fn try_convert(id: &PoolId) -> Result<AccountId, &PoolId> {
		sp_io::hashing::blake2_256(&Encode::encode(id)[..])
			.using_encoded(|e| Decode::decode(&mut TrailingZeroInput::new(e)).map_err(|_| id))
	}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1198-1219)
```rust
			let resolve_path = || -> Result<CreditOf<T>, DispatchError> {
				for pos in 0..=path.len() {
					if let Some([(asset1, _), (asset2, amount_out)]) = path.get(pos..=pos + 1) {
						let pool_from = T::PoolLocator::pool_address(asset1, asset2)
							.map_err(|_| Error::<T>::InvalidAssetPair)?;

						if let Some((asset3, _)) = path.get(pos + 2) {
							let pool_to = T::PoolLocator::pool_address(asset2, asset3)
								.map_err(|_| Error::<T>::InvalidAssetPair)?;

							T::Assets::transfer(
								asset2.clone(),
								&pool_from,
								&pool_to,
								*amount_out,
								Preserve,
							)?;
						} else {
							let credit_out =
								Self::withdraw(asset2.clone(), &pool_from, *amount_out, true)?;
							return Ok(credit_out);
						}
```

**File:** substrate/frame/asset-conversion/precompiles/src/lib.rs (L246-254)
```rust
	/// Returns the caller's account ID.
	fn caller_account_id(
		env: &impl Ext<T = Runtime>,
	) -> Result<<Runtime as frame_system::Config>::AccountId, Error> {
		env.caller()
			.account_id()
			.map_err(|_| Error::Revert(Revert { reason: ERR_INVALID_CALLER.into() }))
			.cloned()
	}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L223-229)
```rust
	/// Get the caller as an `H160` address.
	fn caller(env: &mut impl Ext<T = Runtime>) -> Result<H160, Error> {
		env.caller()
			.account_id()
			.map(<Runtime as pallet_revive::Config>::AddressMapper::to_address)
			.map_err(|_| Error::Revert(Revert { reason: ERR_INVALID_CALLER.into() }))
	}
```
