### Title
Native `value` attached to an ERC20 precompile call is unconditionally moved and permanently lost, mirroring the unchecked `msg.value` loss in `receiveFunds` - ([File: substrate/frame/revive/src/exec.rs])

### Summary
`pallet-revive`'s `ERC20` precompile (`substrate/frame/assets/precompiles/src/lib.rs`) exposes Solidity-ABI functions like `transfer`, `approve`, `transferFrom` that operate purely on `pallet-assets` balances and never inspect the native `value` attached to the call. However, the exec-stack framework in `substrate/frame/revive/src/exec.rs::run()` unconditionally moves any attached native `value` to the destination account *before* invoking the precompile logic, regardless of whether the target function is "payable". For a `HAS_CONTRACT_INFO = false` precompile such as `ERC20`, the destination account is a stateless fallback `AccountId32` derived from the fixed precompile address, which nobody can practically control. Any native value sent alongside an ERC20 `transfer`-style call is silently swallowed with no revert, no event, and no on-chain mechanism to recover it — the same "unchecked, mixed native+token funding channel causes accidental fund loss" bug class described in the reported `receiveFunds` issue.

### Finding Description
Root cause and reachable path:

1. **Entry point** – `pallet_revive::Pallet::call` (or `bare_call`/Ethereum-RPC `eth_sendTransaction`) is a normal signed-extrinsic entry point. Any account can dispatch a call with `dest = <ERC20 precompile address>`, an arbitrary `evm_value: U256`, and ABI-encoded `data` for `IERC20Calls::transfer(...)`. No privilege is required. [1](#0-0) 

2. **Unconditional value transfer** – Inside `ExecStack::run`, regardless of whether the destination is a regular contract or a precompile, and regardless of `HAS_CONTRACT_INFO`, the native `value_transferred` is moved to the destination account *before* the precompile's `call`/`call_with_info` is even invoked: [2](#0-1) 
   Only after that transfer does the framework decide whether to mint an ED / create contract info (only for `HAS_CONTRACT_INFO = true`) and then dispatch into the precompile: [3](#0-2) 

3. **Precompile never checks or rejects native value** – The `ERC20` precompile's `transfer` (and `approve`, `transferFrom`, etc.) implementation only manipulates `pallet_assets` balances via `do_transfer`; it never reads `env.value_transferred()` nor rejects a non-zero value: [4](#0-3) 
   The `Precompile` trait itself documents that `HAS_CONTRACT_INFO = false` precompiles (which `ERC20` is configured as — `const HAS_CONTRACT_INFO: bool = false;`) get **no account/state created** for them beyond what the framework does automatically: [5](#0-4) [6](#0-5) 

4. **Destination account is not practically controllable** – For `AccountId32Mapper`, an address with no stateful mapping resolves to the "fallback account", which is the same shape (`0xEE`-suffixed) as an eth-derived secp256k1 account: [7](#0-6) 
   The precompile's address is a fixed, hardcoded value (e.g. derived from an asset id via `AssetPrecompileConfig::MATCHER`), so its fallback `AccountId32` is not a real, key-controlled account — recovering the funds would require finding a secp256k1 private key whose address collides with this specific hardcoded H160, which is not feasible.

5. **Demonstrated mechanism** – The existing test `pure_precompile_works` explicitly sends non-zero native `value` (`100u64`) to `HAS_CONTRACT_INFO = false` builtin precompiles (ECRecover, Sha256, Identity, …) and asserts the value lands permanently on the precompile address's balance with no way back: [8](#0-7) 
   This is the same code path (`run()`'s unconditional `transfer_from_origin`) used for every `HAS_CONTRACT_INFO = false` precompile, including the `ERC20` precompile added in this codebase (`substrate/frame/assets/precompiles/src/lib.rs`), which has no code to move funds back out.

This is directly analogous to the reported `BountyCore.receiveFunds` bug: a function meant to handle only one funding channel (ERC20 tokens / native `msg.value`) does not validate that the *other* channel is zero, so a caller who attaches native value while intending a token-only operation permanently loses it.

### Impact Explanation
Any signed account that calls the `ERC20` precompile's `transfer`/`approve`/`transferFrom` while also attaching a non-zero native `value` (e.g. from a wallet UI mistake, a misconfigured dApp/script, or fee-estimation tooling that defaults `value` incorrectly) will have that native amount irrecoverably locked at the precompile's stateless fallback account. There is no revert, no event, and no extrinsic in `pallet-revive` or `pallet-assets` capable of moving funds out of that account. This is a genuine, unbounded (per-call) native-token loss for end users — a direct funds-loss bug, matching Medium severity for the analogous report.

### Likelihood Explanation
Likelihood is moderate: it requires the caller (or their tooling) to mistakenly or carelessly attach a non-zero `value` to a call whose ABI-decoded intent is purely an ERC20 operation. This is a very plausible operator/wallet-tooling mistake given that ERC20 precompiles present themselves as ordinary EVM-style contract addresses to Ethereum-compatible wallets, which always expose a `value` field independent of calldata. No attacker privilege, governance, or malicious peer is required — this is purely a self-inflicted user-funds loss enabled by a missing guard in the framework/precompile.

### Recommendation
- In `ExecStack::run` (`substrate/frame/revive/src/exec.rs`), reject calls with non-zero `value_transferred` targeting `HAS_CONTRACT_INFO = false` precompiles (or any precompile that does not explicitly declare itself "payable"), mirroring Solidity's automatic revert-on-value for non-payable functions.
- Alternatively/additionally, have precompiles such as `ERC20::transfer/approve/transferFrom` (`substrate/frame/assets/precompiles/src/lib.rs`) explicitly check `env.value_transferred() == 0` (or equivalent) at the top of each handler and revert otherwise, consistent with the audit recommendation for `receiveFunds`.

### Proof of Concept
- Deployment/config evidence: `ERC20` precompile is configured with `const HAS_CONTRACT_INFO: bool = false;` (`substrate/frame/assets/precompiles/src/lib.rs:147-167`), and its `transfer` handler performs only `pallet_assets::do_transfer` with no inspection of native value (`lib.rs:261-294`).
- Mechanism evidence (existing, passing test in-repo): `pure_precompile_works` in `substrate/frame/revive/src/tests/pvm.rs:4792-4823` sends `value = 100` alongside a call to a `HAS_CONTRACT_INFO=false` precompile and asserts `Pallet::<Test>::evm_balance(&precompile_addr) == U256::from(100)` — i.e., native value sent to a stateless precompile call is retained on that address's balance permanently, since no code exists there to move it.
- I did not execute a new integration test against the `ERC20` precompile specifically (no execution environment available in this session); the claim rests on tracing the exact same code path (`exec.rs::run`'s unconditional `transfer_from_origin` prior to `instance.call`) that the existing `pure_precompile_works` test already exercises and verifies for other `HAS_CONTRACT_INFO=false` precompiles, plus static review of `ERC20::transfer` showing it never checks or rejects attached native value. A minimal reproduction would extend `pure_precompile_works`-style setup: create an asset, call `bare_call` on the ERC20 precompile address with `evm_value = U256::from(100)` and `IERC20Calls::transfer` data, then assert (a) the ERC20 balance moved correctly and (b) `Pallet::<Test>::evm_balance(&precompile_addr) == U256::from(100)` with no extrinsic available to reclaim it — mirroring exactly the assertions already present at `substrate/frame/revive/src/tests/pvm.rs:4810-4814`.

### Citations

**File:** substrate/frame/revive/src/lib.rs (L1784-1807)
```rust
	pub fn bare_call(
		origin: OriginFor<T>,
		dest: H160,
		evm_value: U256,
		transaction_limits: TransactionLimits<T>,
		data: Vec<u8>,
		exec_config: &ExecConfig<T>,
	) -> ContractResult<ExecReturnValue, BalanceOf<T>> {
		let mut transaction_meter = match TransactionMeter::new(transaction_limits) {
			Ok(transaction_meter) => transaction_meter,
			Err(error) => return ContractResult { result: Err(error), ..Default::default() },
		};
		let mut storage_deposit = Default::default();

		let try_call = || {
			let origin = ExecOrigin::from_runtime_origin(origin)?;
			let result = ExecStack::<T, ContractBlob<T>>::run_call(
				origin.clone(),
				dest,
				&mut transaction_meter,
				evm_value,
				data,
				&exec_config,
			)?;
```

**File:** substrate/frame/revive/src/exec.rs (L1451-1463)
```rust
			// Every non delegate call or instantiate also optionally transfers the balance.
			// If it is a delegate call, then we've already transferred tokens in the
			// last non-delegate frame.
			if frame.delegate.is_none() {
				Self::transfer_from_origin(
					&self.origin,
					&caller,
					account_id,
					frame.value_transferred,
					&mut frame.frame_meter,
					self.exec_config,
				)?;
			}
```

**File:** substrate/frame/revive/src/exec.rs (L1465-1495)
```rust
			// We need to make sure that the pre-compiles contract exist before executing it.
			// A few more conditionals:
			// 	- Only contracts with extended API (has_contract_info) are guaranteed to have an
			//    account.
			//  - Only when not delegate calling we are executing in the context of the pre-compile.
			//    Pre-compiles itself cannot delegate call.
			if let Some(precompile) = executable.as_precompile() &&
				precompile.has_contract_info() &&
				frame.delegate.is_none() &&
				!<System<T>>::account_exists(account_id)
			{
				// prefix matching pre-compiles cannot have a contract info
				// hence we only mint once per pre-compile
				T::Currency::mint_into(account_id, T::Currency::minimum_balance())?;
				// make sure the pre-compile does not destroy its account by accident
				<System<T>>::inc_consumers(account_id)?;
			}

			let mut code_deposit = executable
				.as_executable()
				.map(|exec| exec.code_info().deposit())
				.unwrap_or_default();

			let mut output = match executable {
				ExecutableOrPrecompile::Executable(executable) => {
					executable.execute(self, entry_point, input_data)
				},
				ExecutableOrPrecompile::Precompile { instance, .. } => {
					instance.call(input_data, self)
				},
			}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L147-167)
```rust
impl<Runtime, PrecompileConfig, Instance: 'static> Precompile
	for ERC20<Runtime, PrecompileConfig, Instance>
where
	PrecompileConfig: AssetPrecompileConfig,
	Runtime: crate::Config<Instance> + pallet_revive::Config + permit::Config,
	<<PrecompileConfig as AssetPrecompileConfig>::AssetIdExtractor as AssetIdExtractor>::AssetId:
		Into<<Runtime as Config<Instance>>::AssetId>,
	Call<Runtime, Instance>: Into<<Runtime as pallet_revive::Config>::RuntimeCall>,
	alloy::primitives::U256: TryInto<<Runtime as Config<Instance>>::Balance>,
	alloy::primitives::U256: TryFrom<<Runtime as Config<Instance>>::Balance>,
{
	type T = Runtime;
	type Interface = IERC20::IERC20Calls;
	const MATCHER: AddressMatcher = PrecompileConfig::MATCHER;
	const HAS_CONTRACT_INFO: bool = false;

	fn call(
		address: &[u8; 20],
		input: &Self::Interface,
		env: &mut impl Ext<T = Self::T>,
	) -> Result<Vec<u8>, Error> {
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L261-294)
```rust
	/// Execute the transfer call.
	fn transfer(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		call: &IERC20::transferCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		env.charge(<Runtime as Config<Instance>>::WeightInfo::transfer())?;

		let from = Self::caller(env)?;
		let dest = <Runtime as pallet_revive::Config>::AddressMapper::to_account_id(
			&call.to.into_array().into(),
		);

		let f = TransferFlags { keep_alive: false, best_effort: false, burn_dust: false };
		pallet_assets::Pallet::<Runtime, Instance>::do_transfer(
			asset_id,
			&<Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&from),
			&dest,
			Self::to_balance(call.value)?,
			None,
			f,
		)?;

		Self::deposit_event(
			env,
			IERC20Events::Transfer(IERC20::Transfer {
				from: from.0.into(),
				to: call.to,
				value: call.value,
			}),
		)?;

		Ok(IERC20::transferCall::abi_encode_returns(&true))
	}
```

**File:** substrate/frame/revive/src/precompiles.rs (L182-221)
```rust
	const MATCHER: AddressMatcher;
	/// Defines whether this pre-compile needs a contract info data structure in storage.
	///
	/// Enabling it unlocks more APIs for the pre-compile to use. Only pre-compiles with a
	/// fixed matcher can set this to true. This is enforced at compile time. Reason is that
	/// contract info is per address and not per pre-compile. Too many contract info structures
	/// and accounts would be created otherwise.
	///
	/// # When set to **true**
	///
	/// - An account will be created at the pre-compiles address when it is called for the first
	///   time. The ed is minted.
	/// - Contract info data structure will be created in storage on first call.
	/// - Only `call_with_info` should be implemented. `call` is never called.
	///
	/// # When set to **false**
	///
	/// - No account or any other state will be created for the address.
	/// - Only `call` should be implemented. `call_with_info` is never called.
	///
	/// # What to use
	///
	/// Should be set to false if the additional functionality is not needed. A pre-compile with
	/// contract info will incur both a storage read and write to its contract metadata when called.
	///
	/// The contract info enables additional functionality:
	/// - Storage deposits: Collect deposits from the origin rather than the caller. This makes it
	///   easier for contracts to interact with the pre-compile as deposits
	/// 	are paid by the transaction signer (just like gas). It also makes refunding easier.
	/// - Contract storage: You can use the contracts key value child trie storage instead of
	///   providing your own state.
	/// 	The contract storage automatically takes care of deposits.
	/// 	Providing your own storage and using pallet_revive to collect deposits is also possible,
	/// though.
	/// - Instantitation: Contract instantiation requires the instantiator to have an account. This
	/// 	is because its nonce is used to derive the new contracts account id and child trie id.
	///
	/// Have a look at [`ExtWithInfo`] to learn about the additional APIs that a contract info
	/// unlocks.
	const HAS_CONTRACT_INFO: bool;
```

**File:** substrate/frame/revive/src/address.rs (L103-147)
```rust
/// The mapper to be used if the account id is `AccountId32`.
///
/// It converts between addresses by either hash then truncate the last 12 bytes or
/// suffixing them. To recover the original account id of a hashed and truncated account id we use
/// [`OriginalAccount`] and will fall back to all `0xEE` if account was found. This means contracts
/// and plain wallets controlled by an `secp256k1` always have a `0xEE` suffixed account.
pub struct AccountId32Mapper<T>(PhantomData<T>);

/// The mapper to be used if the account id is `H160`.
///
/// It just trivially returns its inputs and doesn't make use of any state.
#[allow(dead_code)]
pub struct H160Mapper<T>(PhantomData<T>);

/// An account mapper that can be used for testing u64 account ids.
pub struct TestAccountMapper<T>(PhantomData<T>);

impl<T> AddressMapper<T> for AccountId32Mapper<T>
where
	T: Config<AccountId = AccountId32>,
{
	fn to_address(account_id: &AccountId32) -> H160 {
		let account_bytes: &[u8; 32] = account_id.as_ref();
		if Self::is_eth_derived(account_id) {
			// this was originally an eth address
			// we just strip the 0xEE suffix to get the original address
			H160::from_slice(&account_bytes[..20])
		} else {
			// this is an (ed|sr)25510 derived address
			// avoid truncating the public key by hashing it first
			let account_hash = keccak_256(account_bytes);
			H160::from_slice(&account_hash[12..])
		}
	}

	fn to_account_id(address: &H160) -> AccountId32 {
		<OriginalAccount<T>>::get(address).unwrap_or_else(|| Self::to_fallback_account_id(address))
	}

	fn to_fallback_account_id(address: &H160) -> AccountId32 {
		let mut account_id = AccountId32::new([0xEE; 32]);
		let account_bytes: &mut [u8; 32] = account_id.as_mut();
		account_bytes[..20].copy_from_slice(address.as_bytes());
		account_id
	}
```

**File:** substrate/frame/revive/src/tests/pvm.rs (L4792-4823)
```rust
	for (description, precompile_addr, input, output) in cases {
		let (code, _code_hash) = compile_module("call_and_return").unwrap();
		ExtBuilder::default().build().execute_with(|| {
			let _ = <Test as Config>::Currency::set_balance(&ALICE, 100_000_000_000);
			let Contract { addr, .. } = builder::bare_instantiate(Code::Upload(code))
				.native_value(1_000)
				.build_and_unwrap_contract();

			let result = builder::bare_call(addr)
				.data(
					(&precompile_addr, 100u64)
						.encode()
						.into_iter()
						.chain(input)
						.collect::<Vec<_>>(),
				)
				.build_and_unwrap_result();

			assert_eq!(
				Pallet::<Test>::evm_balance(&precompile_addr),
				U256::from(100),
				"{description}: unexpected balance"
			);
			assert_eq!(
				alloy_core::hex::encode(result.data),
				alloy_core::hex::encode(output),
				"{description} Unexpected output for precompile: {precompile_addr:?}",
			);
			assert_eq!(result.flags, ReturnFlags::empty());
		});
	}
}
```
