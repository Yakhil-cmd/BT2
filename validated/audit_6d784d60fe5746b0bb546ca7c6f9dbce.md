No vulnerability found for this question.

The fastify CVE concerns HTTP-specific routing internals: plugin-encapsulated prefixes, a shared "not-found handler" pointer resolved before URL decoding, and the resulting skip of a route's `preHandler` hook. Polkadot SDK's dispatch model has no structural analog to "URL prefix encapsulation," "not-found handler," or "decode-before-route" ordering — FRAME calls are dispatched by SCALE-decoded `RuntimeCall` variants with per-pallet-attached filters/origins, not by string-path routing with shared fallback pointers.

I looked for candidate analogs in fallback/bypass-filter dispatch paths, including:
- `pallet-utility`'s `if_else`/`dispatch_as`/`dispatch_as_fallible`, which explicitly apply `ensure_root` or origin filters before bypassing, not skipping them [1](#0-0) [2](#0-1) 
- `pallet-revive`'s `dispatch_as_fallback_account`, which requires `ensure_signed` on the real origin before dispatching under the fallback account — no shared/pre-decode dispatch pointer bypasses this check [3](#0-2) 
- XCM `Barrier`/`ShouldExecute`/`DenyRecursively` chains, which are evaluated per-message against the full decoded XCM before any transact/dispatch occurs, with no encapsulated-prefix-style shared fallback handler [4](#0-3) 
- The `TransactionExtension`/`CheckedExtrinsic` pipeline, where every extrinsic format (`Bare`/`Signed`/`General`) is validated and prepared through its own extension pipeline before dispatch — there is no single shared "unauthenticated fallback" pointer that a malformed payload could redirect to [5](#0-4) 

None of these exhibit the fastify bug's core defect (a single shared handler reference dispatched before input normalization, bypassing the target's own lifecycle hooks across an isolation boundary). No exploitable analog was found.

### Citations

**File:** substrate/frame/utility/src/lib.rs (L370-378)
```rust
		pub fn dispatch_as(
			origin: OriginFor<T>,
			as_origin: Box<T::PalletsOrigin>,
			call: Box<<T as Config>::RuntimeCall>,
		) -> DispatchResult {
			ensure_root(origin)?;

			let res = call.dispatch_bypass_filter((*as_origin).into());

```

**File:** substrate/frame/utility/src/lib.rs (L501-523)
```rust
		pub fn if_else(
			origin: OriginFor<T>,
			main: Box<<T as Config>::RuntimeCall>,
			fallback: Box<<T as Config>::RuntimeCall>,
		) -> DispatchResultWithPostInfo {
			// Do not allow the `None` origin.
			if ensure_none(origin.clone()).is_ok() {
				return Err(BadOrigin.into());
			}

			let is_root = ensure_root(origin.clone()).is_ok();

			// Track the weights
			let mut weight = T::WeightInfo::if_else();

			let main_info = main.get_dispatch_info();

			// Execute the main call first
			let main_result = if is_root {
				main.dispatch_bypass_filter(origin.clone())
			} else {
				main.dispatch(origin.clone())
			};
```

**File:** substrate/frame/revive/src/lib.rs (L1746-1757)
```rust
		pub fn dispatch_as_fallback_account(
			mut origin: OriginFor<T>,
			call: Box<<T as Config>::RuntimeCall>,
		) -> DispatchResultWithPostInfo {
			Self::ensure_non_contract_if_signed(&origin)?;
			let account_id = origin.as_signer().ok_or(DispatchError::BadOrigin)?;
			let unmapped_account = T::AddressMapper::to_fallback_account_id(
				&T::AddressMapper::to_address(&account_id),
			);
			origin.set_caller_from(RawOrigin::Signed(unmapped_account));
			call.dispatch(origin)
		}
```

**File:** polkadot/xcm/xcm-builder/src/barriers.rs (L602-611)
```rust
/// Denies execution if the XCM contains instructions not meant to run on this chain,
/// first checking at the top-level and then **recursively**.
///
/// This barrier only applies to **locally executed** XCM instructions (`SetAppendix`,
/// `SetErrorHandler`, and `ExecuteWithOrigin`). Remote parts of the XCM are expected to be
/// validated by the receiving chain's barrier.
///
/// Note: Ensures that restricted instructions do not execute on the local chain, enforcing stricter
/// execution policies while allowing remote chains to enforce their own rules.
pub struct DenyRecursively<Inner>(PhantomData<Inner>);
```

**File:** substrate/primitives/runtime/src/generic/checked_extrinsic.rs (L82-149)
```rust
impl<AccountId, Call, ExtensionV0, ExtensionOtherVersions, RuntimeOrigin> traits::Applyable
	for CheckedExtrinsic<AccountId, Call, ExtensionV0, ExtensionOtherVersions>
where
	AccountId: Member + MaybeDisplay,
	Call: Member + Dispatchable<RuntimeOrigin = RuntimeOrigin> + Encode,
	ExtensionV0: TransactionExtension<Call>,
	ExtensionOtherVersions: Pipeline<Call>,
	RuntimeOrigin: From<Option<AccountId>> + AsTransactionAuthorizedOrigin,
{
	type Call = Call;

	#[allow(deprecated)]
	fn validate<I: crate::traits::ValidateUnsigned<Call = Self::Call>>(
		&self,
		source: TransactionSource,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> TransactionValidity {
		match self.format {
			ExtrinsicFormat::Bare => {
				let inherent_validation = I::validate_unsigned(source, &self.function)?;
				let legacy_validation = ExtensionV0::bare_validate(&self.function, info, len)?;
				Ok(legacy_validation.combine_with(inherent_validation))
			},
			ExtrinsicFormat::Signed(ref signer, ref extension) => {
				let origin = Some(signer.clone()).into();
				extension
					.validate_only(origin, &self.function, info, len, source, EXTENSION_V0_VERSION)
					.map(|x| x.0)
			},
			ExtrinsicFormat::General(ref extension) => {
				extension.validate_only(None.into(), &self.function, info, len, source)
			},
		}
	}

	#[allow(deprecated)]
	fn apply<I: crate::traits::ValidateUnsigned<Call = Self::Call>>(
		self,
		info: &DispatchInfoOf<Self::Call>,
		len: usize,
	) -> crate::ApplyExtrinsicResultWithInfo<PostDispatchInfoOf<Self::Call>> {
		match self.format {
			ExtrinsicFormat::Bare => {
				I::pre_dispatch(&self.function)?;
				// TODO: Separate logic from `TransactionExtension` into a new `InherentExtension`
				// interface.
				ExtensionV0::bare_validate_and_prepare(&self.function, info, len)?;
				let res = self.function.dispatch(None.into());
				let mut post_info = res.unwrap_or_else(|err| err.post_info);
				let pd_res = res.map(|_| ()).map_err(|e| e.error);
				// TODO: Separate logic from `TransactionExtension` into a new `InherentExtension`
				// interface.
				ExtensionV0::bare_post_dispatch(info, &mut post_info, len, &pd_res)?;
				Ok(res)
			},
			ExtrinsicFormat::Signed(signer, extension) => extension.dispatch_transaction(
				Some(signer).into(),
				self.function,
				info,
				len,
				EXTENSION_V0_VERSION,
			),
			ExtrinsicFormat::General(extension) => {
				extension.dispatch_transaction(None.into(), self.function, info, len)
			},
		}
	}
```
