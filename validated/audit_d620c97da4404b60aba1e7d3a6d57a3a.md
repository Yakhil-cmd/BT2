No vulnerability found for this question.

The reported CVE describes a web-application authentication flaw: an admin-privileged mlflow API path allows creating a new user account with no password, weakening that account's login security. This bug class presupposes a username/password authentication model with a distinct "account creation" step that can omit credential material.

Polkadot SDK/FRAME has no analogous concept. Accounts are not "created" with credentials by an admin — they are cryptographic keypairs, and authorization for any dispatchable call is proven via a valid signature over the extrinsic (`ensure_signed`) rather than a stored password. I checked several places where something resembling "add a credential/key to an account" exists:

- `pallet_session::set_keys` requires an explicit `ownership_proof_is_valid` check before persisting `NextKeys`, so keys cannot be attached to a validator ID without proof of key ownership. [1](#0-0) 
- `pallet_people::set_personal_id_account` similarly requires the caller to already control the personal identity (`ensure_personal_identity`) and validates account availability before binding. [2](#0-1) 
- `pallet_purchase::create_account` is root/`validity_origin`-gated and still requires a valid signature (`InvalidSignature` check) before an account entry is created. [3](#0-2) 

In every case, "account creation"/"credential attachment" either requires a signature-based proof of key ownership or is not a privilege-escalation vector comparable to a password-less login. There is no code path where a privileged origin can register a new account/authority whose subsequent authentication check is silently skipped or defaults to "no credential required," which is the core invariant violated in PYSEC-2025-17. No genuine FRAME/XCM/contracts analog exists for this bug class.

### Citations

**File:** substrate/frame/session/src/lib.rs (L704-713)
```rust
		pub fn set_keys(origin: OriginFor<T>, keys: T::Keys, proof: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(
				who.using_encoded(|who| keys.ownership_proof_is_valid(who, &proof)),
				Error::<T>::InvalidProof,
			);

			Self::do_set_keys(&who, keys)?;
			Ok(())
		}
```

**File:** substrate/frame/people/src/lib.rs (L1009-1023)
```rust
		pub fn set_personal_id_account(
			origin: OriginFor<T>,
			account: T::AccountId,
			call_valid_at: BlockNumberFor<T>,
		) -> DispatchResultWithPostInfo {
			let id = Self::ensure_personal_identity(origin)?;
			let now = frame_system::Pallet::<T>::block_number();
			let time_tolerance = Self::account_setup_time_tolerance();
			ensure!(
				call_valid_at <= now && now <= call_valid_at.saturating_add(time_tolerance),
				Error::<T>::TimeOutOfRange
			);
			ensure!(!AccountToPersonalId::<T>::contains_key(&account), Error::<T>::AccountInUse);
			ensure!(!AccountToAlias::<T>::contains_key(&account), Error::<T>::AccountInUse);
			let mut record = People::<T>::get(id).ok_or(Error::<T>::NotPerson)?;
```

**File:** polkadot/runtime/common/src/purchase/tests.rs (L141-162)
```rust
#[test]
fn account_creation_handles_basic_errors() {
	new_test_ext().execute_with(|| {
		// Wrong Origin
		assert_noop!(
			Purchase::create_account(
				RuntimeOrigin::signed(alice()),
				alice(),
				alice_signature().to_vec()
			),
			BadOrigin,
		);

		// Wrong Account/Signature
		assert_noop!(
			Purchase::create_account(
				RuntimeOrigin::signed(validity_origin()),
				alice(),
				bob_signature().to_vec()
			),
			Error::<Test>::InvalidSignature,
		);
```
