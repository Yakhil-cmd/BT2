No vulnerability found for this question.

The EIP-7683 report's core defect is a stateless signature-authorization path where a nonce is accepted only as opaque salt and never checked/incremented against signer state, so a single signature can be replayed to repeat an irreversible fund-moving action.

I searched the Polkadot SDK for the closest structural analogs to this pattern — signed, gasless, third-party-relayed authorization — and in every case found explicit, enforced, and tested nonce/replay protection tied to the signer's account state:

- `pallet-meta-tx`'s `MetaTx` dispatch path requires `frame_system::CheckNonce<Runtime>` inside the signed extension tuple, and `validate_nonce_for_account`/`prepare_nonce_for_account` check and atomically increment the signer's actual account nonce before dispatch, with a passing test (`meta_tx_extension_work`) proving a stale nonce is rejected. [1](#0-0) [2](#0-1) 
- `pallet-verify-signature` only validates the signature over the call plus the rest of the extension pipeline (which includes `CheckNonce`); it does not itself provide replay protection, by design, since nonce enforcement is delegated to `CheckNonce` in the same extension tuple used across all runtimes wiring `MetaTxExtension`. [3](#0-2) [4](#0-3) 
- `pallet-people`'s `AsPerson` transaction extension, which authorizes calls via signature/proof rather than a normal account nonce, explicitly checks the target state before allowing dispatch (`if People::<T>::get(index).is_some_and(|record| record.account.is_some_and(|stored_account| stored_account == *account)) { return Err(InvalidTransaction::Stale.into()); }`) and documents the narrow, intentional replay window in its own doc comments rather than leaving it unhandled. [5](#0-4) [6](#0-5) 
- The EVM-permit analog inside `pallet-assets-precompiles` (`use_permit`) atomically increments a per-owner nonce as part of consuming the signature, with dedicated tests asserting that replaying the same `(v, r, s)` fails and that the nonce cannot double-increment. [7](#0-6) 

None of these entry points exhibit the missing-nonce-tracking defect described in the report — signer-bound nonces are checked and incremented atomically in the same extrinsic that authorizes the effect, and the closest edge case (`pallet-people`'s bounded replay tolerance) is a deliberate, documented, idempotent design choice rather than an unauthenticated, unbounded replay of a fund-moving action. I found no reachable, unprivileged FRAME/XCM entry point where a validly-signed authorization can be resubmitted to duplicate an irreversible state/value transfer the way `openFor()` allowed in the original report.

### Citations

**File:** substrate/frame/system/src/extensions/check_nonce.rs (L70-105)
```rust
	pub fn validate_nonce_for_account(
		who: &T::AccountId,
		nonce: T::Nonce,
	) -> Result<ValidNonceInfo, TransactionValidityError> {
		let account = crate::Account::<T>::get(who);
		if account.providers.is_zero() && account.sufficients.is_zero() {
			// Nonce storage not paid for
			return Err(InvalidTransaction::Payment.into());
		}
		if nonce < account.nonce {
			return Err(InvalidTransaction::Stale.into());
		}

		let provides = vec![Encode::encode(&(who.clone(), nonce))];
		let requires = if account.nonce < nonce {
			vec![Encode::encode(&(who.clone(), nonce.saturating_sub(One::one())))]
		} else {
			vec![]
		};

		Ok(ValidNonceInfo { provides, requires })
	}

	/// In transaction extension, prepare nonce for account.
	pub fn prepare_nonce_for_account(
		who: &T::AccountId,
		mut nonce: T::Nonce,
	) -> Result<(), TransactionValidityError> {
		let account = crate::Account::<T>::get(who);
		if nonce > account.nonce {
			return Err(InvalidTransaction::Future.into());
		}
		nonce = nonce.checked_add(&T::Nonce::one()).unwrap_or(T::Nonce::zero());
		crate::Account::<T>::mutate(who, |account| account.nonce = nonce);
		Ok(())
	}
```

**File:** substrate/frame/meta-tx/src/tests.rs (L304-317)
```rust
		// increment alice's nonce to invalidate the meta tx and verify that the
		// meta tx extension works.
		frame_system::Pallet::<Runtime>::inc_account_nonce(alice_account.clone());

		// Check Extrinsic validity and apply it.
		let result = apply_extrinsic(uxt);

		// Asserting the results.
		assert_eq!(result.unwrap_err().error, Error::<Runtime>::Stale.into());

		// Alice balance is unchanged, Bob paid the transaction fee.
		assert_eq!(alice_balance, Balances::free_balance(alice_account));
		assert_eq!(bob_balance - tx_fee, Balances::free_balance(bob_account));
	});
```

**File:** substrate/frame/verify-signature/src/lib.rs (L50-67)
```rust
	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Signature type that the extension of this pallet can verify.
		type Signature: Verify<Signer = Self::AccountIdentifier>
			+ Parameter
			+ Encode
			+ Decode
			+ Send
			+ Sync;
		/// The account identifier used by this pallet's signature type.
		type AccountIdentifier: IdentifyAccount<AccountId = Self::AccountId>;
		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
		/// Helper to create a signature to be benchmarked.
		#[cfg(feature = "runtime-benchmarks")]
		type BenchmarkHelper: BenchmarkHelper<Self::Signature, Self::AccountId>;
	}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L1541-1560)
```rust
pub type MetaTxExtension = (
	pallet_verify_signature::VerifySignature<Runtime>,
	pallet_meta_tx::MetaTxMarker<Runtime>,
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);

impl pallet_meta_tx::Config for Runtime {
	type WeightInfo = weights::pallet_meta_tx::WeightInfo<Runtime>;
	type RuntimeEvent = RuntimeEvent;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type Extension = MetaTxExtension;
	#[cfg(feature = "runtime-benchmarks")]
	type Extension = pallet_meta_tx::WeightlessExtension<Runtime>;
}
```

**File:** substrate/frame/people/src/extension.rs (L46-63)
```rust
	/// This can only dispatch the call `set_alias_account`.
	///
	/// Replay is only protected against resetting the same account during the tolerance period
	/// after `call_valid_at` parameter.
	/// If 2 transaction that set 2 different account are sent for an overlapping validity period,
	/// then those 2 transactions can be replayed indefinitely for the duration of the overlapping
	/// period.
	AsPersonalAliasWithProof(<T::Crypto as GenerateVerifiable>::Proof, RingIndex, Context),
	/// The none origin will be transformed using signature.
	///
	/// This can only dispatch the call `set_personal_id_account`.
	///
	/// Replay is only protected against resetting the same account during the tolerance period
	/// after `call_valid_at` parameter.
	/// If 2 transaction that set 2 different account are sent for an overlapping validity period,
	/// then those 2 transactions can be replayed indefinitely for the duration of the overlapping
	/// period.
	AsPersonalIdentityWithProof(<T::Crypto as GenerateVerifiable>::Signature, PersonalId),
```

**File:** substrate/frame/people/src/extension.rs (L274-279)
```rust
				// This protects again replay attack.
				if People::<T>::get(index).is_some_and(|record| {
					record.account.is_some_and(|stored_account| stored_account == *account)
				}) {
					return Err(InvalidTransaction::Stale.into());
				}
```

**File:** substrate/frame/assets/precompiles/src/permit_tests.rs (L544-598)
```rust
#[test]
fn use_permit_rejects_replay_of_consumed_permit() {
	new_test_ext().execute_with(|| {
		let p = valid_permit_params();

		// First use: should succeed
		let first_result = permit::Pallet::<Test>::use_permit(
			&p.verifying_contract,
			p.name,
			&p.owner,
			&p.spender,
			&p.value,
			&p.deadline,
			p.v,
			&p.r,
			&p.s,
		);
		assert!(first_result.is_ok(), "first use_permit should succeed");

		// Verify nonce was incremented
		let nonce = permit::Pallet::<Test>::nonce(&p.verifying_contract, &p.owner);
		assert_eq!(nonce, U256::one(), "nonce should be 1 after first use");

		// Replay attempt: should fail because nonce is now 1, but signature was for nonce 0
		let replay_result = permit::Pallet::<Test>::use_permit(
			&p.verifying_contract,
			p.name,
			&p.owner,
			&p.spender,
			&p.value,
			&p.deadline,
			p.v,
			&p.r,
			&p.s,
		);

		// The replay should fail with SignerMismatch because the digest computed
		// with nonce=1 won't match the signature created for nonce=0
		assert!(
			replay_result.is_err(),
			"replay of consumed permit MUST fail - this is a critical security property"
		);
		assert!(
			matches!(replay_result, Err(permit::pallet::Error::<Test>::SignerMismatch)),
			"replay should fail with SignerMismatch due to nonce mismatch in digest"
		);

		// Nonce should still be 1 (failed attempt should not increment)
		let nonce_after_replay = permit::Pallet::<Test>::nonce(&p.verifying_contract, &p.owner);
		assert_eq!(
			nonce_after_replay,
			U256::one(),
			"nonce should remain 1 after failed replay attempt"
		);
	});
```
