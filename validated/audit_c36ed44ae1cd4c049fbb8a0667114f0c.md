## Analog Found

### Title
Irrevocable EIP-2612 Permit Signatures in `pallet-assets` Precompiles Allow Stale Execution - ([File: substrate/frame/assets/precompiles/src/permit.rs])

### Summary
The `pallet-assets` precompiles crate implements an EIP-2612-style `permit` mechanism that lets an asset owner sign an off-chain approval message (owner, spender, value, nonce, deadline) which anyone holding the signature can later submit through the `pallet-revive` precompile dispatch to grant an ERC20-style allowance [1](#0-0) . Exactly like the RFQ order in the external report, the only invalidation mechanism is the `deadline` field and nonce consumption on successful use; there is no dispatchable call or storage-level mechanism allowing the owner to proactively revoke an outstanding, unexpired, unconsumed permit signature before its `deadline`.

### Finding Description
The pallet stores a per-`(verifying_contract, owner)` nonce and only increments it when a permit is *successfully used* via `use_permit`, which calls `do_verify_permit` then `increment_nonce` [2](#0-1) . Verification checks only that `owner`/`spender` are non-zero, that `deadline >= now`, and that the ECDSA-recovered signer matches `owner` for the digest built from the *current* on-chain nonce [3](#0-2) .

Critically, `increment_nonce` is a plain internal `impl<T: Config> Pallet<T>` function [4](#0-3) , and the crate defines **no `#[pallet::call]` block at all** — confirmed by search, which returned zero matches for `#[pallet::call]` in the entire `substrate/frame/assets/precompiles/src/**` tree. This means there is no extrinsic (e.g., `Assets::invalidate_permit` or an owner-callable nonce bump) that the signer can dispatch to bump their own nonce and thereby invalidate an already-signed-but-not-yet-submitted permit. The only paths that advance the nonce are successful `use_permit` calls driven through the precompile dispatch surface referenced in `permit`/`selector` handling in `substrate/frame/assets/precompiles/src/lib.rs`.

Consequently, once an owner signs a permit (analogous to the market maker signing an RFQ quote) with a future `deadline`, that signature remains valid and exercisable by any holder (the `spender`, or anyone who relays it) for the entire window up to `deadline`, regardless of whether the owner's intent has changed in the meantime (e.g., they no longer want to grant that allowance because off-chain/market conditions shifted). There is no way to make it stale early short of waiting for `deadline` to pass or consuming the nonce through an unrelated permit use.

### Impact Explanation
An owner who signs a permit with a distant deadline cannot cancel it if they change their mind — e.g., they signed it under an assumption (price, counterparty behavior, an off-chain agreement) that no longer holds. A holder of the signature can submit it at the most opportune moment within the validity window, extracting value the owner did not intend to grant once conditions changed — the same "free option" dynamic described in the RFQ report, transplanted onto FRAME's EIP-2612-style permit primitive. This is a design-level gap rather than a memory-safety or fund-theft bug: no fee/deposit is bypassed, no unauthorized origin is created, and the loss is limited to what the owner already signed away in the permit's `value` field.

### Likelihood Explanation
High likelihood of applicability whenever an owner signs a permit for a spender they don't fully trust, or signs multiple permits in sequence and only later decides some should not be honored. The precompile/permit pathway is a normal, callable production entry point (no privileged role required, no forged inherent, no governance) — any owner using the permit flow is exposed. Severity is capped at Medium because it requires the owner to have voluntarily signed the permit; the risk is purely "signed-but-should-be-revocable," matching the referenced report's own Medium classification.

### Recommendation
Add an explicit, owner-authenticated on-chain revocation path, e.g.:
- A dispatchable extrinsic (`invalidate_nonce`/`cancel_permit`) callable by the owner's real `AccountId` (mapped to their `H160`) that bumps `Nonces::<T>` for a given `verifying_contract`, immediately invalidating any outstanding permit signed against the old nonce.
- Alternatively, support per-permit unique nonces/hashes with an explicit on-chain "used/cancelled" bitmap so a specific signature (not just "everything below this nonce") can be revoked without disturbing other pending permits.

### Proof of Concept
No executable PoC was run; this is a design-gap analysis based on static review of `permit.rs`. Evidence supporting the finding:
- `increment_nonce` is only invoked from `use_permit`'s success path [2](#0-1) .
- No `#[pallet::call]` block exists anywhere under `substrate/frame/assets/precompiles/src/` (confirmed via repo-wide grep with zero matches), so there is no dispatchable extrinsic for an owner to self-invalidate a nonce/permit.
- `do_verify_permit`'s only temporal/state check is `deadline < now` and signature/nonce-derived digest match [5](#0-4) ; there is no "cancelled" flag or additional owner-controlled gate.

This is a static-review analog rather than a proven exploit chain; because the pallet exposes no direct extrinsic call surface (all invocation is presumably mediated through the `pallet-revive` precompile dispatch in `lib.rs`, whose selector-handling code was only partially inspected), a full runtime integration reproduction (deploy the precompile, sign+submit two conflicting permits, confirm success of the later, "should-be-cancelled" one) was not executed within this analysis and would be required to fully confirm reachability and exact economic impact.

### Citations

**File:** substrate/frame/assets/precompiles/src/permit.rs (L18-30)
```rust
//! ERC20Permit pallet for signature-based approvals (EIP-2612).
//!
//! This pallet stores permit-related state (nonces) and provides EIP-712
//! signature verification for gasless approvals.
//!
//! # Security Notes
//!
//! - **Nonce management**: Use `use_permit` (not `verify_permit`) to atomically verify and consume
//!   permits. This prevents replay attacks.
//! - **Deadline validation**: Permits are validated against UNIX timestamps.
//! - **Domain separation**: Each verifying contract has its own domain separator.
//! - **Signature malleability**: The `s` value is checked to be in the lower half of the secp256k1
//!   curve order to prevent signature malleability attacks.
```

**File:** substrate/frame/assets/precompiles/src/permit.rs (L139-146)
```rust
		/// Increment the nonce for an owner on a specific verifying contract.
		/// Returns the new nonce value, or an error if overflow would occur.
		pub fn increment_nonce(verifying_contract: &H160, owner: &H160) -> Result<U256, Error<T>> {
			Nonces::<T>::try_mutate(verifying_contract, owner, |nonce| {
				*nonce = nonce.checked_add(U256::one()).ok_or(Error::<T>::NonceOverflow)?;
				Ok(*nonce)
			})
		}
```

**File:** substrate/frame/assets/precompiles/src/permit.rs (L311-362)
```rust
		fn do_verify_permit(
			verifying_contract: &H160,
			name: &[u8],
			owner: &H160,
			spender: &H160,
			value: &[u8; 32],
			deadline: &[u8; 32],
			v: u8,
			r: &[u8; 32],
			s: &[u8; 32],
		) -> Result<(), Error<T>> {
			// EIP-2612: owner and spender cannot be the zero address
			if owner.is_zero() {
				return Err(Error::<T>::InvalidOwner);
			}
			if spender.is_zero() {
				return Err(Error::<T>::InvalidSpender);
			}

			// Validate deadline against current timestamp.
			// EIP-2612 specifies deadlines in UNIX seconds. We use the `UnixTime`
			// trait which returns a `core::time::Duration` — its `as_secs()` method
			// gives us seconds regardless of pallet_timestamp's internal resolution
			// (which stores milliseconds, converted via `Duration::from_millis` in
			// pallet_timestamp's `UnixTime` implementation).
			let now_seconds = <pallet_timestamp::Pallet<T> as UnixTime>::now().as_secs();
			let deadline_u256 = U256::from_big_endian(deadline);
			let now_u256 = U256::from(now_seconds);

			if deadline_u256 < now_u256 {
				return Err(Error::<T>::PermitExpired);
			}

			let nonce = Self::nonce(verifying_contract, owner);
			let digest = Self::permit_digest(
				verifying_contract,
				name,
				owner,
				spender,
				value,
				&nonce,
				deadline,
			);

			let recovered = Self::ecrecover(&digest, v, r, s)?;

			if &recovered != owner {
				return Err(Error::<T>::SignerMismatch);
			}

			Ok(())
		}
```

**File:** substrate/frame/assets/precompiles/src/permit.rs (L364-403)
```rust
		/// Verify and consume a permit signature atomically.
		///
		/// This is the recommended function for production use. It:
		/// 1. Validates the deadline against the current timestamp
		/// 2. Verifies the signature matches the owner
		/// 3. Increments the nonce to prevent replay attacks
		///
		/// The `name` parameter should be the token name per EIP-2612 specification.
		///
		/// After this function returns `Ok(())`, the permit cannot be used again.
		pub fn use_permit(
			verifying_contract: &H160,
			name: &[u8],
			owner: &H160,
			spender: &H160,
			value: &[u8; 32],
			deadline: &[u8; 32],
			v: u8,
			r: &[u8; 32],
			s: &[u8; 32],
		) -> Result<(), Error<T>> {
			// Verify the permit first
			Self::do_verify_permit(
				verifying_contract,
				name,
				owner,
				spender,
				value,
				deadline,
				v,
				r,
				s,
			)?;

			// Consume the permit by incrementing the nonce
			// This prevents the same permit from being used again
			Self::increment_nonce(verifying_contract, owner)?;

			Ok(())
		}
```
