## Finding

The reported Keycloak bug is a **CWE‑269 privilege‑escalation via missing boundary check in role/permission mapping**: a low‑privileged principal can self‑assign a higher‑privileged role because the system does not verify that the "superset" role it's using to authorize the grant actually admits every permission that the target role grants.

The exact same bug class exists — and has already been found and fixed once in this codebase (`asset-hub-westend`'s `NonTransfer`/`Governance` mismatch, see `prdoc/pr_12769.prdoc`) — but reappears **unpatched** in a different runtime.

### Title
`ProxyType::is_superset` in the staking‑async relay‑chain runtime lets a `NonTransfer` proxy self‑grant a `SudoBalances` proxy, bypassing the pallet's explicit Sudo exclusion - (`substrate/frame/staking-async/runtimes/rc/src/lib.rs`)

### Summary
`pallet_proxy::do_proxy` authorizes a delegate's `add_proxy`/`remove_proxy` calls made *through* an existing proxy solely via `ProxyType::is_superset`, not via `ProxyType::filter`. [1](#0-0)  In `substrate/frame/staking-async/runtimes/rc/src/lib.rs`, `is_superset` declares `NonTransfer` a superset of *every* other `ProxyType`, including `SudoBalances`: [2](#0-1) 

But `NonTransfer`'s own `filter` explicitly excludes the Sudo pallet (per its own inline comment), while `SudoBalances`'s `filter` admits `Sudo::sudo{ call: Balances(..) }`: [3](#0-2) 

### Finding Description
A `NonTransfer` proxy is designed to be a broad, mostly-non-financial delegation that intentionally denies Balances *and* Sudo access ("Specifically omitting Sudo pallet"). However, because `is_superset(NonTransfer, _) => true` unconditionally, `pallet_proxy` treats `NonTransfer` as dominating `SudoBalances` too.

When a delegate `D` holds a `NonTransfer` proxy for account `R`, `D` can call the signed extrinsic `Proxy::proxy(real = R, call = Proxy::add_proxy{ delegate: D, proxy_type: SudoBalances, delay: 0 })`. Inside `do_proxy`, the added filter only blocks `add_proxy`/`remove_proxy` when `!def.proxy_type.is_superset(proxy_type)`; since `NonTransfer.is_superset(SudoBalances) == true`, the call passes and `D` becomes its own `SudoBalances` proxy for `R`. [4](#0-3)  `D` can then call `Proxy::proxy(real = R, force_proxy_type = SudoBalances, call = Sudo::sudo{ call: Balances::force_set_balance{..} })`, which `SudoBalances`'s filter admits.

`pallet_sudo::sudo` is documented and implemented to check the signed caller against the stored `Key`, then dispatch the inner call with **Root** origin via `dispatch_bypass_filter`. [5](#0-4)  This means the attack only succeeds when `R` is the actual configured Sudo key — but that is precisely the account this pallet's comment says a `NonTransfer` delegate should *never* be able to reach. The `is_superset`/`filter` mismatch, not any legitimate grant, is what lets `D` cross that explicit boundary and reach root-authorized `Balances` calls (`force_set_balance`, `force_transfer`, `force_unreserve`, `force_adjust_total_issuance`, etc.) on behalf of the sudo key.

### Impact Explanation
If the sudo-key-holding account ever delegates a `NonTransfer` proxy to any account (a normal, low-trust delegation intended to explicitly exclude Sudo/Balances access), that delegate can escalate to root-authorized `Balances` calls, enabling unbacked issuance/force-transfers of funds under Root authority — a serious integrity break far beyond what `NonTransfer` is meant to permit.

### Likelihood Explanation
Exploitation requires the victim delegator to be the actual configured Sudo key holder who has granted someone a `NonTransfer` proxy — this narrows real-world exposure (sudo keys are normally tightly held/rotated to governance or removed on production chains). However, this is not a privileged-attacker scenario: any legitimate, ordinary `NonTransfer` delegate can perform the escalation unconditionally once such a delegation exists, with no additional secrets, and the flaw is purely a configuration/logic defect in production runtime code (not test/mock code), matching a bug class already proven exploitable and fixed once in this same codebase.

### Recommendation
Fix `ProxyType::is_superset` in `substrate/frame/staking-async/runtimes/rc/src/lib.rs` so that `NonTransfer` is not declared a superset of `SudoBalances` (and audit all other `(NonTransfer, _) => true` pairs in this and sibling runtimes for the same class of mismatch, as was done for `asset-hub-westend` in `prdoc/pr_12769.prdoc`). Consider adding the same kind of exhaustive `filter`-vs-`is_superset` lattice regression test used in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs` (`proxy_type_superset_relation_matches_call_filters`) to this runtime's test suite so the class cannot silently reappear.

### Proof of Concept
Reproduction path (structural, not executed against a live network):
1. `R` (the runtime's configured Sudo `Key`) grants `D` a `NonTransfer` proxy via `Proxy::add_proxy(D, ProxyType::NonTransfer, 0)`.
2. `D` calls `Proxy::proxy(real=R, force_proxy_type=None, call=Proxy::add_proxy{delegate: D, proxy_type: ProxyType::SudoBalances, delay: 0})`. This passes `do_proxy`'s filter because `ProxyType::NonTransfer.is_superset(&ProxyType::SudoBalances) == true` (confirmed by reading the `is_superset` match arms directly).
3. `D` calls `Proxy::proxy(real=R, force_proxy_type=Some(ProxyType::SudoBalances), call=Sudo::sudo{call: Balances::force_set_balance{who: D, new_free: MAX}})`. `SudoBalances::filter` admits this call; `pallet_sudo::sudo` succeeds because the origin is `Signed(R)` and `R == Key`, dispatching `Balances::force_set_balance` with Root origin.
4. Net effect: `D`, holding only a proxy type whose filter and design comment explicitly exclude Sudo, obtains root-authorized control over `Balances` calls on `R`'s account.

No test execution against a network was performed; this is a code-level trace through `pallet_proxy::do_proxy`, `ProxyType::is_superset`/`filter`, and `pallet_sudo::sudo`, backed by the file:line evidence cited above and the precedent fix in `prdoc/pr_12769.prdoc` for the structurally identical `NonTransfer`/`Governance` bug.

### Citations

**File:** substrate/frame/proxy/src/lib.rs (L994-1023)
```rust
	fn do_proxy(
		def: ProxyDefinition<T::AccountId, T::ProxyType, BlockNumberFor<T>>,
		real: T::AccountId,
		call: <T as Config>::RuntimeCall,
	) {
		use frame::traits::{InstanceFilter as _, OriginTrait as _};
		// This is a freshly authenticated new account, the origin restrictions doesn't apply.
		let mut origin: T::RuntimeOrigin = frame_system::RawOrigin::Signed(real).into();
		origin.add_filter(move |c: &<T as frame_system::Config>::RuntimeCall| {
			let c = <T as Config>::RuntimeCall::from_ref(c);
			// We make sure the proxy call does access this pallet to change modify proxies.
			match c.is_sub_type() {
				// Proxy call cannot add or remove a proxy with more permissions than it already
				// has.
				Some(Call::add_proxy { ref proxy_type, .. }) |
				Some(Call::remove_proxy { ref proxy_type, .. })
					if !def.proxy_type.is_superset(proxy_type) =>
				{
					false
				},
				// Proxy call cannot remove all proxies or kill pure proxies unless it has full
				// permissions.
				Some(Call::remove_proxies { .. }) | Some(Call::kill_pure { .. })
					if def.proxy_type != T::ProxyType::default() =>
				{
					false
				},
				_ => def.proxy_type.filter(c),
			}
		});
```

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1327-1376)
```rust
			ProxyType::NonTransfer => matches!(
				c,
				RuntimeCall::System(..) |
				RuntimeCall::Babe(..) |
				RuntimeCall::Timestamp(..) |
				RuntimeCall::Indices(pallet_indices::Call::claim{..}) |
				RuntimeCall::Indices(pallet_indices::Call::free{..}) |
				RuntimeCall::Indices(pallet_indices::Call::freeze{..}) |
				// Specifically omitting Indices `transfer`, `force_transfer`
				// Specifically omitting the entire Balances pallet
				RuntimeCall::Session(..) |
				RuntimeCall::Grandpa(..) |
				RuntimeCall::Utility(..) |
				RuntimeCall::Identity(..) |
				RuntimeCall::ConvictionVoting(..) |
				RuntimeCall::Referenda(..) |
				RuntimeCall::Whitelist(..) |
				RuntimeCall::Recovery(pallet_recovery::Call::control_inherited_account{..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::initiate_attempt{..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::approve_attempt{..}) |
				RuntimeCall::Recovery(pallet_recovery::Call::finish_attempt{..}) |
				// Specifically omitting Recovery `create_recovery`, `initiate_recovery`
				RuntimeCall::Vesting(pallet_vesting::Call::vest{..}) |
				RuntimeCall::Vesting(pallet_vesting::Call::vest_other{..}) |
				// Specifically omitting Vesting `vested_transfer`, and `force_vested_transfer`
				RuntimeCall::Scheduler(..) |
				// Specifically omitting Sudo pallet
				RuntimeCall::Proxy(..) |
				RuntimeCall::Multisig(..) |
				RuntimeCall::Registrar(paras_registrar::Call::register{..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister{..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve{..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..)
			),
			ProxyType::Staking => {
				matches!(c, RuntimeCall::Session(..) | RuntimeCall::Utility(..))
			},
			ProxyType::NominationPools => {
				matches!(c,| RuntimeCall::Utility(..))
			},
			ProxyType::SudoBalances => match c {
				RuntimeCall::Sudo(pallet_sudo::Call::sudo { call: ref x }) => {
					matches!(x.as_ref(), &RuntimeCall::Balances(..))
				},
				RuntimeCall::Utility(..) => true,
				_ => false,
			},
```

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1410-1418)
```rust
	fn is_superset(&self, o: &Self) -> bool {
		match (self, o) {
			(x, y) if x == y => true,
			(ProxyType::Any, _) => true,
			(_, ProxyType::Any) => false,
			(ProxyType::NonTransfer, _) => true,
			_ => false,
		}
	}
```

**File:** substrate/frame/sudo/src/lib.rs (L106-116)
```rust
//! ## Low Level / Implementation Details
//!
//! This pallet checks that the caller of its dispatchables is a signed account and ensures that the
//! caller matches the sudo key in storage.
//! A caller of this pallet's dispatchables does not pay any fees to dispatch a call. If the account
//! making one of these calls is not the sudo key, the pallet returns a [`Error::RequireSudo`]
//! error.
//!
//! Once an origin is verified, sudo calls use `dispatch_bypass_filter` from the
//! [`UnfilteredDispatchable`](frame_support::traits::UnfilteredDispatchable) trait to allow call
//! execution without enforcing any further origin checks.
```
