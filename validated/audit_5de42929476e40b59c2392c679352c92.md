This is a strong, confirmed analog. Notably, the emulated integration test itself documents the expected behavior explicitly: `1414213562372995 - ASSET_HUB_WESTEND_ED * 2, // all but the 2 EDs can't be retrieved.` [1](#0-0) , confirming this is a known, deliberate, documented behavior in the live AssetHub configuration rather than an unknown defect.

### Title
Last liquidity provider cannot withdraw funds proportional to the pool's ED-floor reserve in `pallet-asset-conversion` - ([File: substrate/frame/asset-conversion/src/lib.rs])

### Summary
`do_remove_liquidity` enforces that after burning LP tokens, each of the pool's two asset reserves must remain `>= T::Assets::minimum_balance(asset)` (i.e., above each asset's existential deposit), or the call fails with `Error::ReserveLeftLessThanMinimal`. Because this floor is checked against the raw reserve values regardless of who currently holds the corresponding LP-token claim, no signed caller — not even the legitimate final redeemer of real liquidity — can ever withdraw the last existential-deposit's worth of each asset out of the pool account. This mirrors the reported Basket bug class: a fixed minimum-amount check blocks the very last withdrawal, permanently stranding a bounded amount of user-owned value in the pool.

### Finding Description
In `Pallet::do_remove_liquidity` (`substrate/frame/asset-conversion/src/lib.rs:894-966`), the amounts to be paid out (`amount1`, `amount2`) are computed pro-rata from the caller's `lp_token_burn` against the pool's `total_supply` and current `reserve1`/`reserve2` [2](#0-1) . Before executing the transfer, the pallet requires:

```
let reserve1_left = reserve1.saturating_sub(amount1);
let reserve2_left = reserve2.saturating_sub(amount2);
ensure!(reserve1_left >= T::Assets::minimum_balance(asset1.clone()), Error::<T>::ReserveLeftLessThanMinimal);
ensure!(reserve2_left >= T::Assets::minimum_balance(asset2.clone()), Error::<T>::ReserveLeftLessThanMinimal);
``` [3](#0-2) 

This is a global invariant on the pool account's reserves, not a per-caller check. Consequently, once the reserves approach the existential deposit(s) of the two assets, *any* `remove_liquidity` extrinsic call — via `Pallet::remove_liquidity` (`substrate/frame/asset-conversion/src/lib.rs:497-517`) or the `MutateLiquidity::remove_liquidity` trait entry (`substrate/frame/asset-conversion/src/liquidity.rs:118-137`), or the EVM-compatible `AssetConversion` precompile's `removeLiquidity` (`substrate/frame/asset-conversion/precompiles/src/lib.rs:462-492`) — will fail if it would push either reserve below its ED. This is a reachable, permissionless, signed-extrinsic path with no privileged role required.

The Westend AssetHub emulated integration test explicitly documents this outcome as expected: after swaps and a partial `remove_liquidity`, the test comment states `// all but the 2 EDs can't be retrieved` when computing the final `lp_token_burn` amount that is safe to redeem [4](#0-3) . The unit test `check_no_panic_when_try_swap_close_to_empty_pool` similarly shows that any attempt to drain the pool below the ED via `swap_tokens_for_exact_tokens` is rejected with `TokenError::NotExpendable` [5](#0-4) , confirming the ED floor is a deliberate, actively-enforced, and already load-bearing design constraint across both the swap and liquidity-removal code paths.

### Impact Explanation
The practical consequence is that a bounded amount of value — up to roughly `minimum_balance(asset1) + minimum_balance(asset2)` — becomes permanently unwithdrawable from any given pool once its reserves shrink to near-ED levels (e.g., as liquidity providers exit or after heavy swapping activity drains one side of the pool). This is functionally identical to the reported Basket vulnerability's root cause (a fixed `MIN_AMOUNT` check applied to the pool's aggregate state, rather than to the withdrawer's fair share, blocking full exit). However, unlike the Basket report — where the locked amount was unbounded/arbitrary and could represent a large fraction of a small pool — here the amount permanently stuck is capped by design at, at most, two EDs (typically a very small, protocol-defined constant), and this ED floor is also required independently to prevent the pool account itself from being reaped by other pallet logic (dusting protection). The Amun team's own reviewer explicitly agreed this class of issue is valid but disputed severity for the same reason: the locked amount is bounded and small.

### Likelihood Explanation
High likelihood of the state being reached: any actively used pool that experiences enough liquidity withdrawal or swap activity will naturally trend its reserves toward the ED floor, and the asset-conversion pallet's own tests/comments confirm this scenario is already anticipated in production configurations (Asset Hub). No attacker privilege, governance action, or malicious infrastructure is required — this occurs through ordinary, permissionless `add_liquidity`/`remove_liquidity`/`swap_*` calls available to any signed account.

### Recommendation
This is intentional, ED-driven dust protection (analogous to Uniswap V2's permanently-locked `MINIMUM_LIQUIDITY`) and is already documented/tested as expected behavior in this codebase (`substrate/frame/asset-conversion/src/tests.rs:1499-1510`; `cumulus/.../swap.rs:210-219`). No code change is required; if stricter guarantees are desired, the recommendation from the analogous Basket report — bound the check to the withdrawer's own fair share and/or allow the pool to reap fully to zero reserves and be effectively destroyed when the last real LP token holder exits — could be considered, but this would trade away the existing anti-dust/anti-reap protection that the ED floor currently provides for the pool account and other pallets relying on `Assets`/`Balances` invariants.

### Proof of Concept
No new PoC was executed. The claim is supported by existing, already-passing test harnesses in this repository that demonstrate and assert exactly this bounded, permanent reserve floor:
- `substrate/frame/asset-conversion/src/tests.rs::check_no_panic_when_try_swap_close_to_empty_pool` (lines 1436-1526) — asserts a swap that would push the reserve below ED fails with `TokenError::NotExpendable`.
- `cumulus/parachains/integration-tests/emulated/tests/assets/asset-hub-westend/src/tests/swap.rs` (lines 210-220) — the live-runtime-shaped emulated test explicitly computes and passes `lp_token_burn = total - 2*ED` because the remaining 2 EDs "can't be retrieved."

No execution against a live network was performed; this is a repository-code-and-test-evidence-based analysis, not a live PoC run. Given this is bounded, small, and already an accepted/documented design trade-off, it does not rise to Critical/High severity under the Polkadot SDK bounty criteria, and is best characterized as a **Low** severity, already-known-and-accepted-tradeoff finding, preserved here as a valid Low rather than discarded or inflated.

### Citations

**File:** cumulus/parachains/integration-tests/emulated/tests/assets/asset-hub-westend/src/tests/swap.rs (L210-219)
```rust
		// 5. Remove liquidity
		assert_ok!(<AssetHubWestend as AssetHubWestendPallet>::AssetConversion::remove_liquidity(
			<AssetHubWestend as Chain>::RuntimeOrigin::signed(sov_penpal_on_ahr.clone()),
			asset_native.clone(),
			Box::new(foreign_asset_at_asset_hub_westend),
			1414213562372995 - ASSET_HUB_WESTEND_ED * 2, // all but the 2 EDs can't be retrieved.
			0,
			0,
			sov_penpal_on_ahr.clone().into(),
		));
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L915-920)
```rust
			let total_supply = T::PoolAssets::total_issuance(pool.lp_token.clone());
			let withdrawal_fee_amount = T::LiquidityWithdrawalFee::get() * lp_token_burn;
			let lp_redeem_amount = lp_token_burn.saturating_sub(withdrawal_fee_amount);

			let amount1 = Self::mul_div(&lp_redeem_amount, &reserve1, &total_supply)?;
			let amount2 = Self::mul_div(&lp_redeem_amount, &reserve2, &total_supply)?;
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L930-939)
```rust
			let reserve1_left = reserve1.saturating_sub(amount1);
			let reserve2_left = reserve2.saturating_sub(amount2);
			ensure!(
				reserve1_left >= T::Assets::minimum_balance(asset1.clone()),
				Error::<T>::ReserveLeftLessThanMinimal
			);
			ensure!(
				reserve2_left >= T::Assets::minimum_balance(asset2.clone()),
				Error::<T>::ReserveLeftLessThanMinimal
			);
```

**File:** substrate/frame/asset-conversion/src/tests.rs (L1499-1510)
```rust
		// validate the reserve should always stay above the ED
		assert_noop!(
			AssetConversion::swap_tokens_for_exact_tokens(
				RuntimeOrigin::signed(user),
				bvec![token_2.clone(), token_1.clone()],
				708 - ed + 1, // amount_out
				500,          // amount_in_max
				user,
				false,
			),
			TokenError::NotExpendable,
		);
```
