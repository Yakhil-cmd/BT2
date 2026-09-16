### Title
Integer-overflow in indivisible-asset denomination cap check allows the definer to smuggle an asset whose declared `cap` does not match the true circulating supply - (File: `validation.js`)

### Summary
`validateAssetDefinition()` in `validation.js` sums `count_coins * denomination` for every denomination bucket of a fixed-denomination (indivisible) asset and requires the sum to equal the declared `cap`. Both `denomInfo.count_coins` and `denomInfo.denomination` are only checked with `isPositiveInteger()`, i.e. bounded by `Number.MAX_SAFE_INTEGER` (~9.007e15), not by `constants.MAX_CAP` (9e15) — and the `denomination > MAX_CAP` guard is applied only for `denomination`, not for `count_coins`, and (for `denomination`) is itself gated behind an MCI upgrade flag (`pemCurvesFixMci`). Because JS numbers only carry 53 bits of integer precision, `count_coins * denomination` can silently lose precision once the true product exceeds `2^53`, so an attacker-crafted asset definition can make `total_cap_from_denominations` (a rounded/aliased value) equal an intended `payload.cap`, even though the real total number of coins the asset can issue is different from what the declared cap implies. This is the direct JS analogue of the CVE's "integer overflow before a value is used/written," reachable purely from an unprivileged unit poster defining an asset.

### Finding Description [1](#0-0) 

Relevant checks:
- `denomInfo.denomination` and `denomInfo.count_coins` are validated only as `isPositiveInteger`, with no explicit per-field cap tied to `MAX_CAP` for `count_coins`: [2](#0-1) 
- The `denomination > MAX_CAP` rejection is conditioned on an MCI upgrade flag (`pemCurvesFixMci`), meaning it is a bolted-on fix rather than a fundamental precision-safe computation: [3](#0-2) 
- `total_cap_from_denominations` is accumulated with plain floating-point `+=`/`*`, with no `Number.isSafeInteger` check on the accumulator or on intermediate products: [4](#0-3) 
- The declared `cap` itself is only checked against `MAX_CAP` (9e15), which is deliberately chosen to sit just under `Number.MAX_SAFE_INTEGER`, so any multiplication of two large positive integers that individually pass validation (e.g. `count_coins` in the trillions and `denomination` in the millions) is essentially guaranteed to exceed 2^53 and round to an imprecise value: [5](#0-4) 

Because `total_cap_from_denominations` is a rounded double, an attacker can pick `denominations` arrays whose true mathematical sum differs from the reported `cap`, but where floating-point rounding makes `payload.cap !== total_cap_from_denominations` evaluate to `false` (i.e., pass). This directly mirrors the GIMP PSP bug class: unvalidated integer arithmetic on attacker-controlled size/count fields overflows/loses precision before the result is trusted and used to gate a security-relevant invariant (here, the asset's total issuable supply).

### Impact Explanation
An asset's `cap` (and the derived `total_cap_from_denominations`) is the invariant that indivisible-asset issuance logic (`indivisible_asset.js` / `pickIndivisibleCoinsForAmount`) relies on to bound how many coins can ever be minted via `type: "issue"` inputs, tracked per-denomination via `asset_denominations.count_coins` / `max_issued_serial_number`. If the definer can construct a denominations table that passes the `cap === sum(count_coins*denomination)` check while the real intended/perceived supply differs due to precision loss, downstream holders, exchanges, or AAs that trust `objAsset.cap` as the true maximum supply can be misled about the actual inflation ceiling of the asset. This is a supply-integrity violation (analogous to "supply inflation" in the validation rubric) reachable by any unprivileged unit poster who defines an asset (`app: "asset"` message), with no special privileges required.

### Likelihood Explanation
Medium-High. Defining an asset is available to any user who can post a unit; no elevated permission, hub cooperation, or peer compromise is needed. Constructing two large positive integers whose product loses precision at the 2^53 boundary is a standard IEEE-754 exercise (e.g. `count_coins = 4503599627370497`, `denomination = 3` vs. other combos) — well within the reach of a single crafted `asset` definition message. Because `MAX_CAP` (9e15) is close to `Number.MAX_SAFE_INTEGER` (~9.007e15), only the `denomination` field is guarded against exceeding it (and only post-upgrade-MCI); `count_coins` is entirely unguarded, so it is easy to pick oversized `count_coins` for a small `denomination` and trigger the loss of precision in the sum.

### Recommendation
- Validate `denomInfo.count_coins` against `constants.MAX_CAP` the same way `denomInfo.denomination` is (unconditionally, not gated behind `pemCurvesFixMci`).
- Compute `total_cap_from_denominations` using integer-safe arithmetic (e.g. BigInt, or verify `Number.isSafeInteger` after every multiplication and addition), rejecting the unit if any intermediate value is not a safe integer.
- Remove the MCI-gating of the `denomination > MAX_CAP` check so the safe-integer invariant always holds, rather than only after a network upgrade point.

### Proof of Concept
1. Attacker crafts an `asset` message with `fixed_denominations: true`, `cap: X`, and `denominations` containing two entries where `count_coins_1 * denomination_1 + count_coins_2 * denomination_2` computed in double precision rounds to `X`, but the true integer sum (verifiable with BigInt) differs from `X` by more than 1 unit (choose `count_coins`/`denomination` pairs straddling `2^53`, e.g. values close to `9007199254740993` which is not exactly representable as a double).
2. Submit this asset-definition unit; `validateAssetDefinition()` accepts it because the floating point comparison `payload.cap !== total_cap_from_denominations` is false due to rounding, even though `payload.cap` does not equal the true sum.
3. Subsequent issuance following `indivisible_asset.js`'s per-denomination `count_coins`/`max_issued_serial_number` bookkeeping can mint a total that diverges from the intended supply as encoded by `cap`, breaking the invariant that other participants (wallets, AAs, exchanges) rely on when trusting `objAsset.cap` as the asset's supply ceiling.

### Citations

**File:** validation.js (L2757-2792)
```javascript
	if (payload.denominations){
		if (payload.denominations.length > constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION)
			return callback("too many denominations");
		var total_cap_from_denominations = 0;
		var bHasUncappedDenominations = false;
		var prev_denom = 0;
		for (var i=0; i<payload.denominations.length; i++){
			var denomInfo = payload.denominations[i];
			if (!isNonemptyObject(denomInfo))
				return callback("denomination must be a non-empty object: " + JSON.stringify(denomInfo));
			if (hasFieldsExcept(denomInfo, ["denomination", "count_coins"]))
				return callback("unknown fields in denomination: " + JSON.stringify(denomInfo));
			if (!isPositiveInteger(denomInfo.denomination))
				return callback("invalid denomination");
			if (denomInfo.denomination > constants.MAX_CAP && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
				return callback("denomination exceeds MAX_CAP");
			if (denomInfo.denomination <= prev_denom)
				return callback("denominations unsorted");
			if ("count_coins" in denomInfo){
				if (!isPositiveInteger(denomInfo.count_coins))
					return callback("invalid count_coins");
				total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
			}
			else
				bHasUncappedDenominations = true;
			prev_denom = denomInfo.denomination;
		}
		if (bHasUncappedDenominations && total_cap_from_denominations)
			return callback("some denominations are capped, some uncapped");
		if (bHasUncappedDenominations && payload.cap)
			return callback("has cap but some denominations are uncapped");
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
	}
```

**File:** constants.js (L57-57)
```javascript
exports.MAX_CAP = 9e15;
```
