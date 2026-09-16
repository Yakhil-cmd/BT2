Confirmed: `isPositiveInteger` in `validation_utils.js` only checks `Math.floor(value) === value && value > 0`, with no upper bound — it does not enforce `MAX_CAP` (9e15) or `Number.MAX_SAFE_INTEGER`. [1](#0-0) 

### Title
Missing upper-bound validation on `denominations[].denomination`/`count_coins` in asset definitions allows floating-point overflow of `total_cap_from_denominations` - (File: validation.js)

### Summary
`validateAssetDefinition` computes `total_cap_from_denominations` by summing `denomInfo.count_coins * denomInfo.denomination` for each denomination entry in a user-submitted asset definition. `count_coins` is only checked with `isPositiveInteger`, which has no upper bound, unlike `denomInfo.denomination` (bounded by `MAX_CAP` only under a later network upgrade check). This mirrors the reported CollateralBook bug class: an unbounded numeric input used unchecked in an arithmetic accumulation that can silently overflow/lose precision instead of being rejected.

### Finding Description
In `validateAssetDefinition`, each denomination entry is validated as: [2](#0-1) 

`denomInfo.denomination` is bounded by `MAX_CAP` only conditionally (post `pemCurvesFixMci`): [3](#0-2) 

But `denomInfo.count_coins` is checked only with `isPositiveInteger`, which has no maximum: [4](#0-3) 

Since JavaScript numbers lose integer precision beyond `Number.MAX_SAFE_INTEGER` (2^53-1) and the code performs plain floating-point multiplication (`count_coins * denomination`) and addition to build `total_cap_from_denominations`, a poster of an asset-definition unit can choose `count_coins` and `denomination` values that, when multiplied, silently round to an attacker-chosen value distinct from the true mathematical product — without triggering any error, since no `isFinite`/`MAX_CAP` check is applied on the product itself before the final `payload.cap !== total_cap_from_denominations` comparison.

### Impact Explanation
If the rounded/aliased product can be crafted to equal a `payload.cap` chosen by the attacker while the true, intended per-denomination coin supply is different, the asset's `cap` field (used everywhere downstream — including issuance validation `input.amount !== objAsset.cap` in `validatePaymentInputsAndOutputs`) becomes inconsistent with the actual sum of coins mintable via `asset_denominations`/`max_issued_serial_number` tracking. This is a supply-accounting integrity issue for a user-defined asset: it can let the definer construct an asset whose declared cap and underlying per-denomination issuable totals disagree, enabling issuance beyond the nominally declared cap or other confusion for wallets/exchanges relying on `cap` as ground truth — a supply-inflation-class defect confined to the asset the attacker themselves defines.

### Likelihood Explanation
Reachable directly by any unprivileged unit poster defining a new asset (`app: 'asset'`) with attacker-chosen `denominations` array — no special privilege required, exactly analogous to the CollateralBook report where an unbounded numeric parameter set by any caller of `addCollateralType` later overflows an unchecked arithmetic operation. Constructing values that hit floating-point precision loss at the JS `Number` boundary (~9e15) requires deliberate crafting but is fully within reach of a scripted attacker; `MAX_CAP` (9e15) is already close to `Number.MAX_SAFE_INTEGER` (~9.007e15) so the margin for both operands to independently pass `isPositiveInteger` yet produce an overflowed/imprecise product is real.

### Recommendation
Enforce `count_coins <= constants.MAX_CAP` unconditionally (not gated behind `pemCurvesFixMci`), and validate the computed `total_cap_from_denominations` itself against `MAX_CAP` and `Number.isSafeInteger` before comparing it to `payload.cap`, mirroring the fix recommended for the interest-rate overflow case (bound the input before it feeds an unchecked arithmetic accumulation).

### Proof of Concept
Not independently executed in this analysis; the argument rests on static code reading of `validateAssetDefinition` in [5](#0-4)  combined with the unbounded `isPositiveInteger` check in [4](#0-3) . A concrete precision-loss collision (two distinct `(count_coins, denomination)` pairs whose product coincides after IEEE-754 rounding, with `payload.cap` set to that rounded value) would need to be numerically constructed and tested against `validateAssetDefinition` to fully confirm exploitability; this was not verified end-to-end due to lack of code-execution access in this session.

### Citations

**File:** validation_utils.js (L20-29)
```javascript
function isInteger(value){
	return typeof value === 'number' && isFinite(value) && Math.floor(value) === value;
};

/**
 * True if int is an integer strictly greater than zero.
 */
function isPositiveInteger(int){
	return (isInteger(int) && int > 0);
}
```

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
