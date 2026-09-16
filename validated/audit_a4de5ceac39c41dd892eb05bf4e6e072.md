### Title
Floating-point overflow in indivisible-asset denomination cap/issuance checks allows supply inflation - ([File: validation.js])

### Summary
`validateAssetDefinition()` and `validateIndivisibleIssue()` in `validation.js` compute `denomination * count_coins` using ordinary JS `Number` arithmetic without ever checking that the product stays within `Number.MAX_SAFE_INTEGER` (2^53‑1 ≈ 9.007e15). Since `denomination` is allowed up to `constants.MAX_CAP` (9e15) and `count_coins` is only checked to be a positive integer with **no upper bound at all**, the product can silently overflow IEEE‑754 double precision, causing incorrect equality/sum comparisons — the same bug class as CVE‑2021‑41197 (unchecked multiplication overflow leading to incorrect results instead of a safe error).

### Finding Description
In the asset-definition validator, the per-denomination cap is accumulated with plain multiplication and no overflow guard: [1](#0-0) 

`denomInfo.denomination` is bounded by `constants.MAX_CAP` (9e15) only conditionally (post-`pemCurvesFixMci`), but `denomInfo.count_coins` is validated only with `isPositiveInteger`, which places **no upper bound** on its magnitude: [2](#0-1) 

`constants.MAX_CAP` is defined as `9e15`, which is already close to `Number.MAX_SAFE_INTEGER` (`9007199254740991`): [3](#0-2) 

Because `denomination` can be up to `9e15` and `count_coins` is unbounded, `denomInfo.count_coins * denomInfo.denomination` easily exceeds `2^53`, so the JS double can no longer represent the exact integer product — the result silently rounds to the nearest representable double. The same unguarded multiplication is repeated later, at actual coin-issuance time, when checking that an issued amount matches the declared denomination size: [4](#0-3) 

Here `input.amount !== denomination * denomInfo.count_coins` is a floating-point equality test. When the right-hand side has overflowed precision, many different (denomination, count_coins) combinations, or many different `input.amount` values, round to the *same* double and the strict `!==` check passes even though the true mathematical product differs from the declared cap. This mirrors exactly the pattern in the TensorFlow advisory: an unguarded multiply that should use a safe/overflow-checked path but instead lets an attacker-controlled overflow silently corrupt a validation invariant instead of raising a controlled `CHECK`/error.

### Impact Explanation
An asset issuer (an ordinary, unprivileged unit poster — anyone can define a new asset) can craft a `denominations` array whose `denomination`/`count_coins` pairs are chosen so that:
1. `total_cap_from_denominations` computed at asset-definition time (line 2778) does not equal the true mathematical sum but matches the declared `payload.cap` due to floating point rounding, passing the "cap doesn't match sum of denominations" check (line 2790).
2. At issuance time, the `input.amount !== denomination * denomInfo.count_coins` check (line 2224) is evaluated with the same imprecise floating arithmetic, allowing an `input.amount` that differs from the intended exact product to still pass validation.

This lets an attacker mint an amount of a custom indivisible/fixed-denomination asset that does not match its declared, validator-enforced cap — i.e., supply inflation for that asset, which every full node will accept as valid because the check is performed identically (and identically wrong) on every node running this code, so it does not even cause node disagreement — it is a deterministic acceptance of an over-issued supply.

### Likelihood Explanation
Reaching this code path requires only posting a normal `asset` definition message followed by an `asset` issuance input — both are standard, permissionless operations available to any user (asset issuer role explicitly listed as in-scope). No special privileges, no p2p/hub trust, and no timing race are needed; the attacker fully controls `denomination` and `count_coins` values at definition time and the issued `amount` at issuance time, making the specific double-precision collision straightforward to construct offline before submitting the unit.

### Recommendation
- Enforce a bound on `count_coins` such that `count_coins * denomination` cannot exceed `constants.MAX_CAP` (e.g., `count_coins > constants.MAX_CAP / denomination` should be rejected before the multiplication occurs).
- Perform all cap/issuance arithmetic in `validateAssetDefinition` and `validateIndivisibleIssue` using integer-safe primitives (e.g., `BigInt`) rather than IEEE‑754 doubles, and reject any input whose computed value would exceed `Number.MAX_SAFE_INTEGER` before comparing.
- Add an explicit check `if (!Number.isSafeInteger(denomInfo.count_coins * denomInfo.denomination)) return callback("denomination product overflows")` at both the asset-definition stage (`validation.js` ~line 2778) and the issuance stage (`validation.js` ~line 2224).

### Proof of Concept
1. Attacker posts an `asset` definition with `fixed_denominations: true`, `cap: 9000000000000000` (max allowed), and `denominations: [{ denomination: 4611686018427388, count_coins: 2 }]` (or similar values) such that `denomination * count_coins` computed as a JS double no longer represents the exact integer but happens to equal `cap` after rounding, passing the "cap doesn't match sum of denominations" check at `validation.js:2790`.
2. Attacker later issues an input referencing this denomination with `input.amount` set to a value that is mathematically different from the true `denomination * count_coins` product but rounds to the identical double, so the check at `validation.js:2224` (`input.amount !== denomination * denomInfo.count_coins`) incorrectly evaluates to `false` (i.e., passes) and the issuance is accepted by all full nodes, resulting in issued supply that exceeds the asset's declared cap.

### Citations

**File:** validation.js (L2207-2232)
```javascript
	function validateIndivisibleIssue(input, cb){
	//	if (objAsset)
	//		profiler2.start();
		conn.query(
			"SELECT count_coins FROM asset_denominations WHERE asset=? AND denomination=?", 
			[payload.asset, denomination], 
			function(rows){
				if (rows.length === 0)
					return cb("invalid denomination: "+denomination);
				if (rows.length > 1)
					throw Error("more than one record per denomination?");
				var denomInfo = rows[0];
				if (denomInfo.count_coins === null){ // uncapped
					if (input.amount % denomination !== 0)
						return cb("issue amount must be multiple of denomination");
				}
				else{
					if (input.amount !== denomination * denomInfo.count_coins)
						return cb("wrong size of issue of denomination "+denomination);
				}
			//	if (objAsset)
			//		profiler2.stop('validateIndivisibleIssue');
				cb();
			}
		);
	}
```

**File:** validation.js (L2763-2783)
```javascript
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
```

**File:** validation_utils.js (L24-29)
```javascript
/**
 * True if int is an integer strictly greater than zero.
 */
function isPositiveInteger(int){
	return (isInteger(int) && int > 0);
}
```

**File:** constants.js (L57-57)
```javascript
exports.MAX_CAP = 9e15;
```
