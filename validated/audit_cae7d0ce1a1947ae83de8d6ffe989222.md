### Title
Integer (floating-point) overflow in asset denomination cap validation allows the declared `cap` to diverge from the true value of a capped, fixed-denomination asset - ([File: validation.js])

### Summary
`validateAssetDefinition()` in `validation.js` computes the total face value backing a capped, fixed-denomination asset by summing `denomInfo.count_coins * denomInfo.denomination` for every entry in the attacker-supplied `denominations` array, then requires this sum to exactly equal the declared `cap`. Both `count_coins` and `denomination` are only checked with `isPositiveInteger()` (and an independent `<= MAX_CAP` bound on `denomination`, not on `count_coins`), so their product can exceed `Number.MAX_SAFE_INTEGER` (2^53‑1). Because the accumulator is a plain JS `number`, the multiplication and running sum silently lose precision (classic double-precision integer overflow) instead of throwing or rejecting the unit. This mirrors the CVE-2017-5333 bug class: an attacker-controlled size/count computation overflows and the resulting (silently wrong) value is trusted for a security-relevant consistency check. [1](#0-0) 

### Finding Description
The vulnerable computation is:

```
if (!isPositiveInteger(denomInfo.denomination))
    return callback("invalid denomination");
if (denomInfo.denomination > constants.MAX_CAP && (...))
    return callback("denomination exceeds MAX_CAP");
...
if ("count_coins" in denomInfo){
    if (!isPositiveInteger(denomInfo.count_coins))
        return callback("invalid count_coins");
    total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
}
``` [2](#0-1) 

`isPositiveInteger()` only verifies the value is a finite integer greater than zero - it places **no upper bound on `count_coins`**: [3](#0-2) 

Meanwhile `denomination` is bounded only by `MAX_CAP`, and `cap` itself is bounded by `MAX_CAP`: [4](#0-3) 

Since `denomination` can itself be close to `MAX_CAP` and `count_coins` can independently be an arbitrarily large positive integer (up to `Number.MAX_SAFE_INTEGER`), the product `count_coins * denomination` can vastly exceed 2^53. JavaScript silently rounds such products to the nearest representable double instead of erroring, and the summation (`total_cap_from_denominations +=`) compounds this imprecision across up to `MAX_DENOMINATIONS_PER_ASSET_DEFINITION` entries. The result is then checked with strict equality against the attacker-chosen `cap`:

```
if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
    return callback("cap doesn't match sum of denominations");
``` [5](#0-4) 

Because floating-point multiplication/rounding is deterministic, an attacker can pre-compute `count_coins`/`denomination` pairs whose IEEE-754 double product rounds to exactly match a chosen, in-range `cap` value, even though the mathematically true face value represented by the denominations is far larger than the declared cap. This is analogous to the icoutils bug where an attacker-controlled size computation overflowed and the wrapped value was trusted downstream, allowing a mismatch between believed and actual data size.

The corresponding "denomination * count_coins" recomputation used at issuance time (`validateIndivisibleIssue` in `validation.js`, and `issueNextCoin` in `indivisible_asset.js`) performs the *same* JS floating multiplication: [6](#0-5) [7](#0-6) 

so on a single node the overflow is self-consistent; the concrete risk is a **cross-implementation / cross-node arithmetic divergence**: any code path that re-derives the "true" total face value differently (e.g., BigInt-based tooling, wallets, exchanges, or future/alternate node implementations that do not reproduce the exact same double-precision rounding order) will compute a different total supply than what full nodes accepted as valid, producing disagreement about the real backing/cap of the asset and potential accounting/supply inconsistency for that asset.

### Impact Explanation
This is reachable by any unprivileged unit poster who authors an `asset` message (asset issuance is explicitly in scope). The invariant that is supposed to guarantee "declared cap == sum of denomination face values" for capped, fixed-denomination assets can be satisfied with attacker-chosen values whose true product diverges from the checked one due to floating-point overflow, undermining a supply-accounting invariant enforced only in JS double precision. This is a data-integrity/asset-accounting bug rather than a memory-safety one (as in the original CVE), but it is a concrete instance of the same integer-overflow bug class occurring in a security-relevant field-validation function.

### Likelihood Explanation
Triggering the overflow only requires crafting a single `asset` definition message with a `denominations` array containing values near `MAX_CAP`/`Number.MAX_SAFE_INTEGER`; no privileged access, race condition, or malicious peer/hub involvement is needed - any unit author can construct and broadcast such a unit.

### Recommendation
- Enforce an explicit upper bound on `count_coins` in `validateAssetDefinition()` (e.g., `count_coins <= MAX_CAP`) in `validation.js`.
- Validate that `count_coins * denomination` does not exceed `Number.MAX_SAFE_INTEGER` before performing the multiplication (or perform the multiplication/sum with `BigInt` and check the final `BigInt` value against `cap` and `MAX_CAP`).
- Apply the same fix to the redundant computations in `aa_validation.js`'s AA asset-definition validator, which mirrors this same unguarded `count_coins`/`denomination` logic. [8](#0-7) 

### Proof of Concept
Post an `asset` message (single-authored) with:
```
"denominations": [
  { "denomination": 9000000000000000, "count_coins": 9000000000000000 }
],
"cap": <value that the double-precision product 9e15 * 9e15 happens to round to, computed offline in Node.js>,
"fixed_denominations": true,
"issued_by_definer_only": true,
...
```
Because `9000000000000000 * 9000000000000000` is computed as a JS `number`, it is rounded to a nearest representable double far below the true mathematical product; by choosing `cap` equal to that rounded double, `validateAssetDefinition()`'s equality check (`payload.cap !== total_cap_from_denominations`) passes even though `cap` in no way reflects `count_coins × denomination` in exact arithmetic. This demonstrates the overflow is reachable and defeats the intended supply-consistency check at `validation.js:2778,2790-2791`. Full confirmation of downstream consequences (e.g., whether any external tooling/exchange logic that reconstructs the asset's true supply using exact/BigInt arithmetic would disagree with the on-chain accepted definition) was not verified further within the scope of this analysis and would require additional testing outside the indexed code.

### Citations

**File:** validation.js (L2210-2226)
```javascript
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
```

**File:** validation.js (L2735-2736)
```javascript
	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");
```

**File:** validation.js (L2769-2782)
```javascript
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
```

**File:** validation.js (L2788-2791)
```javascript
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
```

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

**File:** indivisible_asset.js (L533-536)
```javascript
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
```

**File:** aa_validation.js (L272-284)
```javascript
							if ("count_coins" in denomInfo) {
								if (typeof denomInfo.count_coins === 'number') {
									if (!isPositiveInteger(denomInfo.count_coins))
										return cb3("invalid count_coins");
								}
								else if (typeof denomInfo.count_coins === 'string') {
									var f = getFormula(denomInfo.count_coins);
									if (f === null)
										return cb3("bad formula in count_coins: "+ denomInfo.count_coins);
								}
								else
									return cb3("bad count_coins " + JSON.stringify(denomInfo.count_coins));
							}
```
