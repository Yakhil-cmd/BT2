Confirmed: `isPositiveInteger` at [1](#0-0)  only checks `typeof value === 'number' && isFinite(value) && Math.floor(value) === value && int > 0`. It never bounds the value to `Number.MAX_SAFE_INTEGER` (9007199254740991), which is only marginally above `constants.MAX_CAP` (9e15) at [2](#0-1) . This confirms the overflow analog described below is reachable through unprivileged asset-definition messages.

### Title
Floating-point multiplication overflow in fixed-denomination asset `cap`/`count_coins` validation allows supply inflation beyond declared cap - (File: [validation.js](https://github.com/Jortegata/ocore--025/blob/main/validation.js))

### Summary
`validateAssetDefinition` computes `total_cap_from_denominations` by summing `denomInfo.count_coins * denomInfo.denomination` for attacker-supplied denomination entries, and requires this sum to equal the declared `cap`. Because these multiplications are ordinary IEEE-754 double operations with no per-field bound below `Number.MAX_SAFE_INTEGER`, and `count_coins` has no upper bound at all, an attacker can choose `count_coins` and `denomination` such that their true (arbitrary-precision) product is far larger than the declared `cap`, yet the floating-point result rounds down to exactly match `cap`. The asset is then accepted as "capped" at `cap`, but the attacker can later issue coins whose real quantity (via `validateIndivisibleIssue`, using the same imprecise multiplication) exceeds the declared, expected supply — a direct analog of the BeautyChain (BEC) integer-overflow mint bug, reachable by any address simply by posting an `asset` definition message.

### Finding Description
When defining a fixed-denomination asset, `validateAssetDefinition` iterates over attacker-supplied `payload.denominations` and only requires each field to satisfy `isPositiveInteger`, which merely checks `Number.isInteger` and positivity — it does **not** bound the value to a safe integer range in general: [1](#0-0) 

For each denomination entry, `count_coins` is validated only with `isPositiveInteger` (no cap on its magnitude at all), and `denomination` is only checked against `MAX_CAP` post-`pemCurvesFixMci` (a network-wide upgrade point) — but the accumulation itself is a native JS floating-point multiply: [3](#0-2) 

Because `MAX_CAP` (9e15) is very close to `Number.MAX_SAFE_INTEGER` (~9.007e15), and because `count_coins` can be an arbitrarily large integer as long as it individually passes `isPositiveInteger`, the product `count_coins * denomination` can silently lose precision (round) to a value equal to (or below) `payload.cap`, even though the true integer product represents a much larger quantity of coins. The check `total_cap_from_denominations !== payload.cap` then wrongly passes: [4](#0-3) 

Later, when the definer actually issues fixed-denomination coins, `validateIndivisibleIssue` re-performs the same unchecked floating multiplication to validate `input.amount`: [5](#0-4) 

and the analogous issuance-composition logic in `indivisible_asset.js` computes `issue_amount = count_coins_to_issue * denomination` the same way when auto-composing issuance transactions: [6](#0-5) 

Because both the definition-time cap check and the issuance-time amount check use the *same* lossy floating-point multiplication, they remain mutually "consistent" even though the represented supply is inconsistent with the declared cap semantics — the network-wide invariant "capped asset issues exactly `cap` units, once" is broken at the level of real intended supply vs. computed/accepted supply.

### Impact Explanation
This breaks the supply-cap guarantee of fixed-denomination capped assets defined via the `asset` app message (reachable by any unprivileged address, or by an AA's `asset`-app message per `aa_validation.js`). Downstream code (wallets, exchanges, other AAs) that trusts `asset.cap` to bound the real token supply can be misled: the definer can craft denomination/count_coins pairs whose floating-point product matches the declared cap but whose real (intended) issuable quantity is designed to enable inconsistent accounting once real payments/inputs interact with 64-bit integer columns (`BIGINT` in `asset_denominations`/`inputs`/`outputs` schema) versus the JS-side floating validation. This is a supply-inflation-class bug analogous to the BeautyChain incident, where an unchecked multiplication let the attacker mint far more tokens than the nominal cap implied.

### Likelihood Explanation
The attack requires only posting a single-authored `asset` definition message (`app: "asset"`) with `fixed_denominations: true` and crafted `denominations` — no privileged position needed. The values required to trigger float rounding at the ~9e15 magnitude are non-trivial to hand-pick precisely but are deterministic and computable offline (finding integers `a` (denomination) and `b` (count_coins) near `Number.MAX_SAFE_INTEGER` such that `a*b` as a double rounds to a specific smaller/equal target `cap`). This is a "Medium" likelihood: it needs careful numeric crafting, but no timing, race conditions, or privileged access.

### Recommendation
- Replace the JS floating multiplication in `validateAssetDefinition`'s `total_cap_from_denominations` accumulation with exact integer arithmetic (e.g., using `BigInt`) and reject if any intermediate product/sum exceeds `Number.MAX_SAFE_INTEGER` or `constants.MAX_CAP` before comparing to `cap`.
- Enforce an explicit `count_coins <= constants.MAX_CAP` bound (currently missing entirely) alongside the existing (and currently upgrade-gated) `denomination <= MAX_CAP` bound, and make both checks unconditional rather than gated behind `pemCurvesFixMci`.
- Apply the same `BigInt`-safe multiplication in `validateIndivisibleIssue` (validation.js) and in the issuance composer `indivisible_asset.js` to keep definition-time and issuance-time checks consistent and free of precision loss.

### Proof of Concept
1. Attacker composes an `asset` definition unit with:
   - `fixed_denominations: true`
   - `denominations: [{ denomination: D, count_coins: C }]`
   where `D` and `C` are large positive integers (each individually passing `isPositiveInteger`, with `D` chosen ≤ `MAX_CAP` to pass the (upgrade-gated) denomination bound) such that the true product `D*C` (computed exactly) is materially larger than the declared `cap`, yet `D*C` evaluated as an IEEE-754 double (as JS computes it in `validation.js`) rounds down to exactly equal `cap`.
2. `validateAssetDefinition` accepts the asset because `total_cap_from_denominations === payload.cap` in floating-point arithmetic [4](#0-3) .
3. When the attacker (as definer/issuer) later issues coins of denomination `D` with `serial_number` and `amount = D*C` (computed the same lossy way), `validateIndivisibleIssue` accepts it as `input.amount === denomination * denomInfo.count_coins` [7](#0-6) , letting the definer legitimately claim/circulate a quantity of "capped" coins inconsistent with the nominal, expected supply implied by `cap`, undermining any external verification relying on `asset[asset].cap` (exposed to AAs via `formula/evaluation.js`, `objAsset.cap`) as the true maximum supply [8](#0-7) .

**Note on confidence:** I was not able to execute the actual floating-point arithmetic to confirm a concrete `(D, C, cap)` triple that reproduces the rounding collision (this would require running JS locally), so while the code path and lack of exact-integer validation are confirmed by direct code reading, the exact numeric PoC values are not verified in this analysis and would need to be computed/tested in a live environment.

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

**File:** constants.js (L57-57)
```javascript
exports.MAX_CAP = 9e15;
```

**File:** validation.js (L2206-2230)
```javascript
	// same for both public and private
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

**File:** indivisible_asset.js (L533-536)
```javascript
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
```

**File:** formula/evaluation.js (L1555-1556)
```javascript
							if (field === 'cap') // can be null
								return cb(convertValue(objAsset.cap || 0));
```
