### Title
Integer-overflow-style precision loss in fixed-denomination asset cap validation allows declared cap to mismatch actual issuable supply - ([File: validation.js])

### Summary
`validateAssetDefinition` in `validation.js` sums `count_coins * denomination` across all denominations of a fixed-denomination asset using ordinary JS floating-point arithmetic, then compares that sum to the attacker-supplied `payload.cap`. `count_coins` has no upper bound (only `isPositiveInteger`), so this multiplication/summation can exceed `Number.MAX_SAFE_INTEGER` (2^53), producing the same class of bug as CVE-2005-1141: an attacker-controlled arithmetic operation on size-like fields that silently loses precision/overflows before being used to validate a critical invariant (declared cap vs. actual mintable amount).

### Finding Description
`isPositiveInteger()` in `validation_utils.js` only checks that a JS number is finite, an integer, and greater than zero — there is no upper bound at all: [1](#0-0) 

In `validateAssetDefinition`, when an asset is defined with `fixed_denominations: true`, each denomination's `count_coins` is validated only with `isPositiveInteger`, with no `MAX_CAP` check, while `denomination` is checked against `MAX_CAP` only conditionally (post `pemCurvesFixMci`/`hasBall` gate). The code then accumulates:
```
total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
```
and finally requires `payload.cap === total_cap_from_denominations`: [2](#0-1) 

Because `count_coins` is unbounded, an attacker can choose `count_coins` and `denomination` values whose product (and the running sum across up to `MAX_DENOMINATIONS_PER_ASSET_DEFINITION` denominations) exceeds `Number.MAX_SAFE_INTEGER`. At that magnitude, IEEE-754 double arithmetic rounds results to the nearest representable double, i.e. the JS-native analog of the C integer overflow in the CVE (silently wrong "wrapped"/rounded value instead of the true mathematical result). This lets `total_cap_from_denominations` collide with an attacker-chosen `payload.cap` value (which is separately bounded to `<= MAX_CAP` at line 2735) even though the true, arbitrary-precision sum of `count_coins * denomination` for the individual denomination rows (which get written verbatim as `BIGINT` into the `asset_denominations` SQL table, see `initial-db/*.sql`) does not actually equal `payload.cap`.

Each individual issuance is separately bounded by `input.amount > constants.MAX_CAP` in `validatePaymentInputsAndOutputs`: [3](#0-2) 
so no single issuing transaction can exceed `MAX_CAP`. However, the asset-definition-time consistency check between `payload.cap` and the sum of per-denomination capacities is the only safeguard tying the publicly declared "cap" (total supply ceiling communicated to wallets/holders) to the real per-denomination issuable amounts recorded in `asset_denominations`. Because that check is performed with lossy floating-point arithmetic on unbounded inputs, the declared cap can be made to not correspond to the real total amount that can eventually be issued across all of the asset's denominations, which are individually issued over time via `indivisible_asset.js`'s `issueNextCoin` using the exact `BIGINT` values stored in `asset_denominations`: [4](#0-3) 

### Impact Explanation
This affects an asset issuer (unprivileged unit poster) crafting an "asset" definition message. If the true total-issuable-amount (computed by summing exact integer `denomination * count_coins` values across denominations, as later executed against the database) differs from the declared `cap` due to floating-point precision loss during validation, then nodes and wallets that trust `assets.cap` as the enforced total supply ceiling for the asset can be misled: the actual number of coins mintable through repeated `issue` inputs (bounded individually by `MAX_CAP` per input, but not bounded in aggregate anywhere else) can diverge from the value communicated as the asset's cap. This is a supply-integrity issue for the affected custom asset — a form of unauthorized/uncontrolled asset inflation relative to its advertised cap, which can mislead holders about total supply and enable a "hidden inflation" of a specific token beyond what was represented in its definition.

### Likelihood Explanation
Triggering the mismatch requires the attacker (any account defining an asset) to choose `count_coins`/`denomination` pairs whose products lie in or beyond the region where IEEE-754 double precision loss occurs (≥ 2^53 ≈ 9.007×10^15) while still passing the individual `isPositiveInteger` checks (no upper bound on `count_coins`, and `denomination`'s `MAX_CAP` check is conditioned on chain height/`pemCurvesFixMci`). Crafting a collision between a rounded sum and a chosen `payload.cap` value is a matter of numerical trial (finding a combination of denominations that round to a convenient nearby double), which is a straightforward offline computation, not requiring any privileged access — just posting a normal, single-authored "asset" definition unit.

### Recommendation
- Reject denomination definitions where `denomInfo.count_coins * denomInfo.denomination` (or the running `total_cap_from_denominations`) exceeds `Number.MAX_SAFE_INTEGER`, or perform the summation using arbitrary-precision arithmetic (e.g. BigInt) instead of native JS floating point.
- Enforce `MAX_CAP` (or an equivalent sane bound) on `count_coins` unconditionally, not only on `denomination`, and remove/harden the height-gated (`pemCurvesFixMci`) conditional bypass on the `denomination > MAX_CAP` check so it always applies.
- After computing `total_cap_from_denominations`, additionally validate it against `MAX_CAP`/`TOTAL_WHITEBYTES`, not merely against the attacker-supplied `payload.cap`.

### Proof of Concept
1. Compute (offline) two or more `{denomination, count_coins}` pairs such that each `denomination <= MAX_CAP` and each `count_coins` is a large positive integer with no imposed bound, chosen so that `Σ (denomination_i * count_coins_i)`, evaluated with native JS double arithmetic, rounds to a target value `V` that is itself `<= MAX_CAP` (satisfying the separate `payload.cap` bound check).
2. Post an "asset" definition unit with `fixed_denominations: true`, `cap: V`, and `denominations: [{denomination_i, count_coins_i}, ...]` as constructed above.
3. `validateAssetDefinition` accepts the unit because `total_cap_from_denominations === payload.cap` under lossy float arithmetic, even though the exact integer sum of `denomination_i * count_coins_i` (which is what actually gets stored per-denomination in `asset_denominations` and later issued coin-by-coin via `issueNextCoin`) differs from `V`.
4. Over time, issue coins for each denomination up to its exact stored `count_coins` (each individual issue input staying under `MAX_CAP`); the asset's real maximum issuable supply diverges from the `cap` value that was validated and published in the asset's definition.

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

**File:** validation.js (L2315-2318)
```javascript
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue amount too large: " + input.amount)
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

**File:** indivisible_asset.js (L516-536)
```javascript
		function issueNextCoin(remaining_amount){
			console.log("issuing a new coin");
			if (remaining_amount <= 0)
				throw Error("remaining amount is "+remaining_amount);
			var issuer_address = objAsset.issued_by_definer_only ? objAsset.definer_address : arrAddresses[0];
			var can_issue_condition = objAsset.cap ? "max_issued_serial_number=0" : "1";
			conn.query(
				"SELECT denomination, count_coins, max_issued_serial_number FROM asset_denominations \n\
				WHERE asset=? AND "+can_issue_condition+" AND denomination<=? \n\
				ORDER BY denomination DESC LIMIT 1", 
				[asset, remaining_amount+tolerance_plus], 
				function(rows){
					if (rows.length === 0)
						return onDone(NOT_ENOUGH_FUNDS_ERROR_MESSAGE);
					var row = rows[0];
					if (!!row.count_coins !== !!objAsset.cap)
						throw Error("invalid asset cap and count_coins");
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
```
