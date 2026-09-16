### Title
Unchecked integer overflow in asset denomination cap sum allows fixed-denomination asset cap bypass - (File: validation.js)

### Summary
`validateAssetDefinition` in `validation.js` computes `total_cap_from_denominations` by summing `denomInfo.count_coins * denomInfo.denomination` for each denomination entry in an asset-definition message, then compares the result against the declared `payload.cap` to ensure they match. [1](#0-0)  Neither operand of the multiplication is bounded against overflow of JS's safe integer range: `denomInfo.denomination` is checked with `isPositiveInteger` and capped at `constants.MAX_CAP`, but `denomInfo.count_coins` is checked only with `isPositiveInteger`, which accepts any finite integer (including values far beyond `Number.MAX_SAFE_INTEGER`), with no upper bound comparison to `MAX_CAP` or any other limit. [2](#0-1) [3](#0-2) 

### Finding Description
This mirrors the CVE-2017-18255 pattern: a value used in an arithmetic/limit calculation (there, `sysctl_perf_cpu_time_max_percent`; here, `count_coins * denomination`) is not range-checked before being multiplied, so the computed limit (`total_cap_from_denominations`) can silently overflow/lose precision instead of failing safely. Because JavaScript numbers use IEEE-754 doubles, once `count_coins * denomInfo.denomination` exceeds `Number.MAX_SAFE_INTEGER` (2^53−1), the product is rounded to the nearest representable double. By choosing `count_coins` and `denomination` values whose true product overflows precision but whose rounded double happens to equal an attacker-chosen `payload.cap`, an attacker can post an asset-definition unit where the declared `cap` "matches" the summed denomination caps per the check `total_cap_from_denominations !== payload.cap` [4](#0-3) , even though the actual intended (mathematically correct) total secretly diverges from the declared cap. Since `denomination` and `count_coins` drive how many discrete indivisible-asset units of that denomination can later be issued, a rounding-driven mismatch between the nominal cap and the real allowed issuance opens the door to issuing more coin-units than the cap ostensibly bounds (supply inflation), because downstream issuance logic in `indivisible_asset.js`/`storage.js` (which also reference `count_coins`) trusts the previously "validated" cap consistency.

### Impact Explanation
If an attacker can craft a fixed-denomination asset definition where the overflowed sum passes the cap-equality check while true issuable supply exceeds the declared cap, this would allow issuance beyond the intended cap for that asset — a supply-inflation bug analogous to unauthorized minting. This affects any node validating the asset-definition unit and any wallet/AA trusting the asset's cap.

### Likelihood Explanation
Reaching this code requires only posting a valid, single-authored asset-definition message with `fixed_denominations: true` and a `denominations` array — a standard action available to any unprivileged unit poster or asset issuer, with no special privileges needed. [5](#0-4)  The `MAX_DENOMINATIONS_PER_ASSET_DEFINITION` limit only bounds array length, not per-entry value magnitude. However, exploitability depends on finding concrete `count_coins`/`denomination` pairs whose overflowed float product exactly collides with a chosen `cap` (a nontrivial but standard floating-point collision search), and on confirming that downstream issuance code (`indivisible_asset.js`) does not perform an independent, overflow-safe cap check using the raw `count_coins`/`denomination` fields rather than the pre-computed sum. This second point could not be fully verified within the available context — the index did not surface the exact issuance-time cap-enforcement code path, so the severity should be validated against `indivisible_asset.js` issuance logic before treating this as confirmed exploitable.

### Recommendation
Perform the cap-sum arithmetic using an overflow-safe method (e.g., `BigInt` or an explicit range check per term and running total against `constants.MAX_CAP` before allowing accumulation), and bound `count_coins` itself to a sane maximum (e.g., `<= constants.MAX_CAP`) analogous to the existing `denomInfo.denomination > constants.MAX_CAP` check. Reject any denomination definition where `count_coins * denomination` would exceed `Number.MAX_SAFE_INTEGER` before performing the multiplication.

### Proof of Concept
Not independently constructible/verifiable within the current investigation because it requires (a) confirming the exact `constants.MAX_CAP` numeric value and (b) confirming that `indivisible_asset.js` issuance validation does not redundantly re-check `count_coins * denomination` against `cap` using overflow-safe arithmetic at issuance time. Both points require deeper file access than the index surfaced; a Devin session with full repository access would be needed to pull `constants.js` (`MAX_CAP`, `MAX_DENOMINATIONS_PER_ASSET_DEFINITION`) and the issuance-time cap checks in `indivisible_asset.js` to construct concrete `count_coins`/`denomination`/`cap` values that trigger the float-rounding collision and confirm resulting over-issuance.

### Citations

**File:** validation.js (L2725-2735)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
```

**File:** validation.js (L2757-2791)
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
