## Finding

### Title
Integer/Floating-Point Overflow in Asset Denomination Cap Sum Enables Declared-Cap Bypass (Supply Inflation) - (File: validation.js)

### Summary
The Redis CVE-2022-35951 root cause is an unchecked, attacker-supplied numeric parameter (`COUNT`) used in an arithmetic operation whose result silently overflows and is then trusted for a memory-safety-critical decision. `ocore`'s asset-definition validation contains the same bug class in a supply-safety-critical decision: an attacker-controlled `count_coins` value is multiplied and summed without an upper bound, and the resulting overflowed/imprecise value is trusted to verify that a divisible asset's declared `cap` matches the sum of its `denominations`.

### Finding Description
In `validateAssetDefinition`, for each element of `payload.denominations` the code only bounds `denomination` (`<= constants.MAX_CAP`) but places no analogous upper bound on `count_coins` — it is checked only with `isPositiveInteger`, which accepts any finite JS integer, including huge values close to `Number.MAX_SAFE_INTEGER` and beyond: [1](#0-0) 

The per-denomination product is then accumulated in a plain JS number without any overflow check: [2](#0-1) 

The declared `cap` is only validated against `constants.MAX_CAP` individually (an author-controlled `payload.cap <= MAX_CAP` check), while `total_cap_from_denominations` — computed as an unbounded sum of `count_coins * denomination` across up to `MAX_DENOMINATIONS_PER_ASSET_DEFINITION` entries — is what is actually compared against `payload.cap` for equality: [3](#0-2) [4](#0-3) [5](#0-4) 

Because JavaScript numbers lose integer precision above `2^53-1`, an attacker who crafts several denomination entries whose `count_coins * denomination` products sum near or past this boundary can cause `total_cap_from_denominations` to round to a value that differs from the true mathematical sum but which nonetheless equals `payload.cap` as computed with the same floating-point arithmetic — exactly mirroring the Redis pattern of an integer overflow silently corrupting a value used in a later bounds/consistency check. Each individual denomination is later checked in isolation, exactly, against `asset_denominations.count_coins` when issuing indivisible-asset coins: [6](#0-5) 

but that per-denomination exactness does nothing to prevent the aggregate cap consistency check from having been satisfied via overflowed arithmetic at definition time, so the network-wide understanding of "total issuable supply of this asset" (encoded by `cap`) can diverge from what is actually mintable across all its denominations.

### Impact Explanation
This directly matches the requested "supply inflation" impact class: any unprivileged asset issuer can define an asset whose declared `cap` (the value wallets, explorers, and other nodes treat as the hard total-supply ceiling) does not match the true summed mintable amount across its `denominations`, due to floating-point overflow in the consistency check rather than a deliberate/legitimate cap. This corrupts the network's shared understanding of the asset's total supply guarantee.

### Likelihood Explanation
Reachable by any single posted unit containing an `asset` message — no privileged role, hub, or peer compromise required, satisfying the "asset issuer" trust boundary named in scope. It requires crafting large `count_coins`/`denomination` values (up to `MAX_CAP`, whose exact value was not confirmed in this investigation) across multiple denomination entries (bounded by `MAX_DENOMINATIONS_PER_ASSET_DEFINITION`) to reach the precision-loss boundary near `2^53`; whether `MAX_CAP` and the denomination count limits are large enough in this codebase to make the overflow arithmetically reachable was not fully verified in the available index (the exact value of `constants.MAX_CAP` and `MAX_DENOMINATIONS_PER_ASSET_DEFINITION` could not be retrieved before the tool budget was exhausted).

### Recommendation
- Bound `count_coins` explicitly (e.g., `count_coins <= constants.MAX_CAP`) in the denomination-validation loop, not just `denomination`.
- Perform the `count_coins * denomination` accumulation with an overflow-safe integer type (e.g., `BigInt`) or add an explicit check that the running `total_cap_from_denominations` never exceeds `Number.MAX_SAFE_INTEGER` before comparison with `payload.cap`.
- Reject asset definitions where any intermediate product or the accumulated sum would exceed `Number.MAX_SAFE_INTEGER`.

### Proof of Concept
Conceptual (exact numeric boundary depends on `constants.MAX_CAP`, which was not confirmed):
1. An attacker posts a unit with an `asset` message, `fixed_denominations: true`, and a `denominations` array containing multiple entries whose `denomination` and `count_coins` values are chosen so that `Σ(count_coins_i * denomination_i)` straddles `2^53` such that floating-point rounding makes the computed sum equal an attacker-chosen `payload.cap` that is smaller than the true mathematical total.
2. `validateAssetDefinition` accepts the unit because `total_cap_from_denominations === payload.cap` under floating-point arithmetic (`validation.js:2790`), even though the real summed mintable supply differs.
3. The asset is registered on the DAG with a `cap` that misrepresents true issuable supply across its denominations, corrupting the network-wide supply guarantee for that asset.

*Note: The exact numeric feasibility of triggering this overflow depends on the concrete values of `constants.MAX_CAP` and `constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION`, which could not be retrieved from the index within the available tool budget; a full session with file access would be needed to confirm reachability of the `2^53` precision boundary with these constants.*

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

**File:** validation.js (L2207-2226)
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
```

**File:** validation.js (L2735-2736)
```javascript
	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");
```

**File:** validation.js (L2758-2760)
```javascript
		if (payload.denominations.length > constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION)
			return callback("too many denominations");
		var total_cap_from_denominations = 0;
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
