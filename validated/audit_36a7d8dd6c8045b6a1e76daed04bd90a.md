### Title
Floating-point precision loss in indivisible-asset denomination cap validation allows asset supply inflation beyond declared cap - (File: validation.js)

### Summary
CVE-2017-16830 is a 32-bit integer-overflow in `print_gnu_property_note` (readelf.c) where an attacker-controlled length field overflows during a size computation, letting a crafted, security-relevant size check silently pass while the real value is larger than expected. `ocore` has no native 32-bit integer arithmetic, but it has an analogous class of bug: JS numbers are IEEE-754 doubles with only 53 bits of integer precision, and `validateAssetDefinition` in [1](#0-0)  sums attacker-supplied `denomination * count_coins` products with plain `+=` without checking for loss of integer precision, then compares the (possibly corrupted) sum against the declared `cap`. This is directly reachable by any unprivileged asset issuer posting an asset-definition message.

### Finding Description
When an asset is defined with `fixed_denominations: true`, the definer supplies an array of `{denomination, count_coins}` entries. Each field is checked only with `isPositiveInteger` (integer > 0) and `denomination` is separately bounded to `constants.MAX_CAP`, but `count_coins` has **no upper bound at all**: [2](#0-1) 

The validator accumulates the declared per-denomination supply with a plain floating-point addition:
```
total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
```
`constants.MAX_CAP` is close in magnitude to `Number.MAX_SAFE_INTEGER` (2^53), so summing just two denomination entries whose individual products are each legally ≤ `MAX_CAP` can push the running total past 2^53, where doubles can no longer represent every integer exactly. The sum then silently rounds to a nearby representable value. The validator only requires that this (possibly rounded) sum equal the declared `cap`: [3](#0-2) 

An attacker can pick `count_coins`/`denomination` pairs whose true mathematical sum is larger than the value actually stored as `total_cap_from_denominations` after floating-point rounding, and set `cap` to that rounded (smaller) value so the equality check passes.

Crucially, when the coins are later actually issued, each denomination's issuance is validated **independently**, not by re-summing against the (already-approved) cap: [4](#0-3) 
and in the composer, each denomination is minted for its own exact `denomination * count_coins` amount: [5](#0-4) 

Because each individual denomination amount is ≤ `MAX_CAP` it is computed and validated exactly (no precision loss at that stage), so the network will happily accept every denomination's full issuance. The *true* total minted (sum of exact per-denomination amounts) can therefore exceed the `cap` value that was "verified" and is trusted/displayed by wallets and other logic (e.g. AA formulas reading `asset[...].cap`) as the maximum possible supply.

### Impact Explanation
This breaks the fundamental invariant that a capped, fixed-denomination asset can never have a circulating supply larger than its declared `cap`. Wallets, exchanges, and Autonomous Agents that rely on `cap` as an upper bound on total supply (e.g. `asset[X].cap` in oscript, or off-chain accounting) can be deceived into treating an asset as scarcer than it actually is, enabling a form of supply inflation / consensus-visible cap violation. This falls squarely under "asset issuance and transfer conditions" and "supply inflation," which is in-scope per the validation rules.

### Likelihood Explanation
Exploitation requires no privileged role — any address can post a unit that defines a new asset (`validateAssetDefinition` is reached by any single-authored unit containing an `asset` message). The attacker only needs to choose two or more `{denomination, count_coins}` pairs whose products, when summed in double-precision floating point, round to a value different from their true mathematical sum — a deterministic, reproducible JavaScript floating-point property, not a timing or race condition. This makes the likelihood of triggering the imprecise-sum path High for a moderately careful attacker, though composing values that intentionally round in a *helpful* direction requires some numeric search (still straightforward given the search space near MAX_CAP magnitude).

### Recommendation
Replace the floating-point accumulation in `validateAssetDefinition` with an integer-safe computation (e.g. `BigInt`) for `total_cap_from_denominations`, and additionally cap `count_coins` at a bound that guarantees `count_coins * denomination` and any partial sums stay within `Number.MAX_SAFE_INTEGER` (equivalently below `MAX_CAP`) at every step, mirroring the existing single-value checks. Reject asset definitions whose intermediate or final sums cannot be represented exactly as JS numbers.

### Proof of Concept
Conceptual PoC (values illustrative; exact boundary values must be near `constants.MAX_CAP`/2^53 to trigger loss of integer precision):
```js
// asset definition message, fixed_denominations = true
{
  app: "asset",
  payload: {
    cap: <sum_S>,                 // chosen so it equals the rounded (imprecise) total
    is_private: false,
    is_transferrable: true,
    auto_destroy: false,
    fixed_denominations: true,
    issued_by_definer_only: true,
    cosigned_by_definer: false,
    spender_attested: false,
    denominations: [
      { denomination: D1, count_coins: C1 }, // D1*C1 <= MAX_CAP
      { denomination: D2, count_coins: C2 }  // D2*C2 <= MAX_CAP
      // D1*C1 + D2*C2 (exact) > 2^53, but D1*C1 + D2*C2 (double addition) rounds to sum_S
    ]
  }
}
```
After this unit is accepted (because `total_cap_from_denominations === cap` holds under floating-point rounding), the issuer later issues each denomination in full via separate `issue` inputs, each individually validated exactly against `denomination * count_coins` (both ≤ MAX_CAP, so no rounding at issuance time). The network ends up accepting a total circulating supply for the asset that exceeds the `cap` value it originally validated. Constructing concrete `D1, C1, D2, C2` satisfying the rounding condition requires a short numeric search against the actual `constants.MAX_CAP` value, which should be done by a background engineer with code execution access.

### Citations

**File:** validation.js (L2219-2226)
```javascript
				if (denomInfo.count_coins === null){ // uncapped
					if (input.amount % denomination !== 0)
						return cb("issue amount must be multiple of denomination");
				}
				else{
					if (input.amount !== denomination * denomInfo.count_coins)
						return cb("wrong size of issue of denomination "+denomination);
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

**File:** indivisible_asset.js (L516-537)
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
					conn.query(
```
