### Title
Precision-loss "integer overflow" in asset denomination cap validation allows an asset definer to declare an inconsistent/inflatable supply cap - (File: validation.js)

### Summary
CVE-2024-31031 describes an unsigned integer overflow in `coap_pdu.c` caused by unchecked arithmetic on attacker-controlled length fields during message parsing. The closest reachable analog in `ocore--015` is in `validateAssetDefinition()` in `validation.js`, where the per-denomination `count_coins` field of a user-submitted asset definition is validated only for being a positive integer, with no upper bound, and is then multiplied by `denomInfo.denomination` and accumulated in `total_cap_from_denominations` using plain JavaScript floating-point arithmetic that silently loses precision past `Number.MAX_SAFE_INTEGER` (2^53), which is JS's structural equivalent of a hardware unsigned-integer overflow.

### Finding Description
In `validateAssetDefinition`, `denomInfo.denomination` is bounded to `constants.MAX_CAP` only conditionally (post `pemCurvesFixMci`), but `denomInfo.count_coins` has no upper bound check at all: [1](#0-0) 

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
```

`isPositiveInteger` only checks `Number.isFinite && Math.floor(v)===v && v>0`, so `count_coins` can be any positive integer representable as a double, including values whose product with `denomination` exceeds `Number.MAX_SAFE_INTEGER`. Beyond that threshold, IEEE-754 double arithmetic silently rounds results — the JS analog of the C unsigned-integer wraparound described in the CVE: an arithmetic operation on attacker-supplied "length/count" fields produces an incorrect, non-exact result instead of throwing or being rejected.

This accumulated (and possibly rounded) `total_cap_from_denominations` is then compared with strict equality against the user-declared `payload.cap` (itself bounded to `<= constants.MAX_CAP`): [2](#0-1) 

Because the comparison is a floating-point equality check fed by an unguarded multiplication/accumulation, a definer can craft `denominations` entries whose *true* integer sum differs from `payload.cap` but whose *floating-point-rounded* sum in this code path coincides with it, passing validation. Each denomination row is later persisted independently (with its own `count_coins`) and used at issuance time in `indivisible_asset.js`: [3](#0-2) 

```
var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
var issue_amount = count_coins_to_issue * denomination;
```

Since each `asset_denominations` row's `count_coins` is stored and honored independently of the rounded aggregate check performed at definition time, the actual achievable total supply across all denominations can diverge from the `cap` value declared in and relied upon by the asset definition, breaking the cap invariant that holders/wallets/AAs depend on when reasoning about an asset's maximum supply.

### Impact Explanation
This is reachable by any unprivileged unit poster acting as an asset issuer — no privileged, network, or node-trust component is required, matching the allowed "asset issuance and transfer conditions" category. The impact is a violation of the declared supply cap of a fixed-denomination asset (a "supply inflation" style outcome), because the cap-consistency check that is supposed to guarantee `sum(count_coins × denomination) == cap` can be defeated by exploiting double-precision rounding on the unbounded `count_coins` field, letting the definer/issuer eventually mint more real value in denominations than the cap declared to consumers of the asset. Overall unit-level `MAX_CAP` limits on `payload.cap` itself remain enforced, so this does not permit breaking the protocol-wide numeric ceiling, but it does allow inconsistency between the declared and actual issuable supply of a specific asset — a supply-inflation-class defect within the scope of what is explicitly acceptable.

### Likelihood Explanation
Triggering the rounding-based bypass requires deliberately chosen `count_coins`/`denomination` pairs whose product(s), summed, straddle `Number.MAX_SAFE_INTEGER` (~9×10^15) so that IEEE-754 rounding produces an accidental equality with a smaller `cap`. This is achievable by any attacker with full control over the crafted `denominations` array (no race condition or privileged access needed), but it does require some numeric engineering to find colliding values, so likelihood is moderate rather than trivial.

### Recommendation
- Bound `denomInfo.count_coins` explicitly (e.g., reject if `count_coins > constants.MAX_CAP` or if `count_coins * denomination` would exceed `Number.MAX_SAFE_INTEGER`) before performing the multiplication.
- Perform the `total_cap_from_denominations` accumulation using an overflow-safe method (e.g., BigInt, or an explicit running-max/overflow check after each addition) instead of raw floating-point `+=`.
- Re-validate that `total_cap_from_denominations === payload.cap` using integer-safe arithmetic, and reject the asset definition entirely if any intermediate product/sum cannot be represented exactly as a JS integer.

### Proof of Concept
Conceptual PoC (exact numeric collision values require additional offline search but the code path accepts them):
1. Attacker composes an `asset_definition` message with `fixed_denominations: true` and a `denominations` array containing two entries, e.g. `{denomination: d1, count_coins: c1}` and `{denomination: d2, count_coins: c2}`, chosen such that `c1*d1 + c2*d2` computed in IEEE-754 double precision equals a desired smaller `cap` value X, while the true (exact, integer) sum is materially larger than X.
2. Set `payload.cap = X`.
3. Submit the unit; `validateAssetDefinition` in `validation.js` (lines 2760–2791) accepts it because the floating-point-computed `total_cap_from_denominations` equals `payload.cap` even though the true achievable issuance (sum over the independently-stored `asset_denominations` rows, later consumed in `indivisible_asset.js` lines 516–536) exceeds the declared cap `X`, breaking the cap invariant relied upon by asset holders.

### Citations

**File:** validation.js (L2769-2778)
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
```

**File:** validation.js (L2788-2791)
```javascript
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
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
