### Title
Integer-overflow / precision-loss in fixed-denomination asset cap validation allows an asset issuer to bypass the declared `cap` - (File: `validation.js`)

### Summary
The CVE describes an unguarded integer multiplication (`sz * nBig`) whose result is not cast to a wide-enough type before being used to size a memory allocation, letting an attacker supply values that silently overflow and corrupt the computed size. `ocore` has a structurally analogous flaw in `validateAssetDefinition()`: the sum used to verify that a fixed-denomination asset's `denominations` add up to its declared `cap` is computed as a plain JS-number multiplication/accumulation with no bound on one of the two factors, so the result can silently lose precision (JS numbers are IEEE-754 doubles, exact only up to `Number.MAX_SAFE_INTEGER = 2^53-1`) and no longer represent the true total.

### Finding Description
When an author defines an asset with `fixed_denominations: true`, each denomination entry is validated in `validateAssetDefinition()`: [1](#0-0) 

- `denomInfo.denomination` is bounded (`isPositiveInteger` and, after `pemCurvesFixMci`, `<= constants.MAX_CAP` i.e. `9e15`).
- `denomInfo.count_coins` is only checked with `isPositiveInteger` — **no upper bound at all** is enforced on `count_coins`.
- The running total is accumulated as `total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;`, a native JS double multiplication/addition.

Because `count_coins` is unbounded, an attacker can choose `count_coins` and `denomination` pairs whose true product/sum vastly exceeds `Number.MAX_SAFE_INTEGER` (`9007199254740991`). At that magnitude, IEEE-754 double arithmetic silently rounds results to the nearest representable double, so multiple distinct, very-large true totals collapse onto the same floating-point value. The subsequent consistency check: [2](#0-1) 
only requires `payload.cap === total_cap_from_denominations` — an attacker can pick `count_coins`/`denomination` combinations that make the lossy floating-point `total_cap_from_denominations` collide with an attacker-chosen, much smaller `payload.cap`, passing this check even though the real, per-row sum of `denomination * count_coins` is many orders of magnitude larger.

Crucially, the *real* per-denomination issuance is gated later purely by the exact stored `count_coins`/`denomination` values, not by the lossy sum: [3](#0-2) 
`asset_denominations.count_coins` is stored directly from the attacker's declared payload: [4](#0-3) 
So the definition-time "cap matches sum of denominations" sanity check is the *only* place that is supposed to prevent an asset from being defined with a `cap` field that understates its real issuable supply — and it can be defeated by floating-point precision loss, since `MAX_CAP` (`9e15`) bounds only `denomination`, not `count_coins`, and the summation itself is unchecked native-double arithmetic exactly analogous to the unguarded `sz*nBig` multiplication in the CVE.

### Impact Explanation
This is a supply-inflation class bug: an asset issuer (any unprivileged unit poster who defines a new asset) can publish a `fixed_denominations` asset whose `cap` field advertises a small, "capped" total while the underlying `asset_denominations` rows in fact allow issuance of a supply far above that cap once summed with correct (non-lossy) arithmetic. Wallets, exchanges, and AAs that trust the declared `cap` as the asset's maximum supply would be misled, and the issuer could subsequently issue coins up to the real (much larger) total permitted by the individual denomination rows, diluting/inflating the asset beyond its advertised cap — a concrete supply-inflation outcome in the accepted impact list.

### Likelihood Explanation
Reachable by any single unprivileged unit author who posts an `asset` definition message — no privileged role, no p2p/hub assumption, no crypto break required. The attacker only needs to choose `count_coins`/`denomination` values whose true product exceeds `2^53` such that double-precision rounding collides with the desired smaller `cap`; this is a deterministic, repeatable floating-point construction, not a probabilistic attack, making it straightforward to script.

### Recommendation
- Bound `count_coins` explicitly (e.g., `count_coins <= constants.MAX_CAP`) the same way `denomination` is bounded.
- Perform the cap-consistency sum using exact/big-integer arithmetic (or validate that `denomination * count_coins` and the running total never exceed `Number.MAX_SAFE_INTEGER`, rejecting the definition otherwise) instead of native JS double accumulation in `validateAssetDefinition()` (validation.js lines 2760-2791).
- Add a regression test defining denominations whose true sum exceeds `2^53` but whose floating-point sum collides with a smaller declared `cap`, asserting the asset definition is rejected.

### Proof of Concept
1. Attacker crafts an `asset` message with `fixed_denominations: true` and two denomination entries, e.g. `{denomination: d1, count_coins: c1}` and `{denomination: d2, count_coins: c2}`, chosen such that the exact integer sum `d1*c1 + d2*c2` is far above `2^53` (e.g. ~10^16–10^18) but, once each product exceeds double precision and is rounded, the JS-computed `total_cap_from_denominations` equals an attacker-chosen small `cap` value (e.g. `1e6`).
2. Set `payload.cap = 1e6` (or whatever the collided rounded value is).
3. `validateAssetDefinition()` (validation.js:2757-2791) passes because `total_cap_from_denominations === payload.cap` in floating point, even though the true sum of `denomination*count_coins` across the rows is vastly larger.
4. The asset is accepted and written; `asset_denominations` rows retain the attacker's real, huge `count_coins` values (writer.js:236-242).
5. Later issuance validation (`validation.js:2219-2226`) checks issuance against the real per-row `count_coins`/`denomination`, not the (fooled) `cap`, letting the issuer mint far more supply than the `cap` field advertised.

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

**File:** validation.js (L2763-2779)
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
```

**File:** validation.js (L2786-2791)
```javascript
		if (bHasUncappedDenominations && payload.cap)
			return callback("has cap but some denominations are uncapped");
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
```

**File:** writer.js (L236-242)
```javascript
							if (asset.denominations){
								for (var j=0; j<asset.denominations.length; j++){
									conn.addQuery(arrQueries, 
										"INSERT INTO asset_denominations (asset, denomination, count_coins) VALUES(?,?,?)",
										[objUnit.unit, asset.denominations[j].denomination, asset.denominations[j].count_coins]);
								}
							}
```
