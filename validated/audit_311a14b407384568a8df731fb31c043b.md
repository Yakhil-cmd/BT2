### Title
Integer-overflow-style precision loss in asset denomination cap calculation - (File: validation.js)

### Summary
`validateAssetDefinition()` computes `total_cap_from_denominations` by summing `denomInfo.count_coins * denomInfo.denomination` for every denomination entry in a user-posted `asset` definition message, then compares this sum against the asset's declared `cap`. Neither factor of the multiplication is bounded relative to the other before the multiplication is performed, so the product can exceed `Number.MAX_SAFE_INTEGER` and silently lose precision — the JS-numeric analogue of the C integer overflow in the CVE (audiofile computes an unchecked product/sum from attacker-supplied length fields, corrupting a downstream size check).

### Finding Description
In `validateAssetDefinition()`: [1](#0-0) 
each `denomInfo.denomination` is checked to be a positive integer and (only conditionally, gated on `pemCurvesFixMci`/stability) `<= constants.MAX_CAP`, and `denomInfo.count_coins` is checked only with `isPositiveInteger` — with **no upper bound at all**: [2](#0-1) 

The code then accumulates:
```
total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
```
Because `count_coins` has no cap, an attacker can choose `count_coins` and `denomination` such that their product exceeds `Number.MAX_SAFE_INTEGER` (2^53-1). JavaScript numbers silently lose integer precision beyond this point (rounding instead of wrapping, but functionally the same class of bug as the C `int` overflow in the CVE: an attacker-controlled multiplication/sum of length-like fields produces a corrupted result that downstream logic trusts).

The corrupted `total_cap_from_denominations` is then compared to `payload.cap`: [3](#0-2) 
If `payload.cap` is set to a rounded/aliased value that happens to equal the precision-lossy sum, the check `total_cap_from_denominations && payload.cap !== total_cap_from_denominations` can pass even though the true (mathematically exact) sum of `count_coins × denomination` per denomination is different (larger) than the declared `cap`. This defines an asset whose declared cap does not truly bound the sum of coins mintable across its denominations.

### Impact Explanation
If the true issuable supply implied by the denomination table can exceed the nominal `cap` due to this precision loss, it could permit issuance of more total value than the asset's cap is supposed to allow (supply inflation for that custom asset), an Impact category explicitly listed as acceptable in scope (asset issuance / supply inflation). This is Medium severity, matching the CVE's severity, and is reachable by any single unit poster defining a custom asset — no privileged actor required.

### Likelihood Explanation
Likelihood is constrained by two factors I could not fully verify given index limits:
1. Whether `indivisible_asset.js` issuance logic re-derives/enforces the cap per-denomination independently of `total_cap_from_denominations` (which would neutralize the bug) — I found references to `cap` in `indivisible_asset.js` but could not view its full content to confirm how per-denomination issuance limits are enforced at write time.
2. The magnitude needed: `count_coins` and `denomination` must jointly multiply past 2^53 while `denomination` itself individually may still be `<= MAX_CAP` (I could not retrieve the exact value of `constants.MAX_CAP` from `constants.js` before the session ended, so I cannot confirm whether `MAX_CAP` alone is already large enough that a single denomination's `count_coins` could reach the required magnitude, or whether multiple denomination lines are needed to reach the overflow region).

Given these open items, I can prove the root-cause defect (missing bound on `count_coins`, unchecked multiplication into a JS number) with certainty, but cannot fully confirm exploitability through to final coin issuance without seeing the enforcement path in `indivisible_asset.js`/`writer.js` for capped, multi-denomination assets.

### Recommendation
- Bound `denomInfo.count_coins` (e.g., `<= constants.MAX_CAP`) the same way `denomInfo.denomination` is bounded, unconditionally (not gated behind an upgrade MCI check).
- Perform the `count_coins * denomination` multiplication using a big-integer-safe method (e.g., reject early if either operand `> Number.MAX_SAFE_INTEGER / other operand`, or use `BigInt` for the accumulation and cap comparison) so that no precision loss can occur before the `payload.cap` equality check.
- Audit `indivisible_asset.js`'s issuance path to confirm it re-validates that cumulative issued amounts per denomination never exceed `count_coins`, independent of the declared `cap`, as defense in depth.

### Proof of Concept
1. Attacker crafts an `asset` definition message (single-authored, `issued_by_definer_only: true`, `fixed_denominations: true`) with denominations array:
   - `{ denomination: D1, count_coins: C1 }` where `D1 * C1` alone, or combined with additional denomination entries, produces a floating-point sum that exceeds `Number.MAX_SAFE_INTEGER`, causing the actual mathematical sum to round to some value `V_rounded` in IEEE-754 double representation.
2. Attacker sets `payload.cap = V_rounded` (the rounded/aliased value), which satisfies:
   ```
   total_cap_from_denominations === payload.cap  // due to float rounding, not true equality
   ```
3. The asset definition passes `validateAssetDefinition()` and is accepted into the DAG.
4. Depending on how `indivisible_asset.js` enforces per-denomination issuance limits at coin-issue time (unverified — see Likelihood), the definer may be able to issue coins whose true total value exceeds the intended `cap`, inflating the asset's effective supply beyond its stated limit.

### Citations

**File:** validation.js (L2763-2792)
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
