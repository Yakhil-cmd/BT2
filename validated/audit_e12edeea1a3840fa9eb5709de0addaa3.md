### Title
Precision-loss overflow in asset denomination cap validation allows cap/count_coins mismatch - ([File: validation.js])

### Summary
`validateAssetDefinition()` in `validation.js` computes the total issuable supply of a custom asset from attacker-controlled `denominations` array entries by multiplying two unbounded 64-bit-range integers (`count_coins * denomination`) and accumulating the result in a plain JavaScript `Number` (IEEE-754 double). This mirrors the libsndfile CVE-2026-37555 bug class: two int-typed, attacker-controlled fields are multiplied without checking that the product stays within the safe/representable range of the accumulator type, and the resulting truncated/imprecise value is then used to enforce a security-relevant invariant (that declared `cap` matches the sum of per-denomination `count_coins * denomination`).

### Finding Description
In `validateAssetDefinition`: [1](#0-0) 
`denomInfo.denomination` is bounded by `constants.MAX_CAP` at line 2771, but `denomInfo.count_coins` is only checked with `isPositiveInteger`, which imposes no upper bound: [2](#0-1) 
`isPositiveInteger`/`isInteger` merely checks `Math.floor(value) === value`, which is trivially true for large floats like `1e18` even though such values no longer represent every integer precisely once they exceed `Number.MAX_SAFE_INTEGER` (2^53). Because `count_coins` has no upper bound, an attacker who authors an asset-definition unit can supply multiple denomination entries whose `count_coins * denomination` products, when summed into `total_cap_from_denominations`, exceed `Number.MAX_SAFE_INTEGER`. At that point IEEE-754 double arithmetic silently rounds the accumulated value, exactly analogous to the 32-bit integer overflow in the CVE (there, `samplesperblock * blocks` silently wrapped in a 32-bit product before being assigned to a 64-bit field). Here, the "overflow" manifests as precision loss/rounding in the double-precision accumulator rather than 2's-complement wraparound, but the underlying flaw is the same: an unbounded product of two attacker-controlled integers is computed and relied upon for a correctness/security check without first bounding the inputs or the intermediate product.

The corrupted `total_cap_from_denominations` is then compared against the asset's declared `payload.cap`: [3](#0-2) 
An attacker can craft `denominations` entries such that the rounded, imprecise sum happens to equal a crafted `payload.cap`, while the "true" (unrounded) sum implied by the individual `denomination`/`count_coins` pairs is different. This breaks the invariant the check is meant to enforce — that the sum of per-denomination capped supplies equals the asset's advertised cap — because the comparison is performed on a value that has already lost precision.

### Impact Explanation
The `cap` field of an asset definition is a security-relevant invariant used throughout indivisible-asset issuance (`indivisible_asset.js`) to decide how many coins of each denomination may ever be issued (`asset_denominations.max_issued_serial_number`, `count_coins`, `denomination`) — see the issuance code that multiplies `count_coins_to_issue * denomination` to build `issue_amount`: [4](#0-3) 
If the cap-vs-denominations check can be defeated via precision loss, an asset could be defined with a declared `cap` that does not actually match the true sum of coins mintable across its denominations, undermining the guarantee that total issuance for a capped asset is bounded — a form of supply-accounting corruption reachable by any unprivileged unit poster who authors an asset-definition message.

### Likelihood Explanation
Reachable by any single unprivileged unit poster: asset definitions are ordinary application payloads validated by `validateAssetDefinition`, requiring no special privilege, hub/peer trust, or node compromise — only crafting a `denominations` array with large `count_coins` values. However, exploitability depends on constructing colliding double-precision sums that pass the exact-equality check at line 2790 while the "true" mathematical sum differs — this requires careful crafting of denomination/count_coins pairs near the 2^53 boundary, and further requires that downstream issuance logic (`indivisible_asset.js`) actually diverges from the declared cap in a way that yields real overissuance rather than only an internal accounting inconsistency. I was not able to fully verify the exact value of `constants.MAX_CAP` or confirm the precise magnitude at which a colliding double-rounding pair is practically constructible before this task's context/iteration limit was reached, so likelihood should be treated as uncertain pending further analysis by someone with full repo access.

### Recommendation
Bound `count_coins` (and any other operands feeding into cap arithmetic) explicitly, e.g. require `count_coins <= constants.MAX_CAP` and additionally validate that `denomInfo.count_coins * denomInfo.denomination <= constants.MAX_CAP` using an overflow-safe check (e.g., dividing back and comparing, or using BigInt for the accumulation and comparisons) before accumulating into `total_cap_from_denominations`. Perform the final `cap` comparison using BigInt or an equivalent exact-arithmetic approach rather than native `Number` addition/multiplication, mirroring the fix pattern needed in the referenced CVE (explicit widening/cast before the multiply, applied consistently across all code paths, not just some).

### Proof of Concept
Conceptual PoC (exact byte-for-byte overflow point requires confirming `constants.MAX_CAP`, which could not be verified in this session):
1. Author an asset-definition unit with `fixed_denominations: true` and a `denominations` array containing entries where `denomination` values are near `constants.MAX_CAP` and `count_coins` values are large positive integers (e.g. > 2^53 / denomination) chosen so that the double-precision sum `Σ(count_coins_i * denomination_i)` rounds to a value equal to an attacker-chosen `payload.cap`, while the mathematically exact sum differs from `payload.cap`.
2. Submit this unit; `validateAssetDefinition` accepts it because the rounded `total_cap_from_denominations === payload.cap` check at `validation.js:2790` passes.
3. Subsequent issuance via `indivisible_asset.js` (lines 533-536) issues coins per denomination based on `count_coins`/`denomination`, potentially producing a real total supply inconsistent with the asset's declared, validator-enforced `cap`.

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

**File:** validation_utils.js (L27-29)
```javascript
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
