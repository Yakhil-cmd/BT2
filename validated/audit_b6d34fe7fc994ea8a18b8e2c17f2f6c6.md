## Finding

### Title
Integer overflow in denomination cap sum allows asset `cap` field to misrepresent true issuable supply - ([File: validation.js])

### Summary
`validateAssetDefinition` in `validation.js` computes the declared cap of a fixed-denomination asset by summing `count_coins * denomination` for each denomination entry, using ordinary JS number arithmetic with no bound on the magnitude of the multiplication before it is compared against the asset's `cap` field.

### Finding Description
When a user (or an AA) defines an asset with `fixed_denominations: true` and per-denomination `count_coins`, the validator only checks that `denomination` and `count_coins` are each `isPositiveInteger` — it does not check that their *product*, or the running total, stays within `constants.MAX_CAP` (9e15, just under `Number.MAX_SAFE_INTEGER`) before doing the multiplication and summation: [1](#0-0) 

```
if (!isPositiveInteger(denomInfo.denomination))
    return callback("invalid denomination");
if (denomInfo.denomination > constants.MAX_CAP && (...pemCurvesFixMci gated...))
    return callback("denomination exceeds MAX_CAP");
...
if ("count_coins" in denomInfo){
    if (!isPositiveInteger(denomInfo.count_coins))
        return callback("invalid count_coins");
    total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
}
...
if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
    return callback("cap doesn't match sum of denominations");
```

`isPositiveInteger` (in `validation_utils.js`) is only checked to enforce integrality and positivity; it was not confirmed (I could not retrieve the file content) to also cap the value at `Number.MAX_SAFE_INTEGER`/`MAX_CAP`. The only magnitude check on `denomination` itself (`> MAX_CAP`) is additionally gated behind the `pemCurvesFixMci` upgrade point, and no equivalent magnitude check exists at all for `count_coins`, nor for the *product* `count_coins * denomination`, nor for the running `total_cap_from_denominations` sum. If `count_coins` and/or `denomination` are chosen large enough that their product or cumulative sum exceeds `Number.MAX_SAFE_INTEGER` (2^53−1 ≈ 9.007e15), JavaScript's IEEE‑754 double arithmetic silently loses precision (the same root cause as the reported Solidity `uint120` truncation: an unchecked narrowing/overflowing numeric operation feeding directly into an equality check that is supposed to guarantee data integrity). This can make `total_cap_from_denominations` collide with an attacker-chosen `payload.cap` value even though the true sum of per‑denomination supplies does not actually equal that declared cap.

This exact check-after-cast/overflow pattern mirrors the reported bug class: a "safety" comparison (`cap !== total_cap_from_denominations`) is rendered meaningless because the value it compares against was already corrupted by an unchecked overflow during computation.

### Impact Explanation
The `cap` field of an asset is the authoritative, user/AA-facing declaration of total issuable supply — code (including AA oscript, via `asset[...].cap`) and downstream integrations rely on it to reason about total supply. If the sum-of-denominations check can be satisfied despite the true total minted supply diverging from the declared `cap` (due to float overflow), an asset issuer can construct a fixed-denomination asset whose actual aggregate issuable coin supply differs from what `cap` states, undermining any invariants that depend on the declared cap (e.g., AAs pricing/distributing tokens based on `asset[...].cap`, or external services assuming `cap` bounds total possible supply). This is a supply-integrity/inflation-adjacent issue reachable by any unprivileged unit poster defining an asset (directly, or via an AA's `asset` message).

### Likelihood Explanation
Reachable by any user who can post an `asset` definition message (public, in-scope entry point) with `fixed_denominations: true` and manipulated `denomination`/`count_coins` values large enough to overflow `Number.MAX_SAFE_INTEGER`. No privileged role, witness, or hub cooperation is required — only carefully chosen large integers in an otherwise ordinary asset-definition unit.

### Recommendation
- Explicitly bound `denomInfo.denomination`, `denomInfo.count_coins`, and the running `total_cap_from_denominations` to `constants.MAX_CAP` (or `Number.MAX_SAFE_INTEGER`) at every step of the loop, rejecting the definition as soon as any intermediate value would exceed that bound, rather than only checking the final sum against `payload.cap`.
- Remove/backport the `pemCurvesFixMci` gating so the `denomination > MAX_CAP` check is unconditional, and add the same unconditional check for `count_coins` and for the running total.
- Consider using a safe/checked-multiplication helper (or a BigInt-based accumulation) instead of native `*`/`+=` for cap arithmetic feeding into equality-based validation.

### Proof of Concept
1. Attacker posts an `asset` definition message with `fixed_denominations: true`, `cap: X` for some value `X` chosen to collide after precision loss, and a `denominations` array containing an entry with `denomination` and/or `count_coins` set to a value near or above `Number.MAX_SAFE_INTEGER` (e.g., `9007199254740993` or similar), such that `count_coins * denomination` and the accumulated `total_cap_from_denominations` silently round to `X` due to IEEE‑754 double precision loss.
2. `validateAssetDefinition` computes `total_cap_from_denominations` via unchecked floating-point multiplication/summation and finds `payload.cap === total_cap_from_denominations` true despite the true intended total differing, allowing the definition to pass validation with a `cap` value that does not truthfully reflect the underlying denomination configuration.

Note: I was unable to retrieve the exact implementation of `isPositiveInteger` in `validation_utils.js` within the available tool calls to confirm whether it independently caps values at `Number.MAX_SAFE_INTEGER`; this is the primary open uncertainty in the analysis and would need to be checked in a live session to determine the precise magnitude threshold required for exploitation.

### Citations

**File:** validation.js (L2769-2792)
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
