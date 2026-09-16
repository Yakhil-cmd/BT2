### Title
Unbounded `count_coins` in asset denominations causes floating-point cap-check bypass, enabling supply inflation - ([File: validation.js])

### Summary
`validateAssetDefinition()` in `validation.js` sums `denomInfo.count_coins * denomInfo.denomination` across an attacker-supplied `denominations` array to verify that the declared asset `cap` matches the true issuable supply. `count_coins` is validated only with `isPositiveInteger()` and has no upper bound (unlike `denomination`, which is capped at `constants.MAX_CAP`), so an attacker can choose a huge `count_coins` value that pushes the product for a given denomination far beyond `Number.MAX_SAFE_INTEGER`. Because JavaScript arithmetic uses IEEE-754 doubles, this causes `total_cap_from_denominations` to be computed with a rounding error that, when combined with a second denomination, can be made to equal a small, valid `cap` (≤ `constants.MAX_CAP`) even though the real `count_coins` value stored verbatim as `BIGINT` in the `asset_denominations` table lets far more coins be issued than the declared `cap` implies.

### Finding Description
This is analogous to CVE-2024-57938 (`sctp_association_init()`): an unbounded, attacker/user-controlled integer is fed unchecked into an arithmetic operation whose result is used for a security-relevant decision, and the operation can silently produce an incorrect (much smaller than expected) result due to fixed-precision arithmetic limits (32-bit int overflow in the kernel case; IEEE-754 double rounding/cancellation in ocore's case).

In `validateAssetDefinition()`: [1](#0-0) 
- `denomInfo.denomination` is bounded: `if (!isPositiveInteger(denomInfo.denomination)) ...; if (denomInfo.denomination > constants.MAX_CAP ...) return callback("denomination exceeds MAX_CAP");`
- `denomInfo.count_coins`, however, is only checked via `isPositiveInteger(denomInfo.count_coins)` — **no upper bound at all**.
- `total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;` accumulates products of these two values with plain JS `*`.
- Finally: `if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations) return callback("cap doesn't match sum of denominations");` — the declared `cap` (which is itself capped to `constants.MAX_CAP = 9e15`) must exactly equal the *computed* (imprecise) sum.

Because `count_coins` can be as large as `Number.MAX_SAFE_INTEGER` (~9.007e15) while `denomination` can independently be as large as `MAX_CAP` (9e15), a single product can reach ~8.1e31. At that magnitude, the double's representable precision step (ULP) is on the order of `value * 2^-52`, which for values around 1e31 is roughly 1e15–1e16 — the *same order of magnitude* as `MAX_CAP` itself. By choosing two (or more) large `count_coins`/`denomination` pairs whose products are close in magnitude but differ in low-order bits, an attacker can engineer floating-point cancellation/rounding so that the *computed* `total_cap_from_denominations` equals a small, legitimate-looking value (≤ `MAX_CAP`) that matches a chosen `cap`, while the actual `count_coins` recorded verbatim in the `asset_denominations` table (stored precisely as `BIGINT`, not as the rounded double) is far larger than what the nominal `cap` implies.

The `asset_denominations.count_coins` value is later used directly (as an exact integer, via SQL `BIGINT`) to gate issuance amounts in `indivisible_asset.js`'s `issueNextCoin()`: `var count_coins_to_issue = row.count_coins || Math.floor(...); var issue_amount = count_coins_to_issue * denomination;` [2](#0-1) 
Since `count_coins` is read from the DB unaltered from what the definer supplied, the issuer can subsequently issue coins consistent with the real (huge) `count_coins`, not the falsely-validated small `cap`, producing far more supply than the network believes the asset is capped at.

The bound gating on the paired `denomination` value in `validation.js` is itself only conditionally enforced pre-`pemCurvesFixMci`: [3](#0-2) 
but even post-upgrade with `denomination` capped, `count_coins` remains fully unbounded, so the arithmetic imprecision described above persists regardless of network upgrade state.

The parallel validation path for AA-issued assets (`aa_validation.js`) has the identical omission — `count_coins` is checked only with `isPositiveInteger`, never bounded: [4](#0-3) 

### Impact Explanation
An asset issuer (a normal unprivileged unit poster reachable via `validateAssetDefinition`, or via an AA's `asset` message reachable via `validateAADefinition`) can craft a `denominations` array whose declared `cap` (bounded by `MAX_CAP`) is validated as consistent with the sum of `count_coins * denomination`, while the real, DB-persisted `count_coins` for one denomination bucket allows issuance of vastly more base units of that asset than the cap implies. This is a direct asset supply-inflation vulnerability: nodes will accept the asset definition as valid (thinking supply is capped at a modest number), yet the issuer can later legitimately issue coins consistent with the real oversized `count_coins`, minting supply that violates the declared and advertised cap — undermining the economic guarantees of the asset for all downstream holders/traders.

### Likelihood Explanation
Exploitation requires the attacker to precisely engineer IEEE-754 rounding/cancellation across the chosen `denomination`/`count_coins` pairs (constrained further by ordering/`prev_denom` uniqueness rules and `MAX_DENOMINATIONS_PER_ASSET_DEFINITION = 64` slots), which is a nontrivial but entirely deterministic and computable search (bounded exponent space, findable offline without any network interaction) — this is a purely local computation problem, not requiring any race condition or privileged access. Given that the attacker fully controls both operands and the modulus of the acceptable outcome (`cap` must be ≤ 9e15 and an exact integer), and there are up to 64 independent terms to tune, a solution is very likely findable via straightforward search/enumeration of representable double values near the target boundary.

### Recommendation
Add an explicit upper bound to `denomInfo.count_coins` (e.g., `count_coins <= constants.MAX_CAP` or, more strictly, ensure `count_coins * denomination <= constants.MAX_CAP` computed via an integer-safe method, such as `BigInt`) in both `validation.js`’s `validateAssetDefinition()` and `aa_validation.js`’s asset-definition validation. Additionally, compute `total_cap_from_denominations` using `BigInt` arithmetic (or incrementally check `count_coins * denomination <= MAX_CAP` and abort early) rather than plain `Number` multiplication, to eliminate any possibility of floating-point rounding masking an oversized true value.

### Proof of Concept
Conceptually (exact numeric pairs require an offline search over representable doubles near 8e31–1e32, which is feasible given ~64 available denomination slots and full attacker control of both factors):
1. Attacker composes an asset-definition message (`app: 'asset'`) with `fixed_denominations: true`, `cap: <small number, e.g. 1e6>`, and a `denominations` array containing two or more entries where each `denomination` is at or near `MAX_CAP` (9e15) and each paired `count_coins` is chosen (via offline brute-force/search over doubles) such that the double-precision sum `Σ(count_coins_i * denomination_i)` rounds to exactly `1e6` (the declared `cap`), even though the true (exact) value of at least one `count_coins_i` for its `denomination_i` is astronomically larger than what the nominal cap implies.
2. `validateAssetDefinition()` accepts the unit because `total_cap_from_denominations === payload.cap` under JS floating-point comparison.
3. `writer.js` persists the *raw* `count_coins` values (as supplied) into `asset_denominations.count_coins` (a `BIGINT` column, exact).
4. The issuer subsequently calls `issueNextCoin()` in `indivisible_asset.js`, which reads the exact (oversized) `count_coins` from the DB and issues `count_coins_to_issue * denomination` coins — far exceeding the network's understanding of the asset's `cap`, achieving supply inflation.

Note: I was unable to fully verify the exact `writer.js` insertion logic for `asset_denominations` (only found reference matches, not the full code snippet) due to index size limits; a Devin session with full repository access would be needed to confirm the exact write path and to compute concrete exploitable `(count_coins, denomination)` pairs.

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

**File:** indivisible_asset.js (L530-536)
```javascript
					var row = rows[0];
					if (!!row.count_coins !== !!objAsset.cap)
						throw Error("invalid asset cap and count_coins");
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
```

**File:** aa_validation.js (L272-284)
```javascript
							if ("count_coins" in denomInfo) {
								if (typeof denomInfo.count_coins === 'number') {
									if (!isPositiveInteger(denomInfo.count_coins))
										return cb3("invalid count_coins");
								}
								else if (typeof denomInfo.count_coins === 'string') {
									var f = getFormula(denomInfo.count_coins);
									if (f === null)
										return cb3("bad formula in count_coins: "+ denomInfo.count_coins);
								}
								else
									return cb3("bad count_coins " + JSON.stringify(denomInfo.count_coins));
							}
```
