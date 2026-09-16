### Title
Predictable pseudo-randomness via `number_from_seed()` on attacker-known inputs lets an AA trigger sender pre-compute and cherry-pick favorable outcomes - (File: `formula/evaluation.js`)

### Summary
The `number_from_seed` oscript function derives a "random" value deterministically from `sha256(seed)` where the seed is whatever expression the AA author supplies. If that seed (or any input feeding it) is knowable by the person constructing the trigger unit *before* it is broadcast — e.g. `trigger.unit`, `trigger.data`, `trigger.address`, or a counter read from `var[...]` — the trigger sender can compute the outcome locally, discard unfavorable candidate units, and only broadcast the one whose derived "random" outcome is best, exactly mirroring the AI Arena reroll finding where `keccak256(tokenId, numRerolls)` let the caller pre-select the best reroll instead of taking a chance.

### Finding Description
`number_from_seed` is implemented as a pure, deterministic hash of caller-supplied evaluated parameters: [1](#0-0) 
It hashes the first parameter with SHA-256 and maps the digest into a float or an integer range — there is no dependency on any value that is unknown to the unit's author at signing time (no block hash, no post-broadcast MC data, no external oracle randomness).

Unlike `response_unit` (only produced by the network **after** the AA response is evaluated) or values fixed only at final stabilization, any input available in `trigger.*`, `params.*`, or existing `var[...]` at the moment of formula authoring can be read off-chain, hashed the same way client-side, and used to filter candidate units before submission. Because Obyte units are constructed and hashed locally (`getUnitHash`) before being broadcast, and the sender fully controls unit content (timestamp, parents chosen by the composer, message payloads, data fields) up until the moment of signing/broadcasting, an attacker can enumerate many candidate trigger units, evaluate what `number_from_seed(...)` would yield for each (by replicating the SHA-256 computation in JS), and only actually submit the trigger whose derived outcome is favorable — precisely "rerolling" for free by simulating outcomes rather than taking a chance.

The parallel to the original finding is exact: in AI Arena, `keccak256(tokenId, numRerolls[tokenId])` was fully computable from state visible to the caller before executing the reroll transaction, letting them choose to submit only when the result was favorable. In ocore's oscript, any AA that implements a lottery/reward/reroll/dice mechanism using `number_from_seed(seed)` with a seed built from `trigger.data`, `trigger.unit`, `trigger.address`, or persisted state-var counters suffers the same defect, because none of these inputs are unknown to the crafting party at unit-construction time.

### Impact Explanation
Any Autonomous Agent built on top of `number_from_seed` for chance-based logic (lotteries, loot boxes, reward distribution, PvP outcome resolution, fee waivers, etc.) can have its "randomness" defeated by an unprivileged trigger sender who locally pre-computes outcomes for many candidate units and only submits the one that yields the best result. This can result in unauthorized draining of AA-held funds (the AA always pays out the maximum/best outcome to whoever bothers to grind for it) or an unfair guaranteed advantage in any game-theoretic AA logic, i.e., concrete AA fund loss.

### Likelihood Explanation
Likelihood is high for any AA that relies on `number_from_seed` seeded from attacker-visible/attacker-chosen inputs — this is the only source of "randomness" oscript exposes to non-oracle-dependent AAs, so it is a natural and commonly reached primitive for game/lottery-style AAs. The attack requires no special privilege: any unit poster who can construct and pre-hash a candidate unit off-chain (trivial, using the same deterministic `getUnitHash`/SHA-256 logic) can grind for favorable seeds before ever broadcasting anything on-chain, at zero cost beyond local computation.

### Recommendation
`number_from_seed`'s documentation and any example/AA templates should explicitly warn that the seed must never be derived solely from values known to the trigger sender before broadcast (own trigger unit hash/content, own address, freely chosen trigger.data, or state vars the AA itself doesn't rotate unpredictably). Where true unpredictability is required, AAs should combine the seed with values unknowable at trigger-construction time — e.g., the response unit hash of a *prior* AA response, or an oracle-supplied data feed value posted by a trusted, independent party after the trigger is locked in — so that no single unprivileged party can compute the outcome before commitment. Consider adding a lint/validation warning in `formula/validation.js` when `number_from_seed`'s seed expression is built purely from `trigger.*` fields with no oracle/state-var contribution from a third party.

### Proof of Concept
1. An AA is written with logic such as:
   `$roll = number_from_seed(trigger.unit, 1, 6); if ($roll == 6) { response payout }`
2. Before broadcasting, the wallet composes the trigger unit locally and obtains its deterministic content hash via the same hashing used in `object_hash.js` (`getUnitHash`), as unit construction and hashing occur client-side prior to broadcast: [2](#0-1) .
3. The attacker replicates the `number_from_seed` computation in JS exactly as done in `formula/evaluation.js` (SHA-256 of the seed, mapped to the 1-6 range): [3](#0-2) .
4. The attacker varies unit content they control (e.g., message ordering, optional data fields, or by waiting and re-composing with different parents/timestamp) until the locally computed `$roll` equals 6, then signs and broadcasts only that unit.
5. The AA reliably pays out the "6" outcome to the attacker every time, defeating the intended randomness — an exact analog of picking the best of all rerolls instead of taking a chance at each attempt.

### Citations

**File:** formula/evaluation.js (L1893-1917)
```javascript
						var seed = evaluated_params[0];
						var hash = crypto.createHash("sha256").update(seed.toString(), "utf8").digest("hex");
						var head = hash.substr(0, 16);
						var nominator = new Decimal("0x" + head);
						var denominator = new Decimal("0x1" + "0".repeat(16));
						var num = nominator.div(denominator); // float from 0 to 1
						if (evaluated_params.length === 1)
							return cb(num);
						var min = dec0;
						var max;
						if (evaluated_params.length === 2)
							max = evaluated_params[1];
						else {
							min = evaluated_params[1];
							max = evaluated_params[2];
						}
						if (!isFiniteDecimal(min) || !isFiniteDecimal(max))
							return setFatalError("min and max must be numbers", { arr }, false, cb);
						if (!min.isInteger() || !max.isInteger())
							return setFatalError("min and max must be integers", { arr }, false, cb);
						if (!max.gt(min))
							return setFatalError("max must be greater than min", { arr }, false, cb);
						var len = max.minus(min).plus(1);
						num = num.times(len).floor().plus(min);
						cb(num);
```

**File:** object_hash.js (L60-65)
```javascript
function getUnitHash(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	if (objUnit.content_hash) // already stripped and objUnit doesn't have messages
		return getBase64Hash(getNakedUnit(objUnit), bVersion2);
	return getBase64Hash(getStrippedUnit(objUnit), bVersion2);
}
```
