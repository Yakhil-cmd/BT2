### Title
Predictable/Grindable Pseudo-Randomness via `number_from_seed()` in Oscript Enables Precomputed-Outcome Bypass of Fairness Guarantees - ([File: formula/evaluation.js])

### Summary
The `number_from_seed` oscript primitive derives a pseudo-random number as a pure, deterministic `sha256(seed)`-based function of an attacker-suppliable value. Because the derivation is a single hash computation with no binding to unforgeable, not-yet-known entropy (such as the eventual `response_unit` hash), an unprivileged AA trigger sender can brute-force candidate seeds off-chain until a favorable output is found, then submit only the winning seed in a single trigger. This mirrors the CVE-2025-65951 bug class: a value that is supposed to require expensive/unpredictable forward computation to obtain is instead precomputed by the untrusted party and handed directly to the verifying logic, which accepts it via cheap verification instead of enforcing the intended sequential/unpredictable derivation.

### Finding Description
`number_from_seed` is implemented as: [1](#0-0) 

The output is `sha256(seed)` converted deterministically into a float/integer in `[min, max]`. There is no mci-locking, no dependence on data unknowable at trigger-composition time, and no enforced delay — any party who controls the `seed` expression's inputs (e.g. `trigger.data.mySeed`) can, entirely off-chain and before ever broadcasting a unit, iterate over arbitrary seed strings to discover a seed that hashes to any desired numeric outcome, then submit exactly that seed inside their trigger's `data` payload.

This is validated purely for arity/type in `formula/validation.js`: [2](#0-1) 

No enforcement exists in either validation or evaluation compelling an AA author to bind the seed to a value that is fixed only *after* the trigger is posted (e.g., `response_unit`, the eventual last-ball hash, or a value fixed by the network's own DAG stability). An AA author who naively writes an oscript lottery/coinflip/dice contract that computes `number_from_seed(trigger.data.seed)` (or `number_from_seed(trigger.unit)`/similar attacker-influenced literal) to decide a payout is exposed: the "randomness" is not random from the perspective of the party supplying the seed, exactly as the CVE's VDF is not delay-enforced from the perspective of the party supplying the pre-computed VDF output. In both cases, the protection intended to force expensive/independent computation by an untrusted party is instead satisfiable by that same untrusted party performing the "hard" work privately and submitting only the result.

### Impact Explanation
Any AA that uses attacker-influenced input as (or as part of) the seed for `number_from_seed` to gate payouts, winner selection, or asset distribution can have its outcome pre-selected by the trigger sender. This directly leads to unauthorized draining of AA funds (the attacker always "wins" jackpots/refunds) — a concrete AA fund-loss scenario reachable by any unprivileged AA trigger sender, matching the required "concrete unauthorized spending... or AA fund loss" bar.

### Likelihood Explanation
Likelihood depends entirely on whether a deployed AA feeds attacker-controlled trigger data (or any other pre-postable value) into `number_from_seed` without binding it to post-trigger, unforgeable entropy. This is a well-known oscript gotcha; nothing in ocore's formula validation/evaluation layer prevents or warns against this usage, so any AA author who "reasonably" builds a gambling/lottery AA using client-supplied seeds is vulnerable, and the exploit costs nothing beyond local hash computation.

### Recommendation
- Document/enforce that `number_from_seed`'s entropy source must not be influenced by the trigger sender before the AA response commits (e.g., recommend or require binding to `response_unit`, or a value derived from data unknown at trigger-composition time, such as data feeds attested strictly after commitment or a to-be-revealed hash-locked commit/reveal scheme with a separate committing trigger and a later reveal trigger validated against the earlier commitment).
- Consider adding an oscript lint/validation warning (in `formula/validation.js`) when `number_from_seed`'s seed argument is syntactically traceable to `trigger.data`, `trigger.unit`, or other author-supplied literals without an intervening commitment step.
- For any built-in "randomness" helpers, provide/encourage a first-class commit-reveal or VRF-with-delay pattern in oscript so AA authors are not left implementing fragile ad hoc seed-based randomness.

### Proof of Concept
1. Deploy an AA whose payout logic is: `if (number_from_seed(trigger.data.seed, 1, 100) > 50) { pay jackpot }`.
2. Attacker, off-chain, iterates over seed strings `s0, s1, s2, ...` computing `sha256(s_i)`-derived value locally (using the exact algorithm in `formula/evaluation.js:1872-1919`) until finding `s*` such that the resulting number is `> 50`.
3. Attacker posts a single trigger unit with `data.seed = s*`.
4. AA evaluates `number_from_seed(trigger.data.seed, 1, 100)` deterministically to the same value the attacker already computed, and pays out the jackpot every time, with 100% success probability instead of the intended ~50%.

### Citations

**File:** formula/evaluation.js (L1872-1900)
```javascript
			case 'number_from_seed':
				var evaluated_params = [];
				async.eachSeries(
					arr[1],
					function (param, cb2) {
						evaluate(param, function (res) {
							if (fatal_error)
								return cb2(fatal_error);
							if (res instanceof wrappedObject)
								res = true;
							if (!isValidValue(res))
								return setFatalError("invalid value in sha256: " + res, { arr }, undefined, cb2);
							if (isFiniteDecimal(res))
								res = toDoubleRange(res);
							evaluated_params.push(res);
							cb2();
						});
					},
					function (err) {
						if (err)
							return cb(false);
						var seed = evaluated_params[0];
						var hash = crypto.createHash("sha256").update(seed.toString(), "utf8").digest("hex");
						var head = hash.substr(0, 16);
						var nominator = new Decimal("0x" + head);
						var denominator = new Decimal("0x1" + "0".repeat(16));
						var num = nominator.div(denominator); // float from 0 to 1
						if (evaluated_params.length === 1)
							return cb(num);
```

**File:** formula/validation.js (L888-903)
```javascript
			case 'number_from_seed':
				complexity++;
				if (arr[1].length === 0)
					return cb("no arguments of number_from_seed");
				if (arr[1].length > 3)
					return cb("too many params in number_from_seed");
				if (typeof arr[1][1] === 'string' || typeof arr[1][2] === 'string')
					return cb("min or max is a string");
				async.eachSeries(
					arr[1],
					function (param, cb2) {
						evaluate(param, cb2);
					},
					cb
				);
				break;
```
