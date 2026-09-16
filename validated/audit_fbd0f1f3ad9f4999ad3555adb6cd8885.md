## Analysis

The external report (CVE-2022-38217-style issue) describes NFT "reveal" logic where trait/outcome randomness derives from data that is knowable/manipulable by the party requesting the mint, letting them predict or grind for a favorable outcome before committing. The closest reachable analog in `ocore` is the `number_from_seed()` oscript function, which AA authors use to produce "randomness" inside Autonomous Agents from a seed value that is frequently sourced from trigger-controlled data (e.g., `trigger.unit`, `trigger.data`, `trigger.address`). Because a unit's hash and payload are fully determined by its author before broadcast, and `number_from_seed` is a pure deterministic function of its input, any unprivileged AA trigger sender can pre-compute the outcome for arbitrary candidate payloads locally, and only broadcast the unit whose derived seed yields a favorable result (grinding), which is functionally the same predictability/grinding weakness as the reported NFT-reveal bug class.

### Title
Predictable/grindable pseudo-randomness via `number_from_seed()` seeded with attacker-controlled trigger data - (File: formula/evaluation.js)

### Summary
`number_from_seed()` derives a deterministic value from `sha256(seed)` [1](#0-0) . AA authors commonly seed it with values fully known and controlled by the trigger sender before broadcast (`trigger.unit`, `trigger.data`, `trigger.address`, `params`), all of which are exposed to oscript evaluation [2](#0-1) .

### Finding Description
Because unit content (and therefore its hash `trigger.unit`) as well as `trigger.data` and `trigger.address` are chosen entirely by the unit's author prior to signing and broadcasting, and because `number_from_seed` is a pure deterministic hash-based function with no entropy contributed by the network, hub, or other parties [3](#0-2) , any AA that uses such trigger-controlled values as the seed for "randomness" (e.g., picking an NFT trait, lottery winner, or reward tier) allows the trigger sender to compute all candidate outcomes offline for many nonce variations of their own unit/message payload, and only submit the specific unit whose resulting `number_from_seed` output is favorable. This mirrors the reported CVE-2022-38217-class bug where NFT trait assignment could be predicted/manipulated before the mint was finalized because the "randomness" source was known/controllable ahead of commitment.

### Impact Explanation
If an AA distributes funds, mints value, or assigns favorable outcomes based on `number_from_seed` fed by trigger-controlled inputs, an attacker can deterministically bias the outcome distribution in their favor, draining the AA's balance faster than intended or unfairly winning scarce/rare payouts — a concrete AA fund-loss scenario reachable by any ordinary trigger sender, without needing any privileged role.

### Likelihood Explanation
This requires no special access — only the ability to author and, before broadcasting, locally simulate an AA trigger unit with different candidate data/authors, which is standard behavior for any wallet/bot interacting with an AA. The `number_from_seed` mechanics are public and documented in-language, so any developer building a game/lottery/reveal AA using trigger-derived seeds is exposed without additional effort by the attacker beyond local computation.

### Recommendation
`ocore` itself should not silently permit "randomness" primitives to be seeded by attacker/trigger-controlled data without warning; consider requiring or strongly recommending unpredictable seed sources (e.g., a future stable unit's hash unknown at trigger-authoring time, VRF-based approaches via `vrf_verify`, or oracle-provided randomness) and documenting in the oscript reference that `trigger.unit`, `trigger.data`, and `trigger.address` are attacker-grindable and unsafe as sole seeds for `number_from_seed`. Providing linter/validation warnings in `formula/validation.js` when `number_from_seed`'s only seed argument resolves to `trigger.*` values would reduce accidental exposure.

### Proof of Concept
An AA such as:
```
{
  if (trigger.data.action == 'mint') {
    var $r = number_from_seed(trigger.unit, 1, 100);
    if ($r > 90) {
      // rare/valuable trait or larger payout
    }
  }
}
```
An attacker builds many candidate messages/units off-chain (varying an incidental field, e.g., an extra no-op data field or output ordering) and computes the resulting unit hash + `number_from_seed` result locally using the same SHA256 logic as `formula/evaluation.js` lines 1893-1898 [1](#0-0) , then signs and broadcasts only the specific unit variant that yields `$r > 90`, guaranteeing the rare/high-value outcome every time.

### Citations

**File:** formula/evaluation.js (L1872-1919)
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
					}
				);
```

**File:** formula/grammars/oscript.js (L37-44)
```javascript
		addressValue: /\b[2-7A-Z]{32}\b/,
		trigger_address: /\btrigger\.address\b/,
		trigger_initial_address: /\btrigger\.initial_address\b/,
		trigger_unit: /\btrigger\.unit\b/,
		trigger_initial_unit: /\btrigger\.initial_unit\b/,
		trigger_data: /\btrigger\.data\b/,
		trigger_outputs: /\btrigger\.outputs\b/,
		trigger_output: /\btrigger\.output\b/,
```
