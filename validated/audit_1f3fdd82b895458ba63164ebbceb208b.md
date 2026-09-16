## Title
Predictable/attacker-grindable pseudo-randomness via `number_from_seed` in oscript AAs - ([File: formula/evaluation.js])

### Summary
Obyte's oscript language (executed by AAs) exposes `number_from_seed` as the only randomness primitive available to Autonomous Agent authors. It derives a "random" number deterministically by SHA-256-hashing an author-supplied seed expression, with no protection against the seed being fully known or grindable by the very unit-poster who triggers the AA. This is the same bug class as the Luckyos rock-paper-scissors incident: a deterministic, precomputable "random" outcome lets an unprivileged attacker choose exactly which unit to broadcast to guarantee a favorable result.

### Finding Description
`number_from_seed` computes its result purely from `sha256(seed)`, mapped into a numeric range: [1](#0-0) 

Nothing in the implementation restricts what the `seed` expression may reference. AA authors commonly derive game/lottery outcomes from values that are visible to, or directly controlled by, the trigger sender before the triggering unit is even broadcast — e.g. `trigger.unit` (the unit's own hash, which the author computes client-side before signing and posting), `trigger.data`, `trigger.address`, or `timestamp`. Because unit content (message data, parent selection, timestamp) is chosen by the poster prior to submission, and because the resulting `unit` hash is a pure, cheap, offline-computable function of that content (`objectHash`/sha256-based), an attacker can:
1. Construct many candidate trigger units off-chain (varying e.g. a nonce field in `trigger.data`, or waiting for different timestamps),
2. Compute `number_from_seed(seed)` locally for each candidate exactly as the AA would,
3. Only actually sign and broadcast the one candidate unit whose derived "random" value produces a winning/favorable AA response.

This grinding costs nothing except local computation and is invisible to the network — discarded candidates are never posted. This directly parallels the Luckyos report, where the attacker discovered the deterministic law behind the "random" rock-paper-scissors move and simply waited/chose inputs to win with the discovered periodicity — the fix in both cases is the same: don't let the party who benefits from the outcome also control or preview the seed.

The oscript grammar/keyword list also defines `vrf_verify`, i.e. a verifiable-random-function *verification* primitive intended for oracle-supplied unbiased randomness: [2](#0-1) 

but `vrf_verify` only checks a VRF proof supplied by an external oracle — it does not stop authors from instead using the cheaper, insecure `number_from_seed` with a self-controllable seed, and ocore performs no analysis to flag or reject seeds built from attacker-controlled trigger fields.

### Impact Explanation
Any AA implementing games, lotteries, raffles, or other logic that pays out Bytes/assets based on `number_from_seed` results is exposed to guaranteed-win exploitation if its seed includes any value the trigger sender can preview or influence prior to broadcast (`trigger.unit`, `trigger.data`, `timestamp`, `trigger.address`). This leads to direct unauthorized extraction of AA-held funds — the attacker always wins, draining the AA's balance, which matches the "AA fund loss" impact category. This is Medium/High severity depending on AA fund size, and it is a pure design footgun inherent to the language primitive provided by ocore, not a misuse limited to one dApp.

### Likelihood Explanation
Likelihood is high for any AA author who naively seeds `number_from_seed` with trigger-derived data (a very natural, commonly-suggested pattern for "unique per-trigger randomness"), since:
- The unit hash and trigger data are fully known to the poster before broadcast.
- Grinding candidates offline is cheap (fast SHA-256, no network cost for discarded attempts).
- No validation logic in `formula/validation.js` or `formula/evaluation.js` flags or restricts which fields may be used as a seed. [3](#0-2) 

### Recommendation
- Document and, where feasible, statically warn/reject `number_from_seed` calls whose seed expression is built solely from attacker-controllable/pre-computable trigger fields (`trigger.unit`, `trigger.data`, `trigger.address`, `timestamp`) without incorporating unpredictable, post-commitment entropy (e.g., a value only known after the triggering unit is stable, or an oracle-supplied VRF value verified via `vrf_verify`).
- Provide AA authors a dedicated "secure randomness" pattern/example (VRF-oracle-backed) as the canonical replacement for `number_from_seed` in any AA that pays out funds based on the outcome, and add prominent documentation warning about the grinding attack, referencing the general class of "predictable on-chain randomness" bugs (like the Luckyos incident).

### Proof of Concept
1. AA code (hypothetical rock-paper-scissors AA) computes the house move as:
   `var house_move = number_from_seed(trigger.unit, 0, 2);` // 0=rock,1=paper,2=scissors
2. Attacker composes a trigger unit including their own move in `trigger.data` (e.g., `{move: 0}` for rock) plus an adjustable dummy field (`nonce`) they can vary.
3. Offline, before signing, attacker computes candidate unit hashes for many `nonce` values (each producing a different `trigger.unit`), and for each candidate computes `sha256(candidate_unit)` locally exactly as `number_from_seed` would in `formula/evaluation.js` (lines 1890-1918), deriving `house_move` for each candidate.
4. Attacker signs and broadcasts only the one candidate unit where the derived `house_move` loses to their chosen move (e.g., `house_move = scissors` when attacker plays `rock`).
5. The AA pays out the win, exactly reproducing the Luckyos exploit: the "randomness" is a public, precomputable function of data the attacker chooses before committing to the transaction.

### Citations

**File:** formula/evaluation.js (L1890-1918)
```javascript
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
```

**File:** formula/grammars/oscript.ne (L52-52)
```text
					'min', 'max', 'pi', 'e', 'sqrt', 'ln', 'ceil', 'floor', 'round', 'abs', 'hypot', 'is_valid_signed_package', 'is_valid_sig', 'vrf_verify', 'sha256', 'chash160', 'json_parse', 'json_stringify', 'number_from_seed', 'length', 'is_valid_address', 'starts_with', 'ends_with', 'contains', 'substring', 'timestamp_to_string', 'parse_date', 'is_aa', 'is_integer', 'is_valid_amount', 'is_array', 'is_assoc', 'array_length', 'index_of', 'to_upper', 'to_lower', 'exists', 'number_of_responses', 'is_valid_merkle_proof', 'replace', 'typeof', 'delete', 'freeze', 'keys', 'foreach', 'map', 'filter', 'reduce', 'reverse', 'split', 'join', 'has_only',
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
