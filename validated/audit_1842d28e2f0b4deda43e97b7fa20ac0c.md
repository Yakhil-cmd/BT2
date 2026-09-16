### Title
Predictable AA "randomness" via `mc_unit`/`trigger.unit`/`number_from_seed` allows outcome-grinding by an unprivileged trigger sender - ([File: formula/evaluation.js])

### Summary
The SlowMist report describes a "transaction congestion attack" against an EOS gambling dApp: attackers use multiple sock-puppet ("trumpet") accounts, repeatedly submitting/retrying transactions in turns so that only favorable outcomes (determined by predictable on-chain values known before broadcast) are ever committed. The equivalent bug class in ocore is that oscript exposes `mc_unit`, `trigger.unit`, `response_unit`, and `number_from_seed()` as sources of "entropy" for AA (Autonomous Agent) game logic, yet all of these values are either fully known to the trigger's author before the unit is even signed/broadcast, or are otherwise attacker-influenceable. This lets an unprivileged AA-trigger sender precompute the outcome offline and choose, "trumpet"-style, whether to broadcast a given trigger unit or discard it and try a different one, exactly mirroring the EOS retry/grinding technique.

### Finding Description
`trigger.unit` is the hash of the very unit that carries the trigger, computed deterministically over its content via `objectHash.getUnitHash` before the unit is ever sent to the network [1](#0-0) . Because the author fully controls the unit's content (timestamps, parent selection order, message contents, `data` payload, etc.), they can compute `trigger.unit` client-side, feed it (or any other author-controlled/known value) into `sha256()` / `number_from_seed()` in the AA's oscript, see the resulting outcome, and only actually broadcast the unit when the outcome favors them — discarding and regenerating (e.g., by tweaking `trigger.data`, changing `max_aa_responses`, or waiting for a different `mc_unit`/parent set) otherwise. These primitives are all exposed to formula evaluation without any warning/guard that they are attacker-predictable:

- `trigger.unit` / `trigger.initial_unit` are plain grammar tokens returned verbatim to the AA [2](#0-1) .
- `mc_unit` and other identifiers used as `number_from_seed()` inputs are accepted with no restriction preventing their use as a "random" seed [3](#0-2) .
- `number_from_seed()` hashes whatever seed is supplied and derives a decimal in `[0,1]` (or an integer range) purely as `sha256(seed)` [4](#0-3) , with no mechanism to prevent the seed from being a value known to the trigger author ahead of time.

An AA-based gambling/lottery game (structurally the direct analog of "SKR EOS games") that seeds its win/lose decision from `trigger.unit`, `mc_unit`, `response_unit`, or any other author-known value inherits this predictability. The attacker (an ordinary, unprivileged unit poster / AA trigger sender) can:
1. Draft many candidate trigger units locally (varying `data`, timestamp, parent set, etc.) without broadcasting them.
2. Compute the resulting `trigger.unit` hash (and thus the AA's derived "random" outcome) for each candidate offline, exactly as `objectHash.getUnitHash` would.
3. Broadcast only the winning candidate.

This is functionally identical to the EOS "trumpet"/retry congestion pattern: repeated, cheap attempts by the same actor (optionally spread across several addresses to also avoid `MAX_AUTHORS_PER_UNIT`/spend limits or evade naive anti-repeat heuristics) until a favorable, deterministic value is found, then a single confirmed submission drains the AA.

### Impact Explanation
Any AA gambling/lottery contract built on ocore's oscript that uses `trigger.unit`, `trigger.initial_unit`, `mc_unit`, `response_unit`, or other author-predictable data as a randomness seed can be driven to pay out favorably to the attacker on demand, resulting in concrete AA fund loss/drain analogous to the reported ~4,000 EOS loss. Because the AA's balance is real bytes/asset funds held at its address (see `aa_balances` table) [5](#0-4) , repeated grinding attacks can systematically transfer AA-held funds to the attacker with no genuine 50/50 (or advertised-odds) risk, i.e. unauthorized/asymmetric spending of AA funds.

### Likelihood Explanation
High for any AA game that naively uses these primitives for randomness, and this is a class of primitives the engine actively offers to AA authors without built-in protection (e.g., no forced "commit-reveal" or "wait N stable units then reveal" pattern is enforced by the protocol itself). The attack requires no special privileges — only the ability to draft (but not necessarily broadcast) an ordinary trigger unit — matching the "unprivileged trigger sender" reachability constraint. It also requires no network-level or peer-malice behavior; it is achievable purely through legitimate client-side unit composition before broadcast.

### Recommendation
- Document (and, where feasible, statically discourage) using `trigger.unit`, `trigger.initial_unit`, `mc_unit`, or `response_unit` as sole/primary randomness seeds in oscript, since they are known to the trigger author prior to broadcast.
- Encourage/require AA game templates to derive randomness from values unknown at unit-composition time to the trigger author (e.g., committed values contributed by multiple independent, mutually distrusting parties combined via `sha256`, or values that only become known after the trigger unit is already stable and irrevocable, such as the hash of a later, independent oracle data feed).
- Consider adding a linter/validation-time warning in `formula/validation.js` when `number_from_seed()`'s seed expression is provably composed only from `trigger.*`/`mc_unit`/`params` values, since these are attacker-controlled at unit-composition time and are exactly the addressable root cause of grinding-based fund drains in gambling AAs.

### Proof of Concept
1. Publish a lottery/dice AA whose payout logic includes state such as:
   `var['result'] = number_from_seed(trigger.unit) >= 0.5 ? 'win' : 'lose';`
   (or equivalently seeded by `mc_unit`).
2. As the attacker, before broadcasting anything, repeatedly draft trigger units to this AA locally (varying `trigger.data`, `timestamp`, or `parent_units` selection), computing `objectHash.getUnitHash(objUnit)` for each candidate exactly as `validate()` will [1](#0-0) .
3. Evaluate `number_from_seed(candidate_unit_hash)` offline using the same algorithm as `formula/evaluation.js` [6](#0-5)  to predict whether that specific candidate would win.
4. Discard losing candidates; sign and broadcast only a winning candidate unit.
5. The AA processes the trigger, computes the identical (already-known-to-be-winning) `number_from_seed` value, and pays out — reproducing the "repeated retries until a favorable outcome, then a single confirmed submission" pattern described in the SKR EOS incident, resulting in AA fund loss.

### Citations

**File:** validation.js (L131-138)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** formula/evaluation.js (L1074-1080)
```javascript
			case 'trigger.unit':
				cb(trigger.unit);
				break;

			case 'trigger.initial_unit':
				cb(trigger.initial_unit);
				break;
```

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

**File:** formula/grammars/oscript.ne (L52-58)
```text
					'min', 'max', 'pi', 'e', 'sqrt', 'ln', 'ceil', 'floor', 'round', 'abs', 'hypot', 'is_valid_signed_package', 'is_valid_sig', 'vrf_verify', 'sha256', 'chash160', 'json_parse', 'json_stringify', 'number_from_seed', 'length', 'is_valid_address', 'starts_with', 'ends_with', 'contains', 'substring', 'timestamp_to_string', 'parse_date', 'is_aa', 'is_integer', 'is_valid_amount', 'is_array', 'is_assoc', 'array_length', 'index_of', 'to_upper', 'to_lower', 'exists', 'number_of_responses', 'is_valid_merkle_proof', 'replace', 'typeof', 'delete', 'freeze', 'keys', 'foreach', 'map', 'filter', 'reduce', 'reverse', 'split', 'join', 'has_only',

					'timestamp', 'storage_size', 'mci', 'this_address', 'response_unit', 'mc_unit', 'params', 'previous_aa_responses',

					'type', 'ifseveral', 'ifnone', 'attestors', 'address',
					'oracles', 'feed_name', 'min_mci', 'feed_value', 'what',
					'amount',
```

**File:** initial-db/byteball-sqlite.sql (L838-846)
```sql
CREATE TABLE aa_balances (
	address CHAR(32) NOT NULL,
	asset CHAR(44) NOT NULL, -- 'base' for bytes (NULL would not work for uniqueness of primary key)
	balance BIGINT NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (address, asset),
	FOREIGN KEY (address) REFERENCES aa_addresses(address)
--	FOREIGN KEY (asset) REFERENCES assets(unit)
);
```
