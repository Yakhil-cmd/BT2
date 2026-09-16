## Title
Predictable pseudo-randomness via `number_from_seed()` with attacker-controlled/known seeds enables gameable AA lotteries/games - (File: `formula/evaluation.js`)

### Summary
Oscript exposes a `number_from_seed(seed[, min[, max]])` function that AA authors use as their primary source of "randomness" for games, lotteries, and other chance-based logic. Its implementation simply hashes the caller-supplied `seed` argument with SHA-256 and maps the digest to a number — it has no built-in entropy of its own. If an AA feeds it a seed that is fully known or fully controllable by the unprivileged trigger sender before the trigger is even broadcast (e.g. `trigger.unit`, `trigger.data`, `timestamp`, `mci`, or values derived from them), the "random" result is deterministic and precomputable off-chain, exactly mirroring the `block.number`-seeded predictable-randomness pattern in the referenced report.

### Finding Description
`number_from_seed` is implemented in `formula/evaluation.js` at the `case 'number_from_seed':` branch: it evaluates the parameter list, then does
```
var hash = crypto.createHash("sha256").update(seed.toString(), "utf8").digest("hex");
```
and maps the first 16 hex chars to a float/integer in the requested range. [1](#0-0) 

This function is purely deterministic — for a given `seed` string it always produces the same output. The oscript grammar exposes several trigger/unit-derived variables (`trigger.unit`, `trigger.address`, `trigger.data`, `timestamp`, `mci`, `response_unit`, `mc_unit`) that AA authors commonly plug into `number_from_seed` as an "entropy" source. [2](#0-1) 

The trigger sender is the one who assembles and signs their own trigger unit — they choose its `unit_hash` inputs (payload commission, message contents, `timestamp`, arbitrary `data` payload fields, etc.) before ever broadcasting it. Because AA definitions are public (stored on-chain, readable by anyone before interacting, as seen in `aa_addresses.definition`) [3](#0-2)  a trigger sender can locally simulate the exact `number_from_seed` computation for any candidate trigger content, and only ever broadcast the specific trigger unit whose resulting seed happens to produce a favorable "random" outcome (e.g., a winning lottery draw or bypassing an unfavorable branch), silently discarding the unfavorable candidates and never paying for them. This is functionally identical to the "FortuneTeller" precomputation attack described in the report, except here the attacker doesn't even need to wait for future blocks — they can grind an unlimited number of candidate trigger contents (via the freely variable `data`/`timestamp` fields) entirely offline before committing to one.

Additionally, since `trigger.unit`/`response_unit` values are visible to `handleTrigger`/`addResponse` in `aa_composer.js` and reused across chained AA responses, any AA logic keyed off these deterministic identifiers as a "randomness" source is subject to the same predictability. [4](#0-3) 

### Impact Explanation
Any AA implementing a lottery, raffle, gambling game, giveaway, or "randomized" reward/penalty logic using `number_from_seed` with a seed under the trigger sender's control (directly or indirectly, e.g. via `trigger.data`, `timestamp`, or `trigger.unit`) can be gamed by an unprivileged trigger sender to guarantee favorable "random" outcomes. This results in direct AA fund loss — the AA systematically pays out winnings/rewards to an attacker who never took on the intended probabilistic risk, draining the AA's balance disproportionately to legitimate, unsophisticated users. This matches the "AA fund loss" impact category.

### Likelihood Explanation
Likelihood is high for any AA author who uses `number_from_seed` with commitment-free, sender-controlled seed material — a common and natural-looking pattern since oscript conveniently exposes `trigger.data`, `timestamp`, and `trigger.unit` for this exact purpose, and the language provides no warning or restriction preventing it. No special privilege is needed: any wallet able to post a unit and trigger the AA can perform the grinding attack entirely off-chain before ever spending funds.

### Recommendation
- In AA/oscript documentation and tooling, explicitly warn against using `number_from_seed` with any seed component that the trigger sender can choose or predict prior to submission (i.e., `trigger.data`, `timestamp`, `trigger.unit`, or values derived purely from them).
- Where true unpredictability is required, direct AA authors to use `vrf_verify` (already implemented, see `formula/validation.js` `case 'vrf_verify':`) with an oracle-supplied VRF proof, or a data-feed-based commit-reveal scheme, instead of `number_from_seed` fed from trigger-controlled data. [5](#0-4) 
- Consider having `number_from_seed` accept only oracle-provided or MC-unit-hash-post-stability seed material as a first-class "trusted randomness" primitive, rather than leaving seed selection entirely to AA authors.

### Proof of Concept
1. AA author deploys a "coin-flip" AA whose state formula does:
   `if (number_from_seed(trigger.unit, 0, 1) == 1) { pay out 2x to trigger.address } else { keep the bet }`
2. Attacker composes a candidate trigger unit (choosing `data`, `timestamp`, and other free fields), computes its would-be `unit` hash locally exactly as ocore's `object_hash` module would, and evaluates `sha256(unit).substr(0,16)` mapped through the same range formula used in `formula/evaluation.js` `case 'number_from_seed':` (lines 1893-1917) to predict the outcome. [6](#0-5) 
3. Attacker repeats step 2 offline for many candidate trigger contents until finding one that yields `1` (win), then broadcasts only that trigger unit.
4. The AA, believing it applied fair randomness, guarantees a payout to the attacker every time, draining AA funds over repeated plays.

### Citations

**File:** formula/evaluation.js (L1872-1918)
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
```

**File:** formula/grammars/oscript.ne (L52-58)
```text
					'min', 'max', 'pi', 'e', 'sqrt', 'ln', 'ceil', 'floor', 'round', 'abs', 'hypot', 'is_valid_signed_package', 'is_valid_sig', 'vrf_verify', 'sha256', 'chash160', 'json_parse', 'json_stringify', 'number_from_seed', 'length', 'is_valid_address', 'starts_with', 'ends_with', 'contains', 'substring', 'timestamp_to_string', 'parse_date', 'is_aa', 'is_integer', 'is_valid_amount', 'is_array', 'is_assoc', 'array_length', 'index_of', 'to_upper', 'to_lower', 'exists', 'number_of_responses', 'is_valid_merkle_proof', 'replace', 'typeof', 'delete', 'freeze', 'keys', 'foreach', 'map', 'filter', 'reduce', 'reverse', 'split', 'join', 'has_only',

					'timestamp', 'storage_size', 'mci', 'this_address', 'response_unit', 'mc_unit', 'params', 'previous_aa_responses',

					'type', 'ifseveral', 'ifnone', 'attestors', 'address',
					'oracles', 'feed_name', 'min_mci', 'feed_value', 'what',
					'amount',
```

**File:** initial-db/byteball-sqlite-light.sql (L794-804)
```sql
CREATE TABLE aa_addresses (
	address CHAR(32) NOT NULL PRIMARY KEY,
	unit CHAR(44) NULL, -- where it is first defined.  No index for better speed, NULL for light
	mci INT NULL, -- it is available since this mci (mci of the above unit), NULL for light
	storage_size INT NOT NULL DEFAULT 0,
	base_aa CHAR(32) NULL,
	definition TEXT NOT NULL,
	getters TEXT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
--	CONSTRAINT aaAddressesByBaseAA FOREIGN KEY (base_aa) REFERENCES aa_addresses(address)
);
```

**File:** aa_composer.js (L1608-1619)
```javascript
		var objAAResponse = {
			mci: mci,
			timestamp: objMcUnit.timestamp,
			trigger_address: trigger.address,
			trigger_initial_address: trigger.initial_address,
			trigger_unit: trigger.unit,
			trigger_initial_unit: trigger.initial_unit,
			aa_address: address,
			bounced: bBouncing,
			response_unit: response_unit,
			objResponseUnit: objResponseUnit,
			response: response,
```

**File:** formula/validation.js (L844-858)
```javascript
			case 'vrf_verify':
				complexity+=1;
				var seed = arr[1];
				var proof = arr[2];
				var pem_key = arr[3];
				evaluate(seed, function (err) {
					if (err)
						return cb(err);
					evaluate(pem_key, function (err) {
						if (err)
							return cb(err);
						evaluate(proof, cb);
					});
				});
				break;
```
