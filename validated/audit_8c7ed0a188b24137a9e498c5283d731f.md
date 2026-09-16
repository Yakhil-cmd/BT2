The strongest analog for this bug class in ocore is in the oscript formula engine's `number_from_seed()` function, combined with the AA trigger fields (`trigger.unit`, `trigger.address`, `mc_unit`, `timestamp`) that AA authors can use as its seed. Just like the Solidity report where `block.timestamp` and `address(this)` are attacker-influenceable/predictable "randomness" inputs, these oscript primitives are fully known or grindable by the trigger sender before the response is generated, so an AA that derives outcomes (e.g., a lottery/game paying from its balance) from them can be biased by the very party who is supposed to be an unprivileged participant.

### Title
AA developers can be tricked into producing predictable "randomness" because `number_from_seed()` accepts attacker-controlled trigger fields (`trigger.unit`, `trigger.address`, `mc_unit`, `timestamp`) as seed material - (File: formula/evaluation.js)

### Summary
`number_from_seed()` derives a pseudo-random number by SHA-256-hashing whatever seed value is passed to it [1](#0-0) . The natural values an AA author reaches for as a "random" seed inside oscript are `trigger.unit`, `trigger.address`, `mc_unit`, and `timestamp` - all of which are exposed to formulas as first-class getters [2](#0-1) . None of these values is secret or unpredictable to the party who composes the trigger unit: `trigger.address` is literally the sender's own address and `trigger.unit` is the hash of the very unit the sender is about to broadcast, both taken directly from the posted unit by `getTrigger()` [3](#0-2) .

### Finding Description
`getTrigger()` builds the `trigger` object handed to AA formula evaluation purely from the fields of the unit that the trigger sender authored: `trigger.address = objUnit.authors[0].address` and `trigger.unit = objUnit.unit`, plus whatever `trigger.data` the sender chooses to include [4](#0-3) . `timestamp` in a formula resolves to the last-ball unit's timestamp, and unit timestamps are only checked against a small forward-looking tolerance (`max_seconds_into_the_future_to_accept`, default 5s) with no similar restriction preventing the sender from choosing an advantageous value within that window [5](#0-4) .

An AA author who (mistakenly, but plausibly, mirroring the Solidity pattern of salting with `block.timestamp`/`address(this)`) writes something like `number_from_seed(trigger.unit || trigger.address || timestamp)` to draw a "random" outcome (e.g., pick a lottery winner, decide a coin-flip payout, or choose a decoding key) gives the trigger sender complete control over the seed: the sender selects their own `trigger.address`, can choose the exact `data` payload embedded in the trigger, and can grind different unit contents/timestamps before broadcasting to search for a resulting `trigger.unit` hash (and hence `number_from_seed()` output) that resolves in their favor. `number_from_seed()`'s underlying SHA-256 computation is fully deterministic once the seed is fixed [6](#0-5) , so nothing in the protocol prevents a sender from computing many candidate seeds offline (varying `data`, or waiting for advantageous `timestamp`/`trigger.unit` values inside the accepted skew) and only submitting the unit that yields the outcome they want.

### Impact Explanation
Any lottery/gambling/decision AA relying on these predictable fields as an entropy source can have its outcome biased by the trigger sender - an ordinary, unprivileged AA-trigger sender, not a witness, hub, or node operator. This directly leads to AA fund loss: the sender can force outcomes that drain the AA's balance to themselves (or repeatedly "win"), which matches the accepted High/Critical impact of unauthorized draining of AA funds.

### Likelihood Explanation
Likelihood is high given the pattern is a natural (if incorrect) way to write "randomness" in oscript, since `trigger.unit`, `trigger.address`, `mc_unit`, and `timestamp` are the most readily available dynamic values exposed to AA authors and documented as legitimate getters [7](#0-6) , and any user (not the AA author) who triggers the AA fully controls the inputs that determine these fields.

### Recommendation
- Document explicitly (in oscript/AA developer guidance) that `trigger.unit`, `trigger.address`, `mc_unit`, and `timestamp` are all attacker-chosen/predictable and must never be used, alone or trivially combined, as the sole seed to `number_from_seed()`.
- Consider requiring `number_from_seed()` callers to mix in state that is fixed before the trigger sender can know/choose it (e.g., a previously-committed value, an oracle/data-feed value not controllable by the sender, or a value derived from the *stable* main chain at a point in time preceding the trigger), and provide oscript-level guidance or a lint/validation warning when a seed expression is built solely from trigger-controlled fields.

### Proof of Concept
1. An AA is deployed with response logic such as: `if (number_from_seed(trigger.unit) > 0.5) { pay trigger sender the pot } else { keep the pot }`.
2. A user drafts several candidate trigger units to the AA, varying only the `data` payload field (which does not affect the AA's business logic but changes `objUnit.unit`, and hence `trigger.unit`).
3. For each candidate, the user computes `objUnit.unit` locally (unit hash is a deterministic function of the unit's own content) and evaluates `number_from_seed(candidate_unit)` offline using the same SHA-256 hashing algorithm as `formula/evaluation.js` lines 1890-1897.
4. The user only broadcasts the one candidate unit whose resulting `number_from_seed()` output favors them, guaranteeing they win the AA's payout every time, draining the AA's balance.

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

**File:** formula/validation.js (L448-462)
```javascript
			case 'trigger.initial_unit':
			case 'trigger.outputs':
			case 'previous_aa_responses':
				if (mci < constants.aa3UpgradeMci)
					return cb(op + ' not activated yet');
			case 'trigger.address':
			case 'trigger.initial_address':
			case 'trigger.unit':
			case 'mc_unit':
			case 'number_of_responses':
				if (bGetters)
					return cb(op + ' in getters');
			case 'storage_size':
				cb(bAA ? undefined : op + ' in non-AA');
				break;
```

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** validation.js (L280-287)
```javascript
	if (objUnit.version !== constants.versionWithoutTimestamp) {
		if (!isPositiveInteger(objUnit.timestamp))
			return callbacks.ifUnitError("timestamp required in version " + objUnit.version);
		var current_ts = Math.round(Date.now() / 1000);
		var max_seconds_into_the_future_to_accept = conf.max_seconds_into_the_future_to_accept || 5;
		if (objUnit.timestamp > current_ts + max_seconds_into_the_future_to_accept)
			return callbacks.ifTransientError("timestamp is too far into the future");
	}
```

**File:** formula/grammars/oscript.ne (L33-54)
```text
		addressValue: /\b[2-7A-Z]{32}\b/,
		trigger_address: /\btrigger\.address\b/,
		trigger_initial_address: /\btrigger\.initial_address\b/,
		trigger_unit: /\btrigger\.unit\b/,
		trigger_initial_unit: /\btrigger\.initial_unit\b/,
		trigger_data: /\btrigger\.data\b/,
		trigger_outputs: /\btrigger\.outputs\b/,
		trigger_output: /\btrigger\.output\b/,
		dotSelector: /\.\w+/,
		local_var_name: /\$[a-zA-Z_]\w*\b/,
	//	search_field: /[a-zA-Z]\w*\b/,
		semi: ';',
		comma: ',',
		dot: '.',
		number_sign: '#',
		IDEN: {
			match: /\b[a-zA-Z_]\w*\b/,
			type: moo.keywords({
				keyword: [
					'min', 'max', 'pi', 'e', 'sqrt', 'ln', 'ceil', 'floor', 'round', 'abs', 'hypot', 'is_valid_signed_package', 'is_valid_sig', 'vrf_verify', 'sha256', 'chash160', 'json_parse', 'json_stringify', 'number_from_seed', 'length', 'is_valid_address', 'starts_with', 'ends_with', 'contains', 'substring', 'timestamp_to_string', 'parse_date', 'is_aa', 'is_integer', 'is_valid_amount', 'is_array', 'is_assoc', 'array_length', 'index_of', 'to_upper', 'to_lower', 'exists', 'number_of_responses', 'is_valid_merkle_proof', 'replace', 'typeof', 'delete', 'freeze', 'keys', 'foreach', 'map', 'filter', 'reduce', 'reverse', 'split', 'join', 'has_only',

					'timestamp', 'storage_size', 'mci', 'this_address', 'response_unit', 'mc_unit', 'params', 'previous_aa_responses',
```
