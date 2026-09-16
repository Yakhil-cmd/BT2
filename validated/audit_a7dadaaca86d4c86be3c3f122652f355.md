### Title
Unbounded input accumulation in AA payment responses causes O(n²) validation cost / CPU-exhaustion DoS - (File: `aa_composer.js`, `validation.js`)

### Summary
An unprivileged user can send a large number of small (but not "dust", i.e. ≥ `FULL_TRANSFER_INPUT_SIZE`) payments to an Autonomous Agent (AA) address and then send a trigger that forces the AA to spend its balance (e.g. via a bounce or a `send`/send-all response). The AA-response composer, `completePaymentPayload`/`iterateUnspentOutputs` in `aa_composer.js`, has no cap on how many UTXOs it consumes as inputs, and `validation.js` explicitly skips the normal `MAX_INPUTS_PER_PAYMENT_MESSAGE` cap for AA-generated units. Every full node that processes the trigger must then validate a payment message whose input array can be arbitrarily long, causing quadratic-time validation (repeated `Array.indexOf` scans over `objValidationState.arrInputKeys`) and a long sequential chain of per-input database queries — analogous to the knot-resolver DoS pattern of "many resource records processed inefficiently."

### Finding Description
When an AA needs to fund a response payment, `aa_composer.js` reads all unspent outputs on the AA's address and folds them into `payload.inputs` with no size limit: [1](#0-0) 

The dust filter only excludes very small byte outputs (`amount < FULL_TRANSFER_INPUT_SIZE`), so outputs at or slightly above this threshold are accepted: [2](#0-1) 

Contrast this with the ordinary wallet coin-selection routine `pickDivisibleCoinsForAmount` in `inputs.js`, which explicitly bounds the number of picked inputs with `LIMIT constants.MAX_INPUTS_PER_PAYMENT_MESSAGE-2`: [3](#0-2) 

No equivalent limit exists in the AA composer's `iterateUnspentOutputs` loop.

Crucially, `validation.js` explicitly exempts AA-authored units from the "too many inputs" check that protects normal user-composed units: [4](#0-3) 

The subsequent per-input validation loop performs an `Array.prototype.indexOf` scan over `objValidationState.arrInputKeys` for every input to detect duplicate spends, and this key list grows with every processed input — making the total cost of duplicate-key checking O(n²) in the number of inputs, in addition to the O(n) sequential database round-trips (`async.forEachOfSeries`) needed to look up each source output: [5](#0-4) [6](#0-5) 

Because AA response units are deterministically recomputed and validated by every full node in the network upon witnessing the triggering unit, this cost is paid by the entire validating network for a single crafted trigger, not just by the attacker.

### Impact Explanation
This matches the "network unable to confirm new units" / node-disagreement class of impact: an attacker can pre-fund an AA address with thousands of small outputs (each a normal, in-scope "unit poster" payment) and then submit a single trigger that causes the AA to consolidate all of them into one payment message. Because the input-count cap is bypassed for AA units, and duplicate-key detection is O(n²), every node validating that AA response experiences a CPU spike proportional to the square of the number of pre-funded outputs, and also a long chain of sequential DB queries, which can stall validation of subsequent units and degrade the whole node's throughput — a High-severity availability issue for the network, closely analogous to CVE-2019-19331's algorithmic-complexity DoS via many records in one message.

### Likelihood Explanation
Likelihood is Medium-to-High: creating many small payment outputs to an address is trivial and cheap for an attacker (only bounded by the attacker's own transaction fees for the funding phase), and triggering an AA to consume its whole balance (e.g. `bounce_fees`, an explicit `send`/send-all statement, or default insufficient-condition bounce) is a normal AA usage pattern that doesn't require cooperation from the AA's author. No privileged or malicious-node/peer capability is required — only posting ordinary units and a single AA trigger.

### Recommendation
- Enforce `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` (or a dedicated AA-specific cap) inside `iterateUnspentOutputs`/`completePaymentPayload` in `aa_composer.js`, stopping accumulation of inputs once the limit is reached (and issuing change/bouncing gracefully if funds are insufficient within that cap).
- Remove or tighten the `&& !objValidationState.bAA` exemption in `validation.js`'s "too many inputs" check, or apply an equivalent hard ceiling specific to AA payment messages.
- Replace the O(n) `arrInputKeys.indexOf` duplicate-key checks with an O(1) hash-set/map lookup to eliminate the quadratic component regardless of input-count limits.

### Proof of Concept
1. From an ordinary wallet, send N (e.g. 5,000–20,000) separate payments of `FULL_TRANSFER_INPUT_SIZE` bytes each to a target AA's address, each in its own unit (in scope: normal unit posting).
2. Send a trigger to the AA that causes it to respond by spending its full balance (e.g. a `send`/send-all statement, or an unmet condition causing a bounce that refunds the trigger's own bytes plus consumes the AA's held balance).
3. Observe that `aa_composer.js`'s `iterateUnspentOutputs` accumulates all N outputs into `payload.inputs` without limit, producing a response unit with an oversized `inputs` array.
4. Observe that every node validating this response unit executes `validatePaymentInputsAndOutputs` in `validation.js`, which skips the `MAX_INPUTS_PER_PAYMENT_MESSAGE` check for AA units and performs O(n²) `indexOf` scans plus N sequential DB round trips, measurably increasing validation latency/CPU usage proportional to N².

Note: I was unable to fully trace the exact save/validate call path that submits the AA-generated response unit back through `validation.js`'s `validate()` (tool access ended before confirming this final wiring), though `validatePaymentInputsAndOutputs`'s explicit `!objValidationState.bAA` bypass strongly indicates AA-authored payments are indeed run through this same validation function with the cap intentionally disabled for AAs.

### Citations

**File:** aa_composer.js (L1102-1138)
```javascript
			function iterateUnspentOutputs(rows) {
				for (var i = 0; i < rows.length; i++){
					var row = rows[i];
					var input = { unit: row.unit, message_index: row.message_index, output_index: row.output_index };
					arrUsedOutputIds.push(row.output_id);
					arrConsumedOutputs.push({asset: asset || 'base', amount: row.amount});
					payload.inputs.push(input);
					total_amount += row.amount;
					if (is_base) {
						net_target_amount += FULL_TRANSFER_INPUT_SIZE;
						size += FULL_TRANSFER_INPUT_SIZE;
						target_amount = net_target_amount + getOversizeFee(size);
					}
					if (total_amount < target_amount)
						continue;
					if (total_amount === target_amount && payload.outputs.length > 0) {
						bFound = true;
						if (send_all_output)
							continue;
						else
							break;
					}
					var additional_output_size = is_base ? OUTPUT_SIZE + (bWithKeys ? OUTPUT_KEYS_SIZE : 0) : 0; // the same for send-all
					var change_amount = total_amount - (net_target_amount + additional_output_size + getOversizeFee(size + additional_output_size));
					if (change_amount > 0) {
						bFound = true;
						if (send_all_output) {
							console.log("change " + change_amount + ", storage_size " + storage_size);
							send_all_output.amount = change_amount;
						}
						else {
							payload.outputs.push({ address: address, amount: change_amount });
							break;
						}
					}
				}
			}
```

**File:** aa_composer.js (L1140-1155)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** inputs.js (L129-145)
```javascript
	function pickMultipleCoinsAndContinue(){
		conn.query(
			`SELECT unit, message_index, output_index, amount, address, blinding
			FROM outputs
			CROSS JOIN units USING(unit)
			${conf.bLight ? "LEFT JOIN aa_responses ON unit=response_unit" : ""}
			WHERE address IN(?) AND asset${asset ? "="+conn.escape(asset) : " IS NULL"} AND is_spent=0
				AND sequence='good' ${confirmation_condition}
				${constants.bDevnet
					? ""
					: (conf.bLight
						? `AND ( response_unit IS NULL OR aa_responses.creation_date<${conn.addTime('-30 SECOND')} )`
						: `AND ( units.is_aa_response IS NULL OR units.creation_date<${conn.addTime('-30 SECOND')} )`
					)
				}
			ORDER BY amount DESC LIMIT ?`,
			[arrSpendableAddresses, constants.MAX_INPUTS_PER_PAYMENT_MESSAGE-2],
```

**File:** validation.js (L2137-2140)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
```

**File:** validation.js (L2237-2252)
```javascript
	// max 1 issue must come first, then transfers, then hc, then witnessings
	// no particular sorting order within the groups
	async.forEachOfSeries(
		payload.inputs,
		function(input, input_index, cb){
			if (!isNonemptyObject(input))
				return cb("input must be a non-empty object");
			if (objAsset){
				if ("type" in input && input.type !== "issue")
					return cb("non-base input can have only type=issue");
			}
			else{
				if ("type" in input && !["issue", "headers_commission", "witnessing"].includes(input.type))
					return cb("bad input type");
			}
			var type = input.type || "transfer";
```

**File:** validation.js (L2402-2405)
```javascript
					var input_key = (payload.asset || "base") + "-" + input.unit + "-" + input.message_index + "-" + input.output_index;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
```
