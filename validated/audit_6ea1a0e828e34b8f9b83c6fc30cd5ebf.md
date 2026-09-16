## Analysis

The reported class of bug — a payable entry point that silently swallows the caller's coins whenever the call does not match the expected "type"/branch, instead of reverting or refunding — has a direct structural analog in `ocore`'s Autonomous Agent (AA) trigger-handling code.

An AA is invoked by any unprivileged user simply by sending a payment/message unit ("trigger") to the AA's address. Just like `Trading.sol`'s `openTrade` accepts ETH regardless of `_type` and can waste it if the branch doesn't expect native coin, an AA's `messages` template accepts arbitrary `trigger.outputs` (any asset/amount) regardless of whether any `if` case in the AA definition actually matches that specific payment. When none of the AA's cases match the trigger (e.g., because the caller sent the wrong asset, or a numeric precondition fails), `aa_composer.js` explicitly "eats" the coins and performs no refund: [1](#0-0) 

This is the same acknowledged trade-off as the reported issue: a design choice to avoid the extra gas/complexity of validating and reverting on unexpected payment types, at the cost of caller funds being unrecoverably absorbed by the contract/AA when the caller's payment doesn't match what the logic expects.

### Title
Unrefunded coins absorbed by AA when trigger payment matches no `if` case - (File: aa_composer.js)

### Summary
When a user (unprivileged unit poster) sends a trigger unit to an Autonomous Agent, `handleTrigger` in `aa_composer.js` evaluates the AA's `messages.cases` against the trigger. If evaluation succeeds but produces no matching response messages (e.g., the trigger sent the "wrong" asset/amount for any defined case, analogous to sending ETH where USDC was expected in `Trading.sol`), the code explicitly eats the coins and returns an empty successful response instead of bouncing/refunding.

### Finding Description
`handleTrigger` calls `evaluateAA`, filters the resulting `messages`, and if the filtered array is empty, calls `handleSuccessfulEmptyResponseUnit(null)` with the comment "eat the received coins and send no response, state changes are still performed": [2](#0-1) 

This differs from `bounce()`, which is only invoked on explicit `bounce()` calls in the oscript or on hard errors (e.g., insufficient fee coverage), and even `bounce()` itself silently keeps (does not refund) any asset whose amount is less than or equal to the configured `bounce_fees` for that asset: [3](#0-2) 

Sample AA logic in the test suite illustrates the exact scenario: a bank AA has one case that pays out a withdrawal only `if trigger.data.withdraw AND ... AND $required_amount <= var[$key]`, and a second case only for deposits `if !trigger.data.withdraw`: [4](#0-3) 

If a caller sends `trigger.data.withdraw = true` but the balance/precondition check fails, neither case matches, `messages` filters down to empty, and any bytes/asset sent with that trigger unit are permanently absorbed into the AA's balance with no bounce and no refund path back to the sender — mirroring `Trading.sol`'s loss of ETH sent for the wrong `_type`.

### Impact Explanation
An unprivileged user interacting with any AA whose oscript definition has gaps between its `if` conditions (a common pattern, since AA authors are not required to cover every possible trigger combination with a matching/refunding branch) can permanently lose the coins sent with a trigger unit that fails to match any case. This is a genuine, protocol-level fund-loss vector for callers, not merely a resource-only or cosmetic issue, since the lost funds become part of the AA balance without any state change crediting the sender.

### Likelihood Explanation
Likelihood is proportional to how many deployed AAs lack a catch-all/refund branch for unmatched triggers — a very common authoring pattern given the design intentionally omits any mandatory reject/refund fallback. Any ordinary user mistake (wrong asset, wrong amount, unmet precondition) when composing a trigger unit can trigger this path, so likelihood of occurrence for careless senders is high, matching the "Medium" categorization used for the original `openTrade` report.

### Recommendation
This mirrors the acknowledged trade-off in the external report: adding a mandatory "no case matched, bounce/refund automatically" mechanism in `aa_composer.js` (rather than "eat the received coins") would eliminate this fund-loss class, at the cost of extra gas/complexity for every trigger execution. Given that `ocore` already implements `bounce()` semantics for other failure conditions, extending that same bounce path to the "no messages after filtering" case (line 1873) rather than silently eating the coins would align behavior with the recommendation from the original report (revert/refund on unexpected payment scenarios) while preserving the option for AA authors to opt out if they prefer the gas savings.

### Proof of Concept
1. Deploy the `bank_without_percent.oscript` AA shown in [5](#0-4) , or any AA with disjoint `if` branches.
2. Send a trigger unit with `trigger.data.withdraw = true` and `trigger.data.asset`/`amount` set such that `$required_amount <= var[$key]` is false (i.e., an underfunded/invalid withdrawal request), while also attaching a payment of extra bytes/asset to the trigger.
3. Observe that neither AA case matches: `evaluateAA` produces `template.messages` that filter to an empty array in `handleTrigger` at [6](#0-5) .
4. `handleSuccessfulEmptyResponseUnit(null)` is invoked; the attached bytes/asset are absorbed into the AA's balance and the sender receives no bounce, no refund, and no state credit for the amount sent.

### Citations

**File:** aa_composer.js (L930-944)
```javascript
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
```

**File:** aa_composer.js (L1865-1877)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
			var messages = template.messages;
			if (!messages)
				return bounce('no messages');
			// this will also filter out the special message that performs the state changes
			messages = messages.filter(function (message) { return (isNonemptyObject(message) && 'payload' in message && (message.app !== 'payment' || isNonemptyObject(message.payload) && Array.isArray(message.payload.outputs))); });
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
```

**File:** test/ojson.test.js (L815-877)
```javascript
test('Bank with deposits without interest', t => {
	var ojson = readSample('a_bank_without_percent.oscript')
	parseOjson(ojson, (err, res) => { t.deepEqual(err || res,
		[
			"autonomous agent",
			{
				messages: {
					cases: [
						{
							if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					$base_key = 'balance_'||trigger.address||'_'||'base';
					$fee = 1000;
					$required_amount = trigger.data.amount + ((trigger.data.asset == 'base') ? $fee : 0);
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND $required_amount <= var[$key] AND $fee <= var[$base_key]
				}`,
							messages: [
								{
									app: 'payment',
									payload: {
										asset: "{trigger.data.asset}",
										outputs: [
											{address: "{trigger.address}", amount: "{trigger.data.amount}"}
										]
									}
								},
								{
									app: 'state',
									state: `{
							var[$key] = var[$key] - trigger.data.amount;
							var[$base_key] = var[$base_key] - $fee;
						}`
								}
							]
						},
						{
							if: "{!trigger.data.withdraw}",
							messages: [{
								app: 'state',
								state: `{
						$asset = trigger.output[[asset!=base]].asset;
						if ($asset == 'ambiguous')
							bounce('ambiguous asset');
						if (trigger.output[[asset=base]] > 10000){
							$base_key = 'balance_'||trigger.address||'_'||'base';
							var[$base_key] = var[$base_key] + trigger.output[[asset=base]];
							$response_base = trigger.output[[asset=base]] || ' bytes\\n';
						}
						if ($asset != 'none'){
							$asset_key = 'balance_'||trigger.address||'_'||$asset;
							var[$asset_key] = var[$asset_key] + trigger.output[[asset=$asset]];
							$response_asset = trigger.output[[asset=$asset]] || ' of ' || $asset || '\\n';
						}
						response['message'] = 'accepted coins:\\n' || ($response_base otherwise '') || ($response_asset otherwise '');
					}`
							}]
						},
					]
				}
			}
		]
	)});
});
```
