Confirmed: `checkAAOutputs` is only invoked from `wallet.js` before composing a payment via the standard wallet flow — it is a client-side, opt-in warning, not a protocol-level safeguard. Any unit poster who constructs and posts a unit directly (bypassing `wallet.js`) sending an amount below an AA's `bounce_fees` gets no warning at all, and the network will accept the unit if it otherwise validates.

### Title
AA fund loss from underpaid bounce_fees causes silent fund seizure with no on-chain protection - (File: aa_composer.js)

### Summary
Any unprivileged unit poster who sends a payment to an autonomous agent (AA) with an amount below the AA's declared `bounce_fees` irrevocably loses those funds. When the trigger fails validation or bounces, `aa_composer.js`'s `bounce()` function checks whether the received amount covers `bounce_fees` per asset; if not, it silently keeps the funds in the AA's balance and returns no response unit at all, with no restitution to the sender.

### Finding Description
In `handleTrigger`, before evaluating the AA, the code checks the trigger's declared `bounce_fees` against the outputs the trigger actually sent: [1](#0-0) 
If the base-byte output is below `bounce_fees.base`, or any asset amount is below its corresponding `bounce_fees[asset]`, `bounce()` is called immediately.

Inside `bounce()`, when the amount received is insufficient to cover the fee (either globally for base, or per-asset), the function returns via `finish(null)` without composing or sending any refund message at all: [2](#0-1) 
Specifically:
- Line 928: if `trigger.outputs.base < bounce_fees.base`, no bounce unit is ever created — the AA keeps 100% of whatever bytes were sent.
- Lines 932-936: for any non-base asset, if `fee > amount`, that asset's tokens are likewise absorbed with zero recourse for the sender.

The only mitigation that exists is a client-side, opt-in check, `checkAAOutputs`, used exclusively by `wallet.js`'s payment composition flow to warn the user before sending: [3](#0-2) 
This function is never invoked by validation, `aa_composer.js`, or any protocol-level code path — it only protects users who compose payments through the reference wallet's `sendMultiPayment`. A single unprivileged unit poster who crafts and broadcasts a raw unit directly (e.g., via `composer.composeJoint` used outside the wallet path, or any custom client) bypasses this warning entirely, and the network has no rule preventing the unit from being accepted and the funds from being seized by the AA.

This is directly analogous to the reported Optimism bridge issue: an unprivileged actor underpays the required fee/gas parameter (`l2Gas` there, `bounce_fees` here) for a cross-domain/AA operation, the receiving side's operation fails/bounces, and the deposited/sent funds are permanently lost with no automatic refund path.

### Impact Explanation
This is a concrete AA fund loss scenario: any address (not privileged, not an AA owner) that sends bytes or an asset to an AA below the AA's `bounce_fees` threshold loses those funds permanently and irreversibly the moment the trigger fails or the AA's logic calls `bounce()`. There is no automated recovery, and the loss is deterministic and reachable by any single poster with no cooperation from other parties. Because the mitigation (`checkAAOutputs`) lives only in the wallet UI layer, any non-wallet client, bot, exchange integration, or manually-crafted transaction is fully exposed.

### Likelihood Explanation
Likelihood is high because:
- AA definitions are public (`aa_addresses` table / `readAADefinitions`), so `bounce_fees` values are discoverable, but many integrators may still fail to check them, especially for multi-asset AAs where per-asset `bounce_fees` are easy to overlook.
- The check in `aa_composer.js` at lines 1851-1859 executes on virtually every primary trigger, so any underpayment reliably triggers the fund-loss path rather than a graceful failure.
- Non-wallet posters (custom scripts, other node software, smart posting tools) have no built-in warning since `checkAAOutputs` is wallet-only.

### Recommendation
Given the design intentionally sacrifices bounced funds below the fee threshold to prevent spam/DoS on AAs, a full protocol fix (e.g., proportional partial refunds) may not be desirable. Instead, as with the LiFi resolution referenced in the external report, the risk should be prominently documented for all AA integrators (not just wallet.js consumers), and ideally the `checkAAOutputs`-equivalent warning logic should be exposed as a reusable utility that any client — not only the reference wallet — can call before posting a payment to an AA address.

### Proof of Concept
1. Deploy/observe an AA with `bounce_fees: { base: 10000 }` (see the pattern in `test/samples/just_a_bouncer.oscript`). [4](#0-3) 
2. Craft and post a unit (bypassing `wallet.js`, e.g. directly via `composer.composeJoint`) sending, say, 2000 bytes to that AA address with trigger data that causes the AA's messages to fail or that simply supplies fewer bytes than `bounce_fees.base`.
3. `handleTrigger` runs, hits the check at `aa_composer.js` lines 1852-1854, calls `bounce('received bytes are not enough to cover bounce fees')`.
4. Inside `bounce()`, line 928 evaluates true (`2000 < 10000`), and `finish(null)` is called — no response unit, no refund. The 2000 bytes remain permanently credited to the AA address. [5](#0-4) 
This exact scenario is already covered by the existing unit test `'less than bounce fees'`, which asserts `response_unit: null` and `objResponseUnit: null` — confirming the funds are consumed with no unit produced to return them.

### Citations

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
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
	}
```

**File:** aa_composer.js (L1851-1859)
```javascript
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```

**File:** aa_addresses.js (L120-155)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (err, rows) {
		if (err)
			return handleResult(err);
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
```

**File:** test/samples/just_a_bouncer.oscript (L1-14)
```text
{
	bounce_fees: { base: 10000 },
	messages: [
		{
			app: 'payment',
			payload: {
				asset: 'base',
				outputs: [
					{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
				]
			}
		}
	]
}
```

**File:** test/aa_composer.test.js (L120-153)
```javascript
test.cb.serial('less than bounce fees', t => {
	var trigger = { outputs: { base: 2000 }, data: { x: 333 } };
	var aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 500}"}
					]
				}
			}
		]
	}];
	var address = objectHash.getChash160(aa);
	addAA(aa);
	
	aa_composer.dryRunPrimaryAATrigger(trigger, address, aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 1);
		t.deepEqual(arrResponses[0].aa_address, address);
		t.deepEqual(arrResponses[0].bounced, true);
		t.deepEqual(arrResponses[0].response_unit, null);
		t.deepEqual(arrResponses[0].objResponseUnit, null);
		t.deepEqual(arrResponses[0].response.error, "received bytes are not enough to cover bounce fees");
		fixCache();
		t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
		t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
		t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
		t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
		t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
		t.end();
	});
```
