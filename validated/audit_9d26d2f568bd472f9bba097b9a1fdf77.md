Based on the analysis, I've found the analogous vulnerability pattern in the ocore AA (Autonomous Agent) execution engine.

### Title
Payment to a griefing/misbehaving AA recipient causes the entire primary trigger's response chain to revert, allowing a malicious secondary AA to permanently block payouts from any AA that sends funds to it - ([File: aa_composer.js])

### Summary
The external report describes a `royaltyRecipient` contract that reverts on receiving ether, causing the entire `sell` operation (and its bounce fee accounting/protocol side effects) to fail, denying service to the caller. The analogous root cause in `ocore` is that when a primary AA's response sends a payment output to *another* AA address, `handleSecondaryTriggers` recursively invokes `handleTrigger` on that recipient AA as a secondary trigger [1](#0-0) . If that secondary AA's execution "bounces" (reverts) for any reason under its control (e.g. an unconditional `bounce()` call in its logic, similar in spirit to a contract that always reverts on receiving ether), the error propagates back and the *entire* primary trigger's state changes and payments are rolled back via `revert()`, not just the secondary AA's leg [2](#0-1) .

### Finding Description
`handleSecondaryTriggers` is called whenever a message's payment `outputs` in an AA response unit target an address that is itself a registered AA [3](#0-2) . For each such output address, a `child_trigger` is built and `handleTrigger` is called recursively with `bSecondary: true` [4](#0-3) . If the child AA's own logic causes it to bounce (e.g., via an explicit `bounce()` statement, similar to the report's `EthRejecter.receive()` reverting), the `async.eachSeries` callback receives an error, and because the *parent* trigger is not itself secondary, the code calls `revert()` instead of just bouncing the child leg [5](#0-4) . `revert()` then rolls back all cached AA responses, clears all state var changes, and rolls back the database transaction to the savepoint before this trigger's initial balance updates were applied `ROLLBACK TO SAVEPOINT initial_balances` [6](#0-5) . This mirrors the `remote function that fails` test where a callee's `bounce("==5")` propagates and bounces the caller's whole trigger [7](#0-6) .

This means any AA (analogous to the "collection" in the report) that pays a fee/royalty/commission to an externally-controlled or attacker-supplied AA address (analogous to `royaltyRecipient`) is at the mercy of that recipient AA's code. If the recipient AA is designed (or can be redefined/pointed) to always bounce when receiving funds under certain conditions, every legitimate operation of the paying AA that routes funds to it will fail and roll back, exactly like the reported issue where an `EthRejecter` recipient blocks `sell()`.

### Impact Explanation
Unlike the EVM case where only the transfer itself reverts, in `ocore` a bounce of a secondary AA rolls back the *entire* chain of state changes and payments of the primary AA that initiated it (see `revert()` restoring `stateVars`, clearing `batch`, and rolling back to `SAVEPOINT initial_balances`) [6](#0-5) . This is a stronger DoS/fund-freezing primitive than the original finding: any protocol AA (marketplace, auction, DEX, fee splitter, etc.) that forwards part of its proceeds to a user-configurable AA address can be completely bricked — every trigger that would otherwise succeed instead bounces and the user's principal is refunded minus bounce fees, but the AA's intended state transition (e.g. recording a sale, updating an order book, releasing an NFT/asset) never happens. This qualifies as AA fund loss/freezing and denial-of-service for legitimate users interacting with the AA.

### Likelihood Explanation
This requires that the AA design routes a payment to an address supplied or influenced by an untrusted party (e.g., a "royalty recipient" or "referrer" address parameter) and that address happens to be (or is later redefined/pointed to be) a registered AA whose logic bounces under attacker-chosen conditions. This is a realistic pattern for marketplace-style or fee-splitting AAs ported from EVM designs (like the one in the report), since AA authors migrating such patterns to Obyte may not anticipate that "sending money" to an address can itself execute arbitrary code that can fail and roll back the sender's whole operation. Likelihood is Medium: it depends on specific AA application design choices rather than a protocol-wide unconditional bug, but the underlying `ocore` mechanics fully enable it.

### Recommendation
- AA authors should avoid making critical, non-bypassable state transitions dependent on payments succeeding to externally-configurable AA addresses; if payment to a fee/royalty recipient AA fails, the payment leg should be isolated (e.g., paid last, or paid via a `bAir`/isolated dry-run first, or queued/pull-based rather than push-based) so that a bounce there does not roll back the primary operation's core effects.
- At the `ocore` engine level, consider offering (or documenting) a mechanism for "fire-and-forget" secondary payments where a bounce of a payment-only secondary AA does not force `revert()` of the primary AA's already-computed state changes, distinguishing between "protocol-critical" secondary calls and "value-forwarding" secondary payments similar to the pull-payment/WETH mitigation suggested in the original report.

### Proof of Concept
The existing test `calling a remote function that fails` demonstrates the underlying mechanic: a `remote_aa` whose getter unconditionally calls `bounce("==5")` when invoked with `trigger.data.x == 5` causes the calling AA's entire response to bounce [7](#0-6) . The same propagation path is exercised via payment-triggered secondary AAs in `handleSecondaryTriggers`/`revert()` [8](#0-7) : an application-level AA (e.g., an NFT marketplace AA) that sends a royalty/fee payment to an attacker-supplied AA address whose definition contains an unconditional `bounce(...)` in its `messages`/`init` would have every sale/payout involving that recipient revert, freezing the marketplace AA's intended operation exactly as in the reported `royaltyRecipient` issue.

### Citations

**File:** aa_composer.js (L1702-1757)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
				},
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
	}
```

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
```

**File:** test/aa_composer.test.js (L1625-1712)
```javascript
test.cb.serial('calling a remote function that fails', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var remote_aa = ['autonomous agent', {
		getters: `{
			$f = ($x) => {
				if ($x==5)
					bounce("==5");
			};
		}`,
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.initial_address}", amount: 1000}
					]
				}
			}
		]
	}];
	var remote_aa_address = objectHash.getChash160(remote_aa);
	
	var aa = ['autonomous agent', {
		init: `{
			$ret = ${remote_aa_address}.$f(trigger.data.x);
		}`,
		messages: [
			{
				app: 'state',
				state: `{
					var['ret'] = $ret;
				}`
			}
		]
	}];

	validateAA(remote_aa, async err => {
		t.deepEqual(err, null);
		await asyncAddAA(remote_aa);

		validateAA(aa, async err => {
			t.deepEqual(err, null);

			var aa_address = objectHash.getChash160(aa);
			await asyncAddAA(aa);
			
			aa_composer.dryRunPrimaryAATrigger(trigger, aa_address, aa, (arrResponses) => {
				t.deepEqual(arrResponses.length, 1);
				t.deepEqual(arrResponses[0].bounced, true);
				t.deepEqual(arrResponses[0].response.error, {
				"message": "==5",
				"formattedContext": "",
				"codeLines": [
					{
					"lineNumber": 4,
					"formula": "bounce(\"==5\");"
					}
				],
				"trace": [
					{
					"type": "aa",
					"aa": "ZAQI55OLQYXSHH5W3YSKN43WFRH4HA62",
					"xpath": "/init",
					"line": 2
					},
					{
					"type": "getter",
					"aa": "TEHAPNFMCMPUKQKJJJZVHDZEDXVLQXRX",
					"xpath": "/getters",
					"name": "f",
					"line": 4
					}
				]
				});
				fixCache();
				t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
				t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
				t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
				t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
				t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
				t.end();
			});
		});
	});
});
```
