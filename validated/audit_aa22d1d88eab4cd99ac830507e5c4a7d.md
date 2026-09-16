## Analysis

The reported Solidity bug is a **griefing/DoS via a forced revert during an outgoing refund**, which locks in a lower bid because the entire transaction (including state updates) reverts when the refund fails. `ocore`'s AA (Autonomous Agent) engine has a directly analogous mechanic through **secondary triggers**: whenever a primary AA response sends a payment to an address that is itself an AA, that payment is treated as an automatic call into that AA (`handleSecondaryTriggers`), and if the secondary AA bounces, the *entire* primary response — payments and state changes — is rolled back via `revert()`.

### Root cause

When an AA sends outputs, `sendUnit()` finalizes the response unit and then calls `handleSecondaryTriggers(objUnit, arrOutputAddresses)` for every output address that is itself an AA address: [1](#0-0) 

Inside `handleSecondaryTriggers`, each AA-address recipient is triggered synchronously, and if it bounces, the error is bubbled up and the **entire primary trigger is reverted**, not just the failed sub-payment: [2](#0-1) 

`revert()` then rolls back all state variable changes and balance changes to the initial savepoint and converts the whole call into a bounce, refunding the *new* trigger's funds (minus bounce fee) back to its own sender — exactly like the Solidity bug where the caller's transaction reverts and no state progress is made: [3](#0-2) 

### Analog Attack

Consider a bidding-style AA (structurally similar to `51_attack_game.oscript`/`fundraising_proxy.oscript` patterns in this repo, which pay out to `trigger.address` or other AAs) where a new higher bid causes the AA to refund the previous highest bidder's address in the same response message set: [4](#0-3) 

If the "previous bidder" address is itself an AA definition that unconditionally calls `bounce(...)` on any incoming trigger (trivial to construct, e.g. `test/samples/just_a_bouncer.oscript`-style logic but always bouncing): [5](#0-4) 

then every subsequent attempt by a legitimate higher bidder to outbid the attacker triggers a secondary-trigger bounce, which forces `revert()` on the primary AA response. The primary AA's `bounce_fees` config controls the fee taken, and the confirmed test suite demonstrates this bounce mechanic already exists and is deterministic: [6](#0-5) 

Because the revert discards the state update that would have recorded the new (higher) bid, the malicious bidder's AA address permanently remains the recorded winner in AA state — any competitor's bid unit gets bounced back to them (minus the bounce fee) with no state progress, exactly mirroring the "malicious bidders will successfully bid at a lower price" impact from the source report.

### Title
Malicious bidder/beneficiary AA can force `revert()` of any AA that pays it, permanently blocking outbid/state-update attempts - (File: aa_composer.js)

### Summary
Any AA design that pays out to a "previous winner"/"beneficiary" address (auction, ICO, fundraising-proxy style AAs) is vulnerable if that address is itself an AA. The recipient AA can unconditionally `bounce()` on every trigger, and because the ocore AA engine (`handleSecondaryTriggers`/`revert()` in `aa_composer.js`) rolls back the *entire* primary response (state changes + payments) when a secondary-triggered AA bounces, an attacker can permanently prevent any AA logic that depends on paying them from ever completing successfully.

### Finding Description
`sendUnit()` automatically fires secondary triggers for every AA-address recipient of an outgoing payment message [1](#0-0) . If that secondary AA bounces, `handleSecondaryTriggers`'s `async.eachSeries` error handler calls `revert(...)` on the *primary* trigger when not already secondary [7](#0-6) . `revert()` restores all original state variables/balances via `ROLLBACK TO SAVEPOINT initial_balances`, clears all accumulated responses, and converts the entire primary call into a bounce that only returns the caller's own bounce fee-adjusted funds [8](#0-7) . This means the state update the primary AA intended to make (e.g., recording a new highest bidder) never happens, because it's tied atomically to the payment leg that failed due to the malicious recipient AA.

### Impact Explanation
For any "auction"/"first refund, then update winner" style AA pattern (the codebase's own sample AAs use this exact pattern of paying `trigger.address` or forwarding funds to other addresses/AAs, e.g. `fundraising_proxy.oscript`, `51_attack_game.oscript`), an attacker who controls the address currently recorded as "winner"/"beneficiary" — by deploying it as an always-bouncing AA — can permanently deny any future participant from displacing them, since every attempt to pay them out during the accounting update will bounce and roll back the entire competing bid. This causes state to be stuck (freezing correct progress) and lets the attacker retain a favorable position (e.g., lowest winning bid, or first-mover advantage) indefinitely, which is a concrete AA fund-loss/freezing and node-disagreement-adjacent impact matching High severity.

### Likelihood Explanation
Likelihood is high for any AA author who writes an auction/refund-style AA without defending against AA-address recipients: the attack requires only deploying a simple always-`bounce()`ing AA at the address used to receive refunds/payouts, which is fully within reach of an unprivileged AA author/trigger sender — no special privileges, hub, or node compromise needed.

### Recommendation
AA developers using auction/refund patterns should avoid coupling payment-to-recipient with state updates in a way that an always-bouncing recipient AA can revert; e.g., use a pull-payment/withdrawal pattern (track "owed" balances in state var, let the winner claim their loss separately) instead of pushing funds to the previous bidder synchronously within the same response, since the revert-on-secondary-bounce behavior in `aa_composer.js` (`handleSecondaryTriggers`/`revert()`) is a structural feature of the AA engine and not something that can be disabled at the protocol level.

### Proof of Concept
1. Deploy AA `B` (bouncer) whose only logic is `bounce('always fail')` on every trigger.
2. Deploy Auction AA `A` that stores `var['highest_bidder']` and, on a new higher bid, sends a refund payment message to the old `var['highest_bidder']` address plus a state update setting the new highest bidder, in the same response (pattern per `test/samples/51_attack_game.oscript` lines 66-94 [4](#0-3) ).
3. Attacker bids first from address `B` (the bouncer AA), becoming `highest_bidder`.
4. A legitimate bidder posts a higher bid trigger to `A`; `A`'s response payment message pays `B` the refund, which auto-fires `handleSecondaryTriggers` into `B`; `B` bounces unconditionally.
5. Per `aa_composer.js` lines 1743-1750 and 1759-1783, `A`'s entire response (including the `highest_bidder` state update) is reverted and instead the legitimate bidder's own funds are bounced back to them minus the bounce fee.
6. Repeat step 4 for any future bidder — `B` remains `highest_bidder` forever, having "won" at the lowest price.

### Citations

**File:** aa_composer.js (L1411-1421)
```javascript
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
									if (arrOutputAddresses.length === 0)
										return finish(objUnit);
									fixStateVars();
									addResponse(objUnit, function () {
										updateStorageSize(function (err) {
											if (err)
												return revert(err);
											handleSecondaryTriggers(objUnit, arrOutputAddresses);
										});
									});
```

**File:** aa_composer.js (L1736-1754)
```javascript
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

**File:** test/samples/51_attack_game.oscript (L66-94)
```text
			{ // contribute to a team
				if: `{trigger.data.team AND !$bFinished}`,
				init: `{
					if (!var['team_' || trigger.data.team || '_asset'])
						bounce('no such team');
					if (var['winner'] AND var['winner'] == trigger.data.team)
						bounce('contributions to candidate winner team are not allowed');
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: `{var['team_' || trigger.data.team || '_asset']}`,
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.output[[asset=base]]}"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['team_' || trigger.data.team || '_amount'] += trigger.output[[asset=base]];
							if (var['team_' || trigger.data.team || '_amount'] > balance[base]*0.51){
								var['winner'] = trigger.data.team;
								var['challenging_period_start_ts'] = timestamp;
							}
						}`
					}
				]
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
