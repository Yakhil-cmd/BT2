This confirms the exact analog: `handleSecondaryTriggers` in `aa_composer.js` calls a child AA when the primary AA's response unit pays another AA address, and if that secondary AA bounces for any reason, `revert()` is triggered for the primary trigger, which does `ROLLBACK TO SAVEPOINT initial_balances`, clears `stateVars` and `batch`, and re-bounces the whole primary AA — undoing every legitimate state change and payment the primary AA made in that trigger. [1](#0-0) [2](#0-1) 

### Title
Primary AA operations (e.g. collateral withdrawal / payout logic) can be permanently blocked or fund-frozen when an unrelated secondary AA in the same trigger bounces - (File: aa_composer.js)

### Summary
`handleTrigger` in `aa_composer.js` automatically fires a *secondary trigger* on every AA address that receives a payment output from a primary AA's response unit [3](#0-2) . If that secondary AA bounces for any reason — including running out of an asset balance it needs to pay out, exactly the "insufficient reward token" scenario in the referenced report — `handleSecondaryTriggers` treats this as a fatal error for the *whole* primary trigger and calls `revert()` [4](#0-3) . `revert()` then rolls back the DB to `SAVEPOINT initial_balances`, clears `stateVars`, and clears the `batch`, discarding all of the primary AA's legitimate state updates and payments before re-bouncing the entire trigger [2](#0-1) . This mirrors the report's root cause: a downstream contract/AA (analogous to the master-chef reward contract, controlled by a third party or simply undercapitalized) failing causes an otherwise-valid, self-contained operation (e.g. releasing/decollateralizing funds to a user) to be unconditionally undone.

### Finding Description
An AA author frequently composes protocols where a single response unit pays multiple addresses, some of which are themselves AAs (e.g., a fee-collector AA, an oracle-fee AA, a reward-distribution AA). Because ocore's secondary-trigger mechanism is fully atomic across the whole call chain stemming from one primary trigger unit, any bounce anywhere in that chain (not just direct dependents of the withdrawing address) forces `revert()` on the primary AA [4](#0-3) . Unlike the primary AA's own `bounce()`, which simply returns the trigger sender's coins minus fees, `revert()` unwinds *committed* database state and previously-saved intermediate AA responses in the chain (`revertResponsesInCaches`), and then still bounces — meaning the user's originally-legitimate action (e.g. "withdraw my collateral", "unwrap my staked asset") never lands, purely because a semantically-unrelated payee AA elsewhere in the chain ran out of balance or otherwise failed its own logic. The test `chain of AAs` and `issue recently defined asset` demonstrate the intentional, load-bearing nature of this chaining behavior [5](#0-4) , confirming it is a real, reachable execution path for any trigger sender, not a hypothetical.

### Impact Explanation
This is functionally identical in effect to the referenced M-04 finding: a legitimate operation (fund release/withdrawal) becomes permanently un-executable as long as the dependent secondary AA remains unable to fulfill its obligation. Because the whole call chain is atomic and there is no equivalent of `emergencyWithdraw` fallback inside ocore's AA composer, an AA author who architects a lending/vault-style AA that forwards a cut of every withdrawal to a secondary fee/reward AA can inadvertently (or a griefer can deliberately, by draining/starving the fee AA of the asset it needs to pay out) cause **all** withdrawals routed through that primary AA to bounce indefinitely — a fund freezing condition for every user of that AA, not just one.

### Likelihood Explanation
Likelihood is real but conditional on AA design: it requires a primary AA to route part of its response payment to another AA address as part of core withdrawal/settlement logic (a common and encouraged composability pattern in Oscript). Any trigger sender can also externally influence when this triggers by controlling the timing/balance state of the dependent secondary AA (e.g., repeatedly draining an asset that the secondary AA needs to forward), making exploitation straightforward once such a composed AA pair exists.

### Recommendation
Document explicitly (and consider providing oscript primitives for) "fire-and-forget" payments to other AAs so that a downstream AA's bounce does not force a `revert()` of the entire upstream call chain — e.g., an opt-in mode where failure of a secondary trigger is recorded/ignored rather than propagated as a `revert` of the primary AA's already-committed state. AA authors composing multi-AA fund flows should avoid making core user-facing operations (withdraw/unwrap) depend on the success of a downstream AA whose balance they do not fully control, and should structure withdrawal-critical payments as the *last*, independently-bounceable message rather than one whose failure cascades via `revert()`.

### Proof of Concept
1. Deploy `Vault AA` whose withdraw logic, upon a valid request, sends the user's collateral back to them and forwards a small fee output to `FeeAA` (a secondary AA) in the same response unit.
2. `FeeAA`'s own logic pays out an accumulated reward in some asset it does not fully control the supply of (e.g., an asset issued/funded by a third party), analogous to the master-chef reward token.
3. Once `FeeAA`'s balance of that asset is insufficient, any trigger to `FeeAA` bounces, e.g., via `bounce("not enough balance in asset")` paths shown in `sendDummyUnit`/`sendUnit` [6](#0-5) .
4. Because `Vault AA`'s payment to `FeeAA` triggers `handleSecondaryTriggers`, `FeeAA`'s bounce propagates to `revert()` on `Vault AA`'s entire trigger [4](#0-3) , undoing the user's withdrawal and re-bouncing the trigger.
5. As long as `FeeAA` remains unable to pay its obligation, every subsequent withdrawal attempt through `Vault AA` fails identically — permanent freezing of all users' collateral in `Vault AA`, mirroring the reported LP unwrap/decollateralize freeze.

### Citations

**File:** aa_composer.js (L977-991)
```javascript
			if (trigger_opts.assocBalances[address].base < 0)
				return bounce("not enough balance in base");
			let arrAssetsWithNegativeBalances = [];
			for (let asset in trigger_opts.assocBalances[address])
				if (asset !== 'base' && trigger_opts.assocBalances[address][asset] < 0)
					arrAssetsWithNegativeBalances.push(asset);
			async.eachSeries(
				arrAssetsWithNegativeBalances,
				function (asset, cb) {
					storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
						if (err)
							return cb(err);
						if (objAsset.issued_by_definer_only && address !== objAsset.definer_address)
							return cb("not enough balance in " + asset); // and we are not the issuer
						cb();
```

**File:** aa_composer.js (L1702-1721)
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
```

**File:** aa_composer.js (L1743-1757)
```javascript
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

**File:** test/aa_composer.test.js (L156-252)
```javascript
test.cb.serial('chain of AAs', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 40000 }, data: { x: 333 }, address: trigger_address };

	var secondary_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.initial_address}", amount: "{trigger.output[[asset=base]] - 2000}"}
					]
				}
			},
			{
				app: 'state',
				state: `{
					var['who'] = trigger.address || timestamp;
					var['initial'] = trigger.initial_address || timestamp;
					var['initial_unit'] = trigger.initial_unit;
					var['large_num2'] = var[trigger.address]['large_num'] + 1;
					var['long_num2'] = var[trigger.address]['long_num'] + 1;
					var['number_of_responses'] = number_of_responses;
					var['previous_aa_responses_trigger_address'] = previous_aa_responses[0].trigger_address;
					var['previous_aa_responses_unit'] = previous_aa_responses[0].unit_obj.unit;
				}`
			}
		]
	}];
	var secondary_address = objectHash.getChash160(secondary_aa);
	addAA(secondary_aa);

	var primary_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: secondary_address, amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
			{
				app: 'state',
				state: `{
					var['who'] = trigger.address || timestamp;
					var['initial'] = trigger.initial_address || timestamp;
					var['large_num'] = 1e15;
					var['long_num'] = 0.000678901234567;
				}`
			}
		]
	}];
	var primary_address = objectHash.getChash160(primary_aa);
	addAA(primary_aa);
	
	aa_composer.dryRunPrimaryAATrigger(trigger, primary_address, primary_aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 2);
		t.deepEqual(arrResponses[0].aa_address, primary_address);
		t.deepEqual(arrResponses[0].bounced, false);
		t.deepEqual(arrResponses[0].response.error, undefined);
		t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === secondary_address); }).amount, 39000);
		t.deepEqual(arrResponses[0].updatedStateVars[primary_address], {
			who: { value: trigger_address + arrResponses[0].objResponseUnit.timestamp },
			initial: { value: trigger_address + arrResponses[0].objResponseUnit.timestamp },
			large_num: { value: 1e15 },
			long_num: { value: 0.000678901234567 },
		});
		t.deepEqual(arrResponses[0].updatedStateVars[secondary_address], {
			who: { value: primary_address + arrResponses[1].objResponseUnit.timestamp },
			initial: { value: trigger_address + arrResponses[1].objResponseUnit.timestamp },
			initial_unit: { value: arrResponses[0].trigger_unit },
			number_of_responses: { value: 1 },
			previous_aa_responses_trigger_address: { value: trigger_address },
			previous_aa_responses_unit: { value: arrResponses[0].response_unit },
			large_num2: { value: 1e15 }, // the same due to loss of precision
			long_num2: { value: 1.00067890123457 }, // rounded to 15 significant digits (but uses cached vars)
		});
		
		t.deepEqual(arrResponses[1].aa_address, secondary_address);
		t.deepEqual(arrResponses[1].bounced, false);
		t.deepEqual(arrResponses[1].response.error, undefined);
		t.deepEqual(arrResponses[1].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger_address); }).amount, 37000);
		t.deepEqual(arrResponses[1].updatedStateVars, undefined);
		
		t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
		t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
		t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
		t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
		t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
		t.end();
	});
});
```
