### Title
Malicious secondary AA can grief and revert an entire multi-party AA response chain, causing fund loss/freezing for unrelated recipients - (File: `aa_composer.js`)

### Summary
`handleTrigger()` in `aa_composer.js` processes an AA's response atomically, including any *secondary triggers* fired when the AA's response sends a payment to another address that also happens to be an AA. If any secondary AA in the resulting call chain bounces, the entire chain — including already-successful state changes and payouts to other, unrelated addresses reached earlier in the same chain — is rolled back via `revert()`. This mirrors the ERC777-hook griefing pattern in the Augur report: a value-transfer step that unconditionally invokes attacker-controlled code, whose failure can unexpectedly revert a shared, multi-party operation.

### Finding Description
When an AA's response contains a payment message whose output address is itself an AA, `handleSecondaryTriggers()` automatically triggers that address as a secondary AA within the same trigger-processing chain: [1](#0-0) 

If the secondary AA's evaluation ends in `bounce()`, the `async.eachSeries` callback receives an error, and because the failure did not originate at the top-level (`!bSecondary`), the code calls `revert()` instead of simply bouncing that one leg: [2](#0-1) 

`revert()` rolls the whole cascading chain back to a single savepoint taken once at the very start of the *primary* trigger's processing (`SAVEPOINT initial_balances`, created only when `!bSecondary`): [3](#0-2) 

`revert()` clears the write batch, discards *all* accumulated responses (`arrResponses.splice(0, arrResponses.length)`), and rolls the DB back to that savepoint before turning the whole thing into a single bounce: [4](#0-3) 

Because any address can later become an AA (by posting a `definition` message that is later referenced as `aa_addresses`), and `handleSecondaryTriggers` looks up whether a payout address is a currently-defined AA purely from the `aa_addresses`/`units` tables at trigger time, an attacker can:
1. Pre-register a malicious AA definition whose logic unconditionally calls `bounce(...)` whenever it receives funds.
2. Get that address included as one of many payout addresses processed within a single primary AA's response (e.g., a multi-user settlement/exchange/distribution AA that fans out payments to several previously-registered participant addresses in one trigger).
3. When the victim (unprivileged) primary AA later sends funds to that address as part of a larger, multi-recipient response, the secondary trigger to the attacker's AA bounces, and `revert()` unwinds the *entire* chain — undoing legitimate payouts and state updates intended for all the other, unrelated recipients processed earlier in the same chain, not just the malicious one.

This is structurally identical to the Augur bug class: a mandatory value-transfer step (`sellCompleteSets`/`burn` there, secondary-trigger dispatch here) unconditionally invokes code controlled by a single participant (`_sender` there, the payee AA here), and that participant can grief an operation whose outcome affects other, uninvolved parties.

### Impact Explanation
Any unprivileged party who can get an attacker-controlled address included as a payee in a shared/multi-party AA settlement (e.g., a pool, distributor, or matching-engine style AA that pays out to many previously known addresses within one trigger) can force the whole chain to bounce. This causes freezing/loss of the intended state changes and fund distributions for all other, unrelated recipients caught up in that same trigger chain — a concrete AA fund loss/freezing scenario reachable by an ordinary AA trigger sender or address registrant, not a privileged actor.

### Likelihood Explanation
Likelihood is moderate-to-high for AAs that are designed to pay out to multiple, previously-registered addresses within a single trigger response (common pattern for pools/distribution/matching AAs). The attacker only needs to register a simple always-bouncing AA at an address that will later be included as a payee — no special privileges, node compromise, or timing races are required, only ordinary unit posting and AA definition capabilities available to any user.

### Recommendation
Avoid letting failures in downstream/secondary AA legs unwind unrelated, already-successful legs of the same chain. Consider isolating each secondary-trigger branch with its own savepoint (rather than sharing a single top-level `initial_balances` savepoint across the whole cascading chain), so a bounce in one branch only reverts that branch's own effects instead of the entire multi-recipient operation. Alternatively, document and strongly discourage this pattern for AA authors, or provide a primitive to send payments to multiple addresses without back-propagating secondary bounce failures to the primary response's already-decided state.

### Proof of Concept
1. Deploy AA `M` whose `getters`/`init` unconditionally calls `bounce("grief")` on any incoming payment.
2. Deploy (or use an existing) distributor AA `D` designed to, on a single trigger, pay out to several registered participant addresses `P1, P2, ..., Pn` in one response, where one of the registered participants is address `M` (registered legitimately beforehand, e.g., as a normal user address that the attacker later redefines as AA `M` before `D`'s payout trigger executes — `aa_addresses` lookup only checks `mci<=?`, i.e., that the AA definition is stable by the time of the payout trigger).
3. Trigger `D`'s payout logic (e.g., a normal user calls the distribution function).
4. `handleSecondaryTriggers` fires a secondary trigger to `M` as part of the payout chain; `M` bounces.
5. Per `aa_composer.js:1743-1750`, since this occurs while `!bSecondary` at the top, `revert()` is invoked, rolling back to the single `SAVEPOINT initial_balances` (`aa_composer.js:528-529`) and discarding all of `D`'s state changes and the outputs intended for `P1...Pn`, even though those participants had no relation to `M`. [5](#0-4) [4](#0-3) [3](#0-2)

### Citations

**File:** aa_composer.js (L526-529)
```javascript
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
```

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

**File:** aa_composer.js (L1759-1798)
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
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```
