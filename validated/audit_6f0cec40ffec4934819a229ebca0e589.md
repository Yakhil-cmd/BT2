## Title
Honey-pot secondary AA can force a full revert of another AA's response - (File: `aa_composer.js`)

### Summary
The Curves bug works because a fee/payment destination that is *set by an untrusted party* is called unconditionally inside a shared, atomic operation, and if that call reverts, the whole operation (including the unrelated legitimate user's action) reverts. The same structural weakness exists in ocore's AA (Autonomous Agent) engine: when an AA sends a payment to another address that happens to be an AA, that AA is automatically invoked as a **secondary trigger**, and if the secondary AA bounces, the **entire primary trigger's response is rolled back and re-bounced**, even though the primary AA's own logic succeeded. An attacker who controls (or gets named as) the receiving AA can make it bounce selectively (e.g., depending on trigger data, sender address, or state), turning it into a "honeypot" that always accepts funds flowing one way but reliably reverts any operation that would forward funds/behavior back through it, freezing legitimate users' AA interactions exactly like the `referralFeeDestination` honeypot froze sells.

### Finding Description
When an AA (the "primary" AA) sends a payment message whose output address is itself an AA address, `handleSecondaryTriggers` automatically re-invokes `handleTrigger` on that address as a secondary trigger: [1](#0-0) 

If any secondary AA in the chain bounces, the error is bubbled up and, for the primary (non-secondary) trigger, `revert()` is called: [2](#0-1) 

`revert()` rolls back the database to `SAVEPOINT initial_balances`, discards all accumulated responses/state changes, and then calls `bounce()`: [3](#0-2) 

`bounce()` refunds the *original trigger sender* only the bytes minus a bounce fee, discarding any state changes and any other payment outputs the primary AA intended to send: [4](#0-3) 

This means: any legitimate AA (e.g. a router, marketplace, DEX, or any AA that forwards funds/calls to an address supplied or influenced by a counterparty, similar in spirit to `setReferralFeeDestination` in the Curves report) that ends up sending funds to a malicious AA can have **all of its successful, otherwise-valid logic undone** purely because the malicious AA chooses to bounce. Just like the `CurveSubject` creator who can update `referralFeeDestination` to a contract that always reverts on "sell" flows but not "buy" flows, an attacker who controls the target AA can make it bounce selectively (based on trigger data, direction of the flow, sender, or accumulated state) so that legitimate counter-party operations always fail while the attacker's own preferred paths succeed.

### Impact Explanation
This is a direct AA-level analog of the "HoneyPot" pattern: unauthorized, one-sided denial-of-service against any AA logic that chains into an attacker-influenceable secondary AA. The victim AA's other users lose the bounce fee on every failed attempt and can never complete the intended action, while the same mechanism can be exploited to extract value asymmetrically (funds flow to the attacker's AA freely, but any path that would return value or complete a swap/settlement back through it can be selectively reverted). This matches the "AA fund loss or freezing" category, since legitimate AA responses (including their state changes and payment outputs) are wholly discarded whenever the attacker-controlled secondary AA decides to bounce.

### Likelihood Explanation
Any AA design that composes with a counterparty-influenceable AA address (e.g., liquidity pools, DEX routers, marketplaces, or any AA pattern where a "destination" or "partner" AA address is configurable per-request, mirroring `referralFeeDestination` in Curves) is exposed. Since chaining to secondary AAs and bouncing is a normal, permitted primitive with no restriction on who can author the receiving AA or make it discriminate on trigger conditions, an attacker can trivially deploy such a contract and either register/propose it as a legitimate counterpart AA or otherwise get referenced by a target AA's logic.

### Recommendation
- Avoid unconditionally cascading failures of secondary/chained AA triggers into a full `revert()` of the primary trigger's already-valid state changes and outputs; consider isolating failures of externally-influenceable secondary AAs so they do not retroactively undo the primary AA's own successful logic.
- For AA authors: never let externally-supplied (attacker/counterparty-controlled) addresses become the direct target of a synchronous secondary-trigger payment when the primary AA's own success should not depend on that party's cooperation; instead use a pull-based/withdraw pattern (analogous to using a balance-based, non-reverting mechanism rather than push+`.call`) so that a hostile counterpart cannot force a rollback of unrelated logic.
- Document/flag this AA-chaining bounce-propagation behavior clearly so template authors don't compose with untrusted counterpart AA addresses in code paths where failure must not be able to unwind previously valid effects.

### Proof of Concept
1. Deploy AA `Trap` whose logic bounces (e.g. via an explicit `bounce(...)` oscript call) whenever `trigger.data.mode == 'return'` (or based on `trigger.address`), but otherwise accepts and forwards funds normally.
2. Deploy/represent AA `Router` (the "victim" logic, analogous to the Curves contract) that performs its own valid state changes and then sends part of the trigger's payment to `Trap` as part of a "return"/"settlement" flow, using `handleSecondaryTriggers`'s automatic secondary-trigger dispatch: [5](#0-4) .
3. A user's trigger to `Router` that should succeed (e.g., trying to "exit"/"sell"/"settle" via `Trap`) always gets fully reverted because `Trap` bounces, forcing `revert()` at `Router`'s primary trigger level: [2](#0-1) , wiping out `Router`'s own valid state changes and refunding only bytes minus the bounce fee: [4](#0-3) .
4. Meanwhile, triggers that don't require going through the "return" path via `Trap` (e.g., "buy"/"deposit") succeed normally, reproducing the buy-succeeds/sell-always-reverts honeypot asymmetry from the original report.

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

**File:** aa_composer.js (L1702-1741)
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
