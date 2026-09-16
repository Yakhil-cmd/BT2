I have enough evidence to construct the analog now.

### Title
Malicious secondary AA can permanently revert a distributor AA's payout, freezing funds owed to all other legitimate recipients - (File: `aa_composer.js`)

### Summary
Ocore's Autonomous Agent (AA) engine uses the same push-strategy that the NextGen `claimAuction()` finding condemns: when a primary AA sends a single response unit containing payment outputs to several addresses (e.g., a distributor/auction/dividend AA paying multiple bidders/participants at once), any output address that happens to be another registered AA is automatically re-triggered as a "secondary trigger". If that secondary AA bounces (reverts), the entire primary response — including all outputs to every other, unrelated recipient — is rolled back via `revert()`. Because a secondary AA's bounce condition is entirely under the control of whoever defines it, an attacker who gets themselves included as one of many payees (e.g., as a bidder, staker, or vault participant) can deploy an AA address that always bounces, permanently blocking the shared payout unit and locking funds meant for every other honest participant.

### Finding Description
When a primary AA computes its response `messages` and calls `sendUnit()`, all payment outputs are combined into one response unit (see the output collection in `sendUnit()` [1](#0-0) ). After the unit is validated and saved, `handleSecondaryTriggers()` looks at every distinct output address and, for any address that is itself a defined AA, re-invokes `handleTrigger()` on it as a secondary trigger [2](#0-1) .

The result of the secondary triggers is aggregated with `async.eachSeries`; the very first secondary AA that "bounces" (returns an error) aborts the whole batch:

```js
function (err) {
    if (err) {
        // revert
        if (bSecondary)
            return bounce(err);
        return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
    }
    ...
}
``` [3](#0-2) 

`revert()` then rolls back *the entire primary response unit* — not just the malicious recipient's share — using `revertResponsesInCaches()` and `ROLLBACK TO SAVEPOINT initial_balances`, clears all state var changes, and finally bounces the whole trigger back to its original sender: [4](#0-3) 

Because bouncing an AA is a normal, permissionless feature (any AA definition can contain a formula path that unconditionally calls `bounce(...)`), an attacker only needs to:
1. Register/deploy an AA address whose definition always bounces (e.g. `bounce("dos")` on every trigger).
2. Get that address included as one of the outputs of a distributor AA's response — e.g., by "bidding"/"participating" using that AA address instead of a normal wallet address, exactly as the NextGen PoC describes bidding 1 wei from a hostile contract.

Every time the distributor AA tries to pay out all participants in one unit, the malicious AA's secondary trigger bounces, `revert()` fires, and the whole payout (to the legitimate participants too) never completes. Since state changes are rolled back on each attempt, the AA's owner/operator cannot simply "try again" with the same participant list — the same malicious address will always cause the same result, indefinitely freezing the funds intended for all honest counterparties in that batch.

This is a direct structural analog of the NextGen `claimAuction()` push-loop bug: a single hostile payee embedded among many legitimate payees in one atomic settlement operation can unconditionally and repeatedly block the whole operation, rather than only affecting their own share.

### Impact Explanation
Any oscript AA pattern that distributes funds/assets to multiple addresses discovered/recorded at trigger time (auctions, lotteries, dividend/staking payouts, escrow refunds, "claim" style AAs modeled on the referenced Solidity contract) is vulnerable to unconditional, repeatable DoS and AA fund freezing if any one of the recipient addresses is attacker-controlled AA logic. This breaks the same invariant flagged in the original report — that all legitimate participants should be able to receive their funds — mapped onto ocore's AA fund-loss/freezing class, since the payout can never succeed while the malicious payee is present.

### Likelihood Explanation
Reaching this path only requires being an unprivileged AA/trigger participant: posting an AA definition is permissionless, and getting one's own (AA) address included among the outputs of a shared distributor is the normal mechanism by which such contracts pay their participants (mirroring how a NextGen bidder simply calls the public bid function). No special privileges, node cooperation, or network-level assumptions are needed.

### Recommendation
Avoid designing/relying on AA patterns that bundle payouts to multiple, attacker-influenceable recipients into a single response unit whose success is coupled to every recipient's (secondary-trigger) success. Where possible:
- Use a pull-style claim pattern in oscript (separate trigger per recipient) instead of a single fan-out payment message, so one recipient's AA misbehavior cannot block others' funds.
- Consider that `handleSecondaryTriggers()`'s all-or-nothing semantics — one bounced secondary trigger reverting the *entire* primary response — is a systemic hazard for any multi-recipient AA design, and this should be documented/guarded against for AA authors, e.g. by allowing a mode where failed secondary triggers are isolated/skipped rather than causing full reversion of unrelated outputs.

### Proof of Concept
1. Attacker deploys AA `M` whose definition unconditionally executes `bounce("dos")` for every trigger.
2. Attacker "participates" (bids/stakes/deposits) in a distributor AA `D` using address `M` as their claim/payout address, alongside honest participants A, B, C.
3. When `D` is triggered to settle/payout (e.g., auction end, dividend distribution), it builds one response unit with payment outputs to `M`, A, B, C via `sendUnit()` [5](#0-4) .
4. `handleSecondaryTriggers()` discovers `M` is a registered AA and triggers it as a secondary trigger [6](#0-5) .
5. `M` bounces unconditionally, `async.eachSeries`'s final callback receives `err`, and since this is the primary trigger, `revert()` is invoked [7](#0-6) .
6. `revert()` rolls back the state and response for the *entire* unit, so A, B, and C never receive their expected payouts either [4](#0-3) .
7. Repeating any subsequent trigger of `D` with the same participant list reproduces the same bounce/revert every time, permanently freezing the funds owed to A, B, and C as long as `M` remains among the outputs.

### Citations

**File:** aa_composer.js (L1043-1046)
```javascript
	async function sendUnit(messages) {
		if (trigger_opts.bAir)
			return sendDummyUnit(messages);
		console.log('send unit with messages', util.inspect(messages, { depth: 6 }));
```

**File:** aa_composer.js (L1290-1296)
```javascript
		var arrOutputAddresses = [];
		const addOutputAddresses = (outputs) => {
			outputs.forEach(function (output) {
				if (output.address !== address && arrOutputAddresses.indexOf(output.address) === -1)
					arrOutputAddresses.push(output.address);
			});
		};
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

**File:** aa_composer.js (L1743-1750)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
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
