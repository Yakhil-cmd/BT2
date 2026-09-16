### Title
Single malicious secondary-AA recipient can revert an entire multi-recipient AA payout, freezing funds intended for all other recipients - ([File: aa_composer.js])

### Summary
When an AA's response sends payments to multiple output addresses in one unit, each recipient address that is itself an AA is triggered as a "secondary trigger." If any one of these secondary AAs bounces, the entire chain — including the primary trigger's already-computed, otherwise-successful response and any previously executed sibling secondary triggers — is rolled back via a savepoint rollback. This mirrors the reported "rogue token blocks all claims" bug class: one attacker-controlled element inside a batch/loop can unconditionally invalidate the whole atomic operation for every other, legitimate participant.

### Finding Description
`handleSecondaryTriggers` collects every output address of a just-produced AA response unit that is itself registered as an AA, and re-invokes `handleTrigger` for each of them as a secondary trigger: [1](#0-0) 

If any secondary trigger bounces, `async.eachSeries` propagates the error and, for a primary (non-secondary) context, calls `revert()` rather than just failing that one branch: [2](#0-1) 

`revert()` unwinds the *entire* trigger-processing cascade back to `SAVEPOINT initial_balances`, discards all buffered state-var updates, and clears every response accumulated so far (`arrResponses.splice(0, arrResponses.length)`), i.e. all payouts to *other, honest* recipients in the same primary trigger are wiped out along with the offending one: [3](#0-2) 

Crucially, the bounce-fee protection that normally makes bouncing costly for the sender is explicitly **not** enforced for secondary triggers: [4](#0-3) 

Since AA addresses are permissionless and fully determined by `chash160(definition)`, any user can pre-register a trivial "always bounce" AA definition at an address they control, and simply ensure that address is one of many recipients in a payout message produced by another AA (e.g., a dividend/royalty distributor, referral-tree payout, lottery/airdrop AA, or any AA that fans out a single response unit to a list of addresses supplied via state vars, triggers, or a data feed). Because the check for sufficient bounce-fee funding is skipped for secondary triggers, the malicious AA can force a bounce essentially for free, regardless of how small a share it was due to receive.

### Impact Explanation
This lets an unprivileged attacker who is (or gets themselves added as) one recipient among many in a single AA payout unit unconditionally block the payout to *every other* recipient in that same unit, and roll back any state changes and sibling AA calls already computed in that trigger cascade — an AA fund-freezing/denial-of-payout condition analogous to the "rogue token disables all claims" issue, mapped onto ocore's secondary-trigger/rollback mechanism instead of ERC-20 `transfer()`.

### Likelihood Explanation
Any address can become an AA merely by posting a valid AA definition matching `chash160(definition)`; no special privilege, cost, or minimum funding is required, and the bounce-fee requirement is explicitly bypassed for secondary triggers. Any real-world AA that pays multiple, at least partly attacker-influenceable, addresses in one response unit (referral rewards, dividend distribution, batch airdrops, "send to list" patterns) is exposed. This requires no cooperation from the DAG operators/witnesses and is reachable purely by posting ordinary units/definitions.

### Recommendation
- Do not roll back the entire primary response cascade when a secondary trigger bounces; instead, let the bounced secondary AA's own payment revert to itself only (already the per-AA local semantics), while allowing sibling secondary triggers and the primary response to still commit.
- Alternatively, require secondary triggers to also satisfy minimum bounce-fee coverage (removing the current exemption at `aa_composer.js:1850-1863`) so that griefing at least costs the attacker resources proportional to spam potential.
- Consider isolating balance/state changes per secondary-trigger branch (partial commit / per-branch savepoints) instead of one global `ROLLBACK TO SAVEPOINT initial_balances` that discards unrelated, already-valid branches.

### Proof of Concept
1. Attacker computes an AA definition `D = ['autonomous agent', { messages: [{app:'state', state:"{bounce('nope');}"}] }]` (or any definition guaranteed to error/bounce), derives `addr_evil = chash160(D)`, and posts it as the AA definition for `addr_evil`.
2. Attacker interacts with a target AA `Payout` in a way that legitimately entitles them to a share of a batch payout alongside other honest users (e.g., joins a referral list, buys a lottery ticket, becomes a dividend-eligible token holder) using `addr_evil` as their receiving address.
3. When `Payout` executes and sends one response unit with payment outputs to `addr_evil` and to several honest addresses, `handleSecondaryTriggers` (aa_composer.js:1702-1757) triggers `addr_evil` as a secondary AA.
4. `addr_evil`'s definition unconditionally bounces; per aa_composer.js:1850-1863 no bounce-fee minimum is enforced for secondary triggers, so the attacker need not even fund a meaningful amount.
5. The bounce propagates to `handleSecondaryTriggers`'s `async.eachSeries` callback (aa_composer.js:1743-1750), which calls `revert()` (aa_composer.js:1759-1783), rolling back to `SAVEPOINT initial_balances` and discarding the entire `Payout` response, including outputs that were destined for the honest recipients — repeatable on every execution of `Payout` that includes `addr_evil` in its recipient set.

### Citations

**File:** aa_composer.js (L1720-1741)
```javascript
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

**File:** aa_composer.js (L1850-1863)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
```
