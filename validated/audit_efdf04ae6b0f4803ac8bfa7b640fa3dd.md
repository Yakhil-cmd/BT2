### Title
One secondary AA (child trigger) bounce rolls back all sibling AA responses cascading from a single primary trigger - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `handleSecondaryTriggers()` iterates over every AA address that received an output from an AA response and fires a child (secondary) trigger for each one with `async.eachSeries`. If any one of these independent secondary AA calls bounces, the entire chain — including all previously-successful sibling AA responses in the same batch — is unwound via `revert()`, exactly the "one plugin fails, blocks/reverts everyone else" pattern described in the external report.

### Finding Description
When a primary AA trigger produces a response unit with payments to multiple recipient addresses that are themselves AAs, `handleSecondaryTriggers()` fetches all of them and processes them one at a time: [1](#0-0) 

Each secondary AA is executed via a recursive call to `handleTrigger()` with `bSecondary = true`. Crucially, the loop is `async.eachSeries`, so AA #1, AA #2, AA #3 (analogous to "plugin 1/2/3" in the report) are executed sequentially, and each one's balance/state changes and response unit are added to the shared `arrResponses`, `batch` (KV store), and `conn` (SQL transaction) as it completes.

If any single secondary AA in the list bounces (fails its business logic, insufficient balance, formula error, etc.), the `eachSeries` final callback receives that error and calls: [2](#0-1) 

This invokes `revert()`, which unconditionally rolls back the *entire* batch of responses accumulated so far — not just the failing AA's own changes: [3](#0-2) 

`revert()` calls `revertResponsesInCaches(arrResponses)` (removing all response units, including ones from AAs that succeeded independently), clears all `stateVars`, clears the KV `batch`, and issues `ROLLBACK TO SAVEPOINT initial_balances`, undoing every successful sibling AA's state and balance changes, then calls `bounce(err)` on the *primary* trigger, converting the whole multi-AA distribution into a single bounce response to the original trigger address.

This mirrors the reported Vault.sol pattern precisely: multiple independent "plugins" (here, independent secondary AAs) are processed in a loop; the loop has no fault isolation; one failure discards the successful work of all the others and reverts the aggregate operation.

### Impact Explanation
Any primary AA whose business logic fans out payments to several other AA addresses (a common "router"/"distributor" AA pattern) is exposed: if just one of the downstream AAs is temporarily or permanently unable to process its share (insufficient bounce fee, a formula error triggered by adversarial trigger data, a state precondition not met, balance overflow, etc.), the entire batch of otherwise-valid downstream AA executions is discarded and the whole transaction is converted into a bounce. This can:
- Freeze/lose expected funds for AAs and their users that would have received a valid payment/response had they been processed independently.
- Allow a single misbehaving or attacker-influenced downstream AA to grief unrelated AAs that share a common upstream distributor, since the trigger sender (or downstream AA logic, if the routing is data-driven) can often influence which addresses/amounts are included in the fan-out.
- Cause repeated, deterministic denial-of-service against a distributor AA's downstream ecosystem: any consistently-failing recipient AA permanently blocks the distributor's payments to all its other (healthy) recipients, since every trigger repeats the same failure.

### Likelihood Explanation
This requires no special privilege — a normal unit poster triggers the primary AA (as designed), and the fan-out to multiple secondary AAs is a standard, supported and demonstrated pattern in ocore itself (chain-of-AAs tests). Any AA definition author (or an attacker who can influence which addresses/amounts a primary AA sends to multiple downstream AAs, e.g., via data-feed-driven or state-var-driven output lists) can reliably trigger this all-or-nothing rollback. The mechanism is deterministic (not a race condition or timing issue), so once a downstream AA has any failure condition, it reproduces on every subsequent trigger.

### Recommendation
Add fault isolation to `handleSecondaryTriggers()` so that a bounce from one secondary AA does not require unwinding the responses/state of unrelated sibling secondary AAs from the same batch:
- Either process each secondary trigger as its own independently committed sub-transaction (with its own savepoint) so a bounce only reverts that specific secondary AA's own state changes (letting that secondary AA's own bounce logic handle refunding its own trigger amount), or
- Explicitly document/require that fan-out distributor AAs must not depend on all downstream AAs succeeding atomically, and provide an AA-level primitive (e.g., an isolated "try/catch"-style dispatch) so AA authors can opt into isolated per-recipient execution instead of the current implicit whole-batch atomicity.

### Proof of Concept
1. Deploy a "distributor" AA `D` whose response messages send outputs to AA addresses `A`, `B`, and `C` (three independent "plugins").
2. Deploy `A` and `C` as always-succeeding AAs (e.g., simple bounce-back or state-update logic).
3. Deploy `B` as an AA that always bounces (e.g., it references a nonexistent state var/format that fails its formula, or it never has sufficient bounce fee margin for the amount it receives).
4. Send a unit that triggers `D`; `D`'s response unit pays `A`, `B`, and `C`.
5. Observe via `handleSecondaryTriggers()` (`aa_composer.js:1702-1757`): `A`'s secondary trigger executes and succeeds first (added to `arrResponses`/batch/conn), then `B`'s secondary trigger bounces, causing the `eachSeries` error branch to call `revert()` (`aa_composer.js:1743-1750`, `1759-1783`), which strips `A`'s already-successful response from `arrResponses`, rolls back its state/balance changes via `ROLLBACK TO SAVEPOINT initial_balances`, and converts the entire operation into a single bounce of `D`'s primary trigger — even though `A` and `C` (had it been reached) were fully capable of succeeding independently.

Note: I was unable to fully verify whether this specific cascading-revert behavior is treated by the Obyte protocol as an accepted/intended design tradeoff (for deterministic replay consistency) versus an unintended defect, since the wiki's AA-execution documentation does not explicitly discuss secondary-trigger fault isolation. This should be confirmed with the maintainers/protocol authors before treating it as a confirmed vulnerability rather than a documented design constraint.

### Citations

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
