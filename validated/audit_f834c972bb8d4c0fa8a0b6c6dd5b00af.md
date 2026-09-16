## Title
AA trigger response with multiple asset payments/secondary AA calls fully reverts if a single payment/secondary AA fails, blocking payouts to unrelated recipients - (File: `aa_composer.js`)

### Summary
`handleTrigger`'s `sendUnit()` builds an AA's response unit by iterating over all outgoing `payment` messages (potentially to several different addresses/assets) in a single `async.eachSeries` pass, and `handleSecondaryTriggers()` iterates over all AA addresses that received outputs from that response, invoking each as a secondary trigger in series. In both loops, a single failure anywhere in the iteration (one bad asset, or one secondary AA that bounces) causes the **entire** batch to be aborted via `bounce()`/`revert()`, discarding all other, otherwise-successful payments/state changes in the same response — exactly the "one bad item blocks the whole claim/loop" pattern described in the report.

### Finding Description
In `sendUnit()`, the code iterates all non-base payment messages and, for each asset, loads asset info and validates it: [1](#0-0) 
If any single asset in the batch is private (`objAsset.is_private`) or otherwise fails validation, the callback returns an error which is propagated to the `async.eachSeries` final callback: [2](#0-1) 
`bounce(err)` throws away the whole in-progress response unit — including any other payment messages to other addresses/assets that had already been successfully validated/merged in the same iteration — and refunds the trigger instead of delivering the valid payments.

The same anti-pattern exists in `handleSecondaryTriggers()`, where every AA address that received an output from the current response is called as a secondary trigger in series: [3](#0-2) 
If any one secondary AA in that list bounces, the primary trigger unconditionally calls `revert()` for the whole batch: [4](#0-3) 
`revert()` rolls back all state variables and cached responses accumulated so far (`ROLLBACK TO SAVEPOINT initial_balances`), i.e. it undoes the state changes and payouts that were already correctly delivered to the other (unrelated, non-bouncing) secondary AAs/recipients in the same trigger chain: [5](#0-4) 

This mirrors the reported bug class precisely: a loop that processes multiple independent recipients/assets, where the failure of one item (a blocked/reverting token in the original report; a private asset or a bouncing downstream AA here) prevents delivery to all the others, instead of isolating the failure to the offending item.

### Impact Explanation
Any AA that is designed to pay out multiple recipients/assets or to call multiple secondary AAs within one trigger execution can have its entire batch of payouts nullified because of a single problematic asset or a single misbehaving/bouncing downstream AA. This causes legitimate users who were correctly due funds in the same response to receive nothing, and any accompanying state updates (marking a claim as paid, updating balances, etc.) are rolled back along with it — an AA fund-freezing / denial-of-payment condition reachable by an ordinary AA trigger sender who can influence which assets/addresses are paid out (e.g., a router/distribution AA that lets the trigger controller specify assets or target addresses), or simply by the natural presence of a downstream AA that bounces for unrelated reasons.

### Likelihood Explanation
This requires an AA whose oscript logic sends multiple asset payments or triggers multiple secondary AAs in one response — a common pattern for routers, distributors, and multi-token AAs. No special privilege is needed: a normal trigger sender (or an attacker able to influence which asset/address is used in one of the outgoing payments) can cause the failure condition, and the cascading revert behavior in `aa_composer.js` is unconditional.

### Recommendation
Where an AA's design allows it, isolate per-recipient/per-asset failures so a single bad asset or a single bouncing secondary AA does not roll back unrelated, already-valid payments in the same response — e.g. by allowing partial success/i solating the erroring message rather than aborting the entire `sendUnit`/`handleSecondaryTriggers` batch. At minimum, this atomicity limitation should be clearly documented for AA authors so it can be defended against with "pull" style claim patterns instead of "push" batch payouts.

### Proof of Concept
1. Deploy an AA that, on a single trigger, builds a response unit paying out to several addresses/assets (or that forwards outputs to multiple other AA addresses in series).
2. Arrange for one of those payments to reference an asset that is `is_private`, or arrange for one of the downstream secondary AAs to bounce (e.g., due to its own validation logic).
3. Observe that `sendUnit`'s `async.eachSeries` callback receives an error and calls `bounce(err)` [2](#0-1) , or that `handleSecondaryTriggers` calls `revert()` [4](#0-3) , discarding all other payments/state changes that would otherwise have succeeded in the same trigger execution.

### Citations

**File:** aa_composer.js (L1323-1331)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
```

**File:** aa_composer.js (L1346-1348)
```javascript
			function (err) {
				if (err)
					return bounce(err);
```

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
