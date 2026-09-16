## Analysis

The reachable ocore analog to the NFTX `distribute()`/`feeReceiver` DoS is the way `handleTrigger` processes **secondary AA triggers** spawned from a single primary AA response in `aa_composer.js`.

### Title
Single malicious/buggy secondary AA can force revert of an entire AA trigger chain, denying funds/execution to all co-recipients - (File: `aa_composer.js`)

### Summary
When a primary AA's response sends payments to several addresses in one unit, and one or more of those addresses are also AAs, `handleTrigger` invokes each of them as a "secondary trigger" sequentially via `async.eachSeries`. If any single secondary AA bounces (fails), the whole trigger chain — including state changes and payments already computed for other, well-behaved recipient AAs — is unwound by `revert()`, exactly as one poorly-implemented `feeReceiver` broke `distribute()` for everyone in the NFTX report.

### Finding Description
`handleSecondaryTriggers` collects every output address of the response unit that is itself an AA and executes them one after another: [1](#0-0) 

If any of these child AA evaluations sets a bounce error, `async.eachSeries`'s final callback receives that error and calls `revert()` for the *entire* primary trigger, not just the failing branch: [2](#0-1) 

`revert()` rolls the whole batch back to the savepoint taken before the trigger started (undoing balance/state changes made by *all* secondary AAs processed so far, including successful ones) and then bounces the primary trigger: [3](#0-2) 

Because secondary AA definitions are frequently supplied or controlled by third parties (e.g., a distribution/marketplace AA that pays out to a list of externally-registered recipient AAs, similar to NFTX's user-registrable `feeReceiver`), a single recipient whose AA formula unconditionally calls `bounce(...)` (or hits any error condition, such as `evaluateAA` failure, `not enough balance`, or unsupported message app) can deterministically fail every trigger that tries to pay out to the full recipient set — see `bounce()` semantics for secondary triggers: [4](#0-3) 

### Impact Explanation
Because AA response processing is deterministic and re-executes identically for every future trigger, once one recipient AA is broken (accidentally, or deliberately registered/deployed as broken by an attacker), *every* subsequent trigger that fans out to that same set of secondary AAs will revert in full. This denies the funds/logic execution not only to the malicious/buggy AA but to every other legitimate co-recipient AA in the same distribution, and repeatedly consumes the trigger sender's bounce fees on each attempt. This matches the "high" severity rationale in the original report: one nefarious/buggy participant can deny funds/service to all other participants sharing the same distribution unit.

### Likelihood Explanation
This is reachable by any unprivileged actor who can get their own address included as a payout target of a primary AA that distributes to a dynamic/attacker-influenceable set of recipient AAs (e.g., referral, staking-reward, or marketplace-fee distributor AAs commonly built on top of ocore's Oscript). No special privileges are required beyond being one of the payees, which is directly analogous to registering a `feeReceiver` in the NFTX case.

### Recommendation
When fanning out to multiple secondary AA recipients from a single trigger, isolate failures per-recipient (e.g., catch/skip a bouncing secondary AA and continue processing the rest, refunding only its share) instead of unwinding the entire batch of secondary triggers via a single `revert()`. Alternatively, document this atomicity clearly and require AA authors who build multi-recipient distributors to isolate untrusted recipients into separate triggers/messages so that one broken recipient cannot block payouts to the others.

### Proof of Concept
1. Deploy AA `Distributor` whose response sends outputs in one unit to `GoodAA1`, `GoodAA2`, and `BadAA` (address supplied/registered by an attacker, e.g., via a state var writable by users).
2. Deploy `BadAA` whose formula always executes `bounce("fail")` regardless of input.
3. Post a trigger to `Distributor`. `handleSecondaryTriggers` (`aa_composer.js:1702`) processes `GoodAA1`, `GoodAA2`, then `BadAA` in series; `BadAA` bounces, and the `async.eachSeries` final callback at `aa_composer.js:1743-1749` calls `revert()`, undoing the entire trigger including the payments/state updates already made for `GoodAA1` and `GoodAA2`.
4. Every future trigger to `Distributor` that includes `BadAA` as a recipient will repeat this failure indefinitely, permanently denying `GoodAA1`/`GoodAA2` their funds while burning bounce fees from the trigger sender each time.

### Citations

**File:** aa_composer.js (L909-927)
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

**File:** aa_composer.js (L1743-1755)
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
