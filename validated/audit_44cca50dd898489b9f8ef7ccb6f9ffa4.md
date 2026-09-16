### Title
Uncaught `throw Error()` reachable from attacker-controlled payment input during unit validation causes full node crash (DoS) - ([File: validation.js])

### Summary
CVE-2018-2703 describes a low-privileged, network-reachable MySQL Server DoS where crafted input to a privilege-related code path causes the server process to hang or crash. The analog in ocore is that `network.js` installs a global `process.on('uncaughtException', ...)` handler that deliberately re-throws (`throw err;`) to crash the whole node process whenever *any* uncaught exception occurs anywhere in the event loop [1](#0-0) . Several validation code paths that process attacker-supplied unit content use `throw Error(...)` inside asynchronous callbacks instead of returning an error to the `callback`, meaning a single crafted unit (postable by any unprivileged unit poster) can trigger an uncaught exception and crash the node.

### Finding Description
`validatePaymentInputsAndOutputs` handles `headers_commission` and `witnessing` input types, which are attacker-selectable via the `type` field on a payment input [2](#0-1) . The attacker fully controls `input.from_main_chain_index` / `input.to_main_chain_index` (bounded only by simple integer/range checks earlier in the same function). These are passed to `mc_outputs.calcEarnings` / `paid_witnessing.calcWitnessEarnings`, and if those helper functions invoke their `ifError` callback, the code does not propagate the error through `callback(err)` — instead it does:

```
ifError: function(err){
    throw Error(err);
},
``` [3](#0-2) 

This `throw` happens inside a DB-query callback (`conn.query(...)` / async chain), i.e. outside of any surrounding `try/catch` in the `validate()` call stack, and outside of the mutex-protected `async.series` error-handling path that normally forwards `err` to `callbacks.ifUnitError`/`ifJointError` [4](#0-3) . Because this throw occurs asynchronously (inside a DB callback), it is not caught by any synchronous `try/catch` and bubbles up to the Node.js event loop, firing the global `uncaughtException` handler in `network.js`, which explicitly re-throws to crash the process "to avoid ending up in an inconsistent state" [1](#0-0) .

Similar unguarded `throw Error(...)` statements exist throughout `validation.js` (36 occurrences) and `aa_composer.js` (e.g. `getTrigger` throwing `"no outputs to " + receiving_address"` when a trigger has no matching payment output) [5](#0-4) , and in `formula/evaluation.js` (`readAADefinition`/`readBaseAADefinitionAndParams` callbacks throwing on unexpected DB states) [6](#0-5) . Each is a candidate for the same crash class: attacker-reachable code path that, on an edge condition presumed by developers to be "impossible" or "should never happen," throws synchronously inside an async callback rather than returning a normal validation error — turning a bad/malformed unit into a full-node crash instead of a rejected unit.

Note: I was not able to fully confirm, within the available tool budget, the exact internal error conditions of `mc_outputs.calcEarnings` and `paid_witnessing.calcWitnessEarnings` (i.e., which precise attacker-controlled `from_main_chain_index`/`to_main_chain_index` combinations reach their `ifError` branch) because the file contents for `mc_outputs.js` and `paid_witnessing.js` were not retrievable within the remaining iterations. This should be verified directly against those files before treating the PoC below as proven; a Devin session with full repo access would be needed to confirm the exact triggering condition.

### Impact Explanation
If a crafted, otherwise-well-formed unit can drive `calcEarnings`/`calcWitnessEarnings` (or any of the other unguarded `throw Error` sites reachable from unit/AA-trigger validation) into their error branch, any full node that receives and validates that unit crashes via the `uncaughtException` handler. Since this occurs during ordinary `validate()` processing of a broadcast/posted unit, an unprivileged attacker who can post a unit or trigger an AA could repeatedly crash any full node that processes it — a network-wide, repeatable denial of service matching CVE-2018-2703's "hang or frequently repeatable crash (complete DOS)" characterization, without requiring any special privilege beyond normal unit posting.

### Likelihood Explanation
Moderate-to-high if a concrete triggering input exists: the input types (`headers_commission`, `witnessing`) and their MCI range fields are fully attacker-controlled in a payment message, and no privileged position (peer/hub/node) is required — only the ability to post a unit, which is the baseline capability of any wallet user. The main uncertainty is whether the specific arithmetic/range conditions inside `calcEarnings`/`calcWitnessEarnings` can actually be forced into their `ifError` branch by an external attacker (vs. being truly unreachable invariants); this needs direct code confirmation.

### Recommendation
- Replace all `throw Error(err)` / `throw Error(...)` calls inside asynchronous DB-callback paths reachable from unit/AA validation (`validation.js`, `aa_composer.js`, `formula/evaluation.js`) with proper propagation of the error to the enclosing `callback`/`cb`, so malformed units are rejected as unit/joint errors rather than crashing the process.
- Audit `mc_outputs.calcEarnings` and `paid_witnessing.calcWitnessEarnings` to determine whether attacker-controlled `from_main_chain_index`/`to_main_chain_index` values can reach the `ifError` branch, and fix the corresponding call sites in `validation.js` (lines 2589–2599) accordingly.
- Consider hardening the global `uncaughtException` handler in `network.js` (lines 4530–4543) so that validation-related exceptions originating from untrusted unit content are converted into rejected units instead of a full process crash, reserving the crash-on-uncaught-exception behavior for genuine unrecoverable internal-state corruption.

### Proof of Concept
Not fully constructible without confirming the exact error condition inside `mc_outputs.calcEarnings` / `paid_witnessing.calcWitnessEarnings`. Conceptually: craft a unit whose payment message includes an input of `type: "headers_commission"` or `type: "witnessing"` with an `address`, `from_main_chain_index`, and `to_main_chain_index` combination that causes the corresponding earnings-calculation helper to invoke its `ifError` callback (e.g., an internally inconsistent MCI range that the helper doesn't expect from otherwise-valid-looking input); post/broadcast this unit to a full node. On validation, `validation.js`'s `ifError: function(err){ throw Error(err); }` (lines 2591/2598 region) throws inside the async DB-callback stack, escapes to `process.on('uncaughtException', ...)` in `network.js` (lines 4530–4543), and crashes the node.

### Citations

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

**File:** validation.js (L445-472)
```javascript
			function(err){
				if(err){
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('failed validation', consumed_time);
						console.log(objUnit.unit+" validation "+JSON.stringify(err)+" took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						unlock();
						if (typeof err === "object"){
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.bRequestPrunedContent);
							else if (err.error_code === "need_hash_tree") // need to download hash tree to catch up
								callbacks.ifNeedHashTree();
							else if (err.error_code === "invalid_joint") // ball found in hash tree but with another unit
								callbacks.ifJointError(err.message);
							else if (err.error_code === "transient")
								callbacks.ifTransientError(err.message);
							else
								throw Error("unknown error code");
						}
						else
							callbacks.ifUnitError(err);
					});
```

**File:** validation.js (L2574-2601)
```javascript
					doubleSpendWhere = "type=? AND from_main_chain_index=? AND address=? AND asset IS NULL";
					doubleSpendVars = [type, input.from_main_chain_index, address];
					if (conf.storage == "mysql")
						doubleSpendIndexMySQL = " USE INDEX (byIndexAddress) ";

					mc_outputs.readNextSpendableMcIndex(conn, type, address, objValidationState.arrConflictingUnits, function(next_spendable_mc_index){
						if (input.from_main_chain_index < next_spendable_mc_index)
							return cb(type + " ranges must not overlap"); // gaps allowed, in case a unit becomes bad due to another address being nonserial
						var max_mci = (type === "headers_commission") 
							? headers_commission.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci)
							: paid_witnessing.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci);
						if (input.to_main_chain_index > max_mci)
							return cb(type+" to_main_chain_index is too large");

						var calcFunc = (type === "headers_commission") ? mc_outputs.calcEarnings : paid_witnessing.calcWitnessEarnings;
						calcFunc(conn, type, input.from_main_chain_index, input.to_main_chain_index, address, {
							ifError: function(err){
								throw Error(err);
							},
							ifOk: function(commission){
								if (commission === 0)
									return cb("zero "+type+" commission");
								total_input += commission;
								checkInputDoubleSpend(cb);
							}
						});
					});
					break;
```

**File:** aa_composer.js (L394-397)
```javascript
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** formula/evaluation.js (L3305-3309)
```javascript
	// no need to cloneDeep, we need to rewrite only storage size, assocBalances cache can be updated by reference
	let objGetterValidationState = _.clone(objValidationState);
	storage.readBaseAADefinitionAndParams(conn, aa_address, objValidationState.last_ball_mci, function (arrBaseDefinition, params, storage_size) {
		if (!arrBaseDefinition)
			return cb("remote AA not found: " + aa_address);
```
