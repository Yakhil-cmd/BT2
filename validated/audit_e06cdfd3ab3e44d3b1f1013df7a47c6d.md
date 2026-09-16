### Title
Unhandled exception during dry-run cleanup of an AA trigger crashes the whole node process on receipt of a single crafted unit - ([File: network.js], [File: aa_composer.js])

### Summary
The Xen CVE describes a case where a failed cleanup operation on a crashed guest is mishandled, forcing a hypervisor-wide crash instead of a contained failure. The analogous pattern in `ocore` is in the AA "dry-run" cleanup path: `network.js` unconditionally `await`s `aa_composer.dryRunPrimaryAATrigger()` when a newly-posted unit funds an AA address, and any internal invariant failure inside the oscript/ojson evaluator (`formula/evaluation.js`) that is thrown as a raw `throw Error(...)` instead of being routed through the `setFatalError`/callback path escapes the dry-run's transaction cleanup, bubbles up as an unhandled exception, and hits the global `process.on('uncaughtException')` handler in `network.js`, which explicitly re-throws to crash the process.

### Finding Description
`network.js`'s `handleJoint` `ifOk` callback runs a mandatory pre-broadcast "dry run" for every newly posted, non-catchup unit that pays to an AA address, specifically so that "if it would crash, let it crash now, not when we execute the trigger for real": [1](#0-0) 

`dryRunPrimaryAATrigger` in `aa_composer.js` opens its own connection, `BEGIN`s a transaction, and calls `handleTrigger(...)`, expecting to reach `onDone` which does `revertResponsesInCaches`, `batch.clear()`, `ROLLBACK`, and `conn.release()`: [2](#0-1) 

The trigger's oscript/ojson formulas are evaluated inside `formula/evaluation.js`'s `evaluate()`, a deeply recursive, callback-based interpreter. Most invalid states are handled via `setFatalError()`, which safely routes the error back through the callback chain: [3](#0-2) 

However, numerous branches in the same evaluator use bare `throw Error(...)` for conditions the author believed "should never happen" (e.g. unknown field/op, object-typed `ifelse` test, unknown assignment op, unknown json type): [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

Because these `throw`s occur deep inside asynchronous `conn.query`/`async.eachSeries` callback frames (not inside the synchronous body of the `new Promise(...)` executor that wraps `dryRunPrimaryAATrigger`), they are **not** caught by that promise wrapper: [8](#0-7) 
They escape as a Node.js "uncaught exception" instead of rejecting the awaited promise in `network.js`, and the already-`BEGIN`'d dry-run connection is never `ROLLBACK`'d or released - i.e. exactly the "mishandling of failed operations during cleanup" pattern from the CVE.

The process-wide exception handler treats this the same way Xen's IOMMU cleanup bug did - it deliberately crashes the whole process rather than failing gracefully for the single offending unit: [9](#0-8) 

### Impact Explanation
Since `sqlite_pool.js`/`db.js` typically run a full node against a small, often single-connection SQLite pool, and the dry run always runs for *every* full node that receives the unit and has `conf.bDryRunNewTriggers` enabled, a single crafted unit that funds a carefully constructed AA address can crash every full node that processes it before broadcasting/relaying — a network-wide denial of service that prevents the network from confirming new units, matching the "network unable to confirm new units" impact bar. This is triggerable by an ordinary, unprivileged unit poster paying to an AA address they control, which is squarely within the allowed reachable surface (AA definitions and triggers, oscript/ojson evaluation).

### Likelihood Explanation
Reaching one of the internal `throw Error(...)` invariants requires crafting an AA definition/oscript formula and trigger data that pushes the evaluator into a state the author assumed impossible (e.g., an `ifelse` test evaluating to a wrapped object, a `json_parse` producing a type outside string/number/boolean/object, or an internal field lookup returning an unexpected value). Because oscript syntax and AA definitions are attacker-controlled and only lightly constrained by `formula/validation.js`'s static checks (which validate syntax/complexity, not all dynamic-value invariants), some of these "should never happen" branches may be reachable dynamically depending on runtime values (e.g. via getters, remote AA calls, or `map`/`filter`/`reduce` producing unexpected wrapped-object results). Precisely which throw is reachable from externally-controlled input requires deeper live analysis of the formula grammar and validator, which is not fully confirmed here — this is the main residual uncertainty.

### Recommendation
- Wrap the entire dry-run trigger evaluation (`dryRunPrimaryAATrigger`/`handleTrigger`/`formulaParser.evaluate`) call chain in defensive `try/catch`, and on any caught exception, force `ROLLBACK`/`conn.release()` and report a formula/validation error back to `network.js` instead of leaking an uncaught exception.
- Replace unconditioned/internal `throw Error(...)` invariant violations in `formula/evaluation.js` with `setFatalError(...)` calls, so that any dynamically-reachable "impossible" state fails the AA trigger gracefully instead of crashing the process.
- Ensure `network.js`'s `uncaughtException` handler does not need to be relied upon as the last line of defense for attacker-reachable AA/oscript evaluation paths, since AA definitions are fully attacker-controlled data.

### Proof of Concept
Conceptual PoC (exact grammar reachability not verified in this pass):
1. Publish an AA whose oscript, when triggered, causes one of the internal invariant branches in `formula/evaluation.js` to be hit with an unexpected runtime value — e.g. construct a getter/remote-call chain whose result is a `wrappedObject` fed into an `ifelse` test (hits `throw Error("test evaluated to object " + res)` at `formula/evaluation.js:1472`), or a `json_parse` result of an unexpected type at `formula/evaluation.js:1953`.
2. Post a unit paying to this AA's address.
3. Every full node with `conf.bDryRunNewTriggers` enabled reaches `network.js`'s `ifOk` handler and calls `await aa_composer.dryRunPrimaryAATrigger(...)`.
4. The internal `throw Error(...)` fires inside an async callback frame beyond the `new Promise` executor's synchronous scope, becomes an uncaught exception, and triggers `process.on('uncaughtException')` → `throw err` → node process crash, before the dry-run transaction is rolled back or the connection released.

### Citations

**File:** network.js (L1271-1281)
```javascript
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
						}
```

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

**File:** aa_composer.js (L272-307)
```javascript
function dryRunPrimaryAATrigger(trigger, address, arrDefinition, onDone) {
	if (!onDone)
		return new Promise(resolve => dryRunPrimaryAATrigger(trigger, address, arrDefinition, resolve));
	console.log('dry run', address, trigger);
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = conf.bLight ? lightBatch : kvstore.batch();
			readLastStableMcUnit(conn, function (mci, objMcUnit) {
				trigger.unit = constants.GENESIS_UNIT; // objMcUnit.unit; // might cause duplicate trigger_unit in aa_triggers if objMcUnit is already a real trigger
				if (!trigger.address)
					trigger.address = objMcUnit.authors[0].address;
				trigger.initial_address = trigger.address;
				trigger.initial_unit = trigger.unit;
				var fPrepare = function (cb) {
					insertFakeOutputsIntoMcUnit(conn, objMcUnit, trigger.outputs, address, cb);
				};
				fPrepare(function () {
					var arrResponses = [];
					handleTrigger({
						bDryRun: true, // suppress events for a unit that will be rolled back
						conn, batch, trigger, params: {}, stateVars: {}, arrDefinition, address, mci, objMcUnit, bSecondary: false, arrResponses,
						onDone: function () {
							revertResponsesInCaches(arrResponses);
							batch.clear();
							conn.query("ROLLBACK", function () {
								conn.release();
								onDone(arrResponses);
							});
						},
					});
				});
			});
		});
	});
}

```

**File:** formula/evaluation.js (L864-871)
```javascript
						} else if (arr[2] === 'asset') {
							cb(result.asset || 'base')
						} else if (arr[2] === 'address') {
							cb(result.address);
						}
						else
							throw Error("unknown field requested: "+arr[2]);
					}
```

**File:** formula/evaluation.js (L1394-1396)
```javascript
								else
									throw Error("unknown assignment op: " + assignment_op);
								if (!isFiniteDecimal(value))
```

**File:** formula/evaluation.js (L1469-1473)
```javascript
					if (Decimal.isDecimal(res))
						res = (res.toNumber() !== 0);
					else if (typeof res === 'object')
						throw Error("test evaluated to object " + res);
					if (!res && !else_block)
```

**File:** formula/evaluation.js (L1949-1954)
```javascript
					if (typeof json === 'number')
						return evaluate(createDecimal(json), cb);
					if (typeof json === 'string' || typeof json === 'boolean')
						return cb(json);
					throw Error("unknown type of json parse: " + (typeof json));
				});
```

**File:** formula/evaluation.js (L3190-3202)
```javascript
	function setFatalError(err, context, cb_arg, cb){
		try {
			const errorData = { error: err, context: context || {}, trace: astTrace, xpath, trigger };
			fatal_error = {formattedError: formatError(errorData)};		
		} catch(formatErr) {
			console.error('unhandled error, use old format', err, formatErr);
			fatal_error = err;
		}

		console.log(err);
		(cb_arg !== undefined) ? cb(cb_arg) : cb(err);
		astTrace = [];
	}
```
