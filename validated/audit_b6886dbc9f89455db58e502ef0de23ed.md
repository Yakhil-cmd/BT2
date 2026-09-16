## Analog Found: Unhandled Synchronous `throw Error()` in oscript Formula Evaluation Can Crash a Node When Processing an AA Trigger

### Title
Uncaught exception in `evaluate()`'s `ifelse` handler crashes the node process when processing an AA trigger - (File: `formula/evaluation.js`)

### Summary
CVE-2019-2784 describes a MySQL Server DML-processing bug that lets an authenticated-but-otherwise-unprivileged user crash/hang the server by feeding it a data-manipulation statement that the engine mishandles internally. The oscript analog is `formula/evaluation.js`'s `evaluate()` function, which is the interpreter used for every AA trigger/response computation. Almost every branch of `evaluate()` reports invalid/unexpected states through the graceful `setFatalError(...)` helper (which bounces the AA and returns control to the caller), but the `ifelse` branch instead does a raw, synchronous `throw Error(...)`: [1](#0-0) 

### Finding Description
In every other place `evaluate()` encounters an unexpected/invalid intermediate value (e.g. `'or'`, `'comparison'`, `'ternary'`), it calls `setFatalError(...)` to fail the AA formula cleanly (returning `false`/bouncing) instead of throwing: [2](#0-1) [3](#0-2) 

But the `ifelse` case throws a raw `Error` synchronously when the evaluated `test` expression is of `typeof 'object'` and not already normalized (wrappedObject → `true`, Decimal → number): [4](#0-3) 

`evaluate()` is invoked deep inside `handleTrigger()` in `aa_composer.js`, which is the code path executed for every primary and secondary AA trigger a node processes, with no surrounding `try/catch` around the recursive `evaluate()` call chain: [5](#0-4) [6](#0-5) 

Because `evaluate()` frequently invokes its callbacks synchronously (the `count % 100` throttle at line 128-129 only periodically defers via `setImmediate`), a thrown `Error` here propagates up the JS call stack through `handleTrigger` and into whatever caller triggered AA processing (unit validation in `validation.js` / `aa_composer.js`), which has no top-level catch for this specific failure mode — an unhandled synchronous exception in Node.js terminates the process (or is caught only by a generic top-level uncaught-exception handler that typically still forces a restart), causing a crash/hang of the node exactly as described in the MySQL DML CVE, but reachable by an ordinary AA author or any unprivileged unit poster who triggers an AA whose oscript definition contains a crafted `ifelse` whose `test` branch resolves to a raw object value that has not already been coerced to `true`/`false`/number by the earlier `wrappedObject`/`Decimal` checks.

### Impact Explanation
Any node (full node, hub, or an AA-processing observer) that executes the trigger against the malicious AA definition will hit the uncaught `throw Error`, crashing/restarting the process. This is a hang/crash-class denial of service against `ocore` nodes analogous to the MySQL "hang or frequently repeatable crash" impact in CVE-2019-2784 — repeated posting of triggers to the vulnerable AA can repeatedly crash any node that re-executes/re-validates the trigger (e.g. during catch-up or re-processing), preventing the network from reliably confirming new units involving that AA.

### Likelihood Explanation
Reachable entirely from data supplied by an unprivileged actor: any user can author and post an AA whose oscript uses `ifelse` in a way engineered to leave `test` evaluated to a bare JS object type at this point in the interpreter, then send a trigger unit to it. No special privileges, witnessing rights, or hub/operator access are required — only the ability to post a unit, which is the baseline capability of any wallet on the network.

### Recommendation
Replace the raw `throw Error("test evaluated to object " + res)` in the `ifelse` branch of `formula/evaluation.js` with the same graceful failure path used elsewhere in the interpreter (`setFatalError(...)`), so that unexpected/invalid `test` results bounce the AA response instead of throwing an uncaught, process-crashing exception. Audit the rest of `evaluate()` for other raw `throw Error(...)` calls inside callback bodies reachable from untrusted oscript input and convert them to `setFatalError` as well.

### Proof of Concept
Author and post an AA definition whose code path drives an `ifelse`'s `test` expression to evaluate to a bare JS object that is neither a `wrappedObject` instance nor a `Decimal` (the two branches that normalize object-typed results before the `typeof res === 'object'` check), then send any trigger unit to the AA so `handleTrigger` → `evaluateAA` → `formulaParser.evaluate` executes the `ifelse` node, causing the synchronous `throw Error` at `formula/evaluation.js:1472` to propagate uncaught through `aa_composer.js`'s trigger-handling call chain.

**Note on verification limits:** I was not able to fully trace `isValidValue()`'s exact set of accepted types (which gates the `typeof res === 'object'` branch) within the available search budget, so I could not conclusively enumerate every concrete oscript construct that produces a `res` satisfying `isValidValue(res)` while still being `typeof 'object'` and not a `wrappedObject`/`Decimal`. The structural evidence — this being the one interpreter branch that raw-throws instead of using the codebase's own graceful-failure convention (`setFatalError`) — is strong, but a Devin session with full repository access should verify `isValidValue`'s definition and construct a concrete failing oscript formula before treating this as fully confirmed.

### Citations

**File:** formula/evaluation.js (L400-425)
```javascript
			case 'or':
				var prevV = false;
				async.eachSeries(arr.slice(1), function (param, cb2) {
					evaluate(param, function (res) {
						if (fatal_error)
							return cb2(fatal_error);
						if (res instanceof wrappedObject)
							res = true;
						if (typeof res === 'boolean') {
						}
						else if (isFiniteDecimal(res))
							res = (res.toNumber() !== 0);
						else if (typeof res === 'string')
							res = !!res;
						else
							return setFatalError('unrecognized type in ' + op, { arr }, undefined, cb2);
						prevV = prevV || res;
						if (prevV) // found first true - abort
							return cb2('done');
						cb2();
					});
				}, function (err) {
					if (err === 'done')
						return cb(true);
					cb(!err ? prevV : false);
				});
```

**File:** formula/evaluation.js (L549-576)
```javascript
			case 'ternary':
				var conditionResult;
				evaluate(arr[1], function (res) {
					if (fatal_error)
						return cb(false);
					if (res instanceof wrappedObject)
						res = true;
					if (typeof res === 'boolean')
						conditionResult = res;
					else if (isFiniteDecimal(res))
						conditionResult = (res.toNumber() !== 0);
					else if (typeof res === 'string')
						conditionResult = !!res;
					else
						return setFatalError('unrecognized type in '+op, { arr }, false, cb);
					var param2 = conditionResult ? arr[2] : arr[3];
					evaluate(param2, function (res) {
						if (fatal_error)
							return cb(false);
						if (isFiniteDecimal(res))
							cb(toDoubleRange(res));
						else if (typeof res === 'boolean' || typeof res === 'string' || res instanceof wrappedObject)
							cb(res);
						else
							return setFatalError('unrecognized type of res in '+op, { arr }, false, cb);
					});
				});
				break;
```

**File:** formula/evaluation.js (L1458-1478)
```javascript
			case 'ifelse':
				var test = arr[1];
				var if_block = arr[2];
				var else_block = arr[3];
				evaluate(test, function (res) {
					if (fatal_error)
						return cb(false);
					if (res instanceof wrappedObject)
						res = true;
					if (!isValidValue(res))
						return setFatalError("bad value in ifelse: " + res, { arr }, false, cb);
					if (Decimal.isDecimal(res))
						res = (res.toNumber() !== 0);
					else if (typeof res === 'object')
						throw Error("test evaluated to object " + res);
					if (!res && !else_block)
						return cb(true);
					var block = res ? if_block : else_block;
					evaluate(block, cb);
				});
				break;
```

**File:** aa_composer.js (L91-151)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
										// copy updatedStateVars to all responses
										if (arrResponses[0].updatedStateVars)
											for (var i = 1; i < arrResponses.length; i++)
												arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
										// merge all changes of balances if the same AA was called more than once
										let assocBalances = {};
										for (let { aa_address, balances } of arrResponses)
											assocBalances[aa_address] = balances; // overwrite if repeated
										for (let r of arrResponses) {
											r.balances = assocBalances[r.aa_address];
											r.allBalances = assocBalances;
										}
									}
									else
										arrResponses[0].allBalances = { [address]: arrResponses[0].balances };
									arrResponses.forEach(function (objAAResponse) {
										if (objAAResponse.objResponseUnit)
											arrPostedUnits.push(objAAResponse.objResponseUnit);
										eventBus.emit('aa_response', objAAResponse);
										eventBus.emit('aa_response_to_unit-'+objAAResponse.trigger_unit, objAAResponse);
										eventBus.emit('aa_response_to_address-'+objAAResponse.trigger_address, objAAResponse);
										eventBus.emit('aa_response_from_aa-'+objAAResponse.aa_address, objAAResponse);
									});
									onDone();
								});
							});
						});
					});
				});
			});
		});
	});
}

```

**File:** aa_composer.js (L399-425)
```javascript
// the result is onDone(objResponseUnit, bBounced)
function handleTrigger(conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone) {
	var trigger_opts;
	if (arguments.length === 1) {
		trigger_opts = conn;
		conn = trigger_opts.conn;
		batch = trigger_opts.batch;
		trigger = trigger_opts.trigger;
		params = trigger_opts.params;
		stateVars = trigger_opts.stateVars;
		arrDefinition = trigger_opts.arrDefinition;
		address = trigger_opts.address;
		mci = trigger_opts.mci;
		objMcUnit = trigger_opts.objMcUnit;
		bSecondary = trigger_opts.bSecondary;
		arrResponses = trigger_opts.arrResponses;
		onDone = trigger_opts.onDone;
		// extra options:
		// trigger_opts.bAir
		// trigger_opts.assocBalances
		if (!!trigger_opts.bAir !== !!trigger_opts.assocBalances)
			throw Error("assocBalances and bAir do not match");
	}
	else
		trigger_opts = { conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone };
	if (arrDefinition[0] !== 'autonomous agent')
		throw Error('bad AA definition ' + arrDefinition);
```
