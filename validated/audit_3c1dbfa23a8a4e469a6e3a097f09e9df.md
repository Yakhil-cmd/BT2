### Title
Unhandled `throw Error` in oscript formula/AA-composer paths reachable from AA definitions/triggers can crash all full nodes, halting the network - (File: [ocore--013/formula/evaluation.js](https://github.com/hirayap/ocore--013/blob/main/formula/evaluation.js), [ocore--013/aa_composer.js](https://github.com/hirayap/ocore--013/blob/main/aa_composer.js))

### Summary
The Optimism report describes a parsing/decoding routine (`ReadWitnessData`) that bubbles up an unhandled error on encountering data it does not expect, and this error halts an entire batch process (migration) rather than skipping the single offending item. The closest reachable analog in ocore is the oscript formula evaluator and AA composer, which are executed deterministically by every full node while processing AA triggers on the DAG. Throughout `evaluate()` in `formula/evaluation.js` and `handleTrigger()`/related helpers in `aa_composer.js`, most malformed-runtime-state conditions are handled gracefully via `setFatalError(...)` (which just bounces the AA), but a number of code paths still use unconditional `throw Error(...)` for conditions that are only checked at validation time or assumed unreachable, e.g. `default: throw Error('unrecognized op '+op);` [1](#0-0)  and multiple `default: throw Error("unknown ...")` branches inside comparison/type-coercion logic [2](#0-1) [3](#0-2) .

### Finding Description
The AA trigger/response pipeline is executed by every node deterministically once a triggering unit becomes stable: `handleAATriggers` reads pending triggers and calls `handlePrimaryAATrigger` → `handleTrigger`, which in turn calls into `evaluateAA`/`formulaParser.evaluate` to run the AA's oscript code against the (attacker-supplied) trigger data [4](#0-3) [5](#0-4) .

Inside `formula/evaluation.js`'s `evaluate()` function, the vast majority of "unexpected" conditions correctly call `setFatalError(...)`, which safely aborts only the current formula evaluation and lets the AA bounce (i.e., the analogous "skip and continue" fix recommended in the Optimism report is already applied in most places). However, several branches instead use a bare `throw Error(...)`, which is an uncaught exception in Node.js in the synchronous call stack of unit processing — for example the `default: throw Error('unrecognized op '+op);` fallback for the main opcode switch [1](#0-0) , unknown-comparison-operator branches [6](#0-5) [7](#0-6) , unknown assignment operator handling [8](#0-7) , and "unrecognized function argument" in `evaluateFunctionExpression` [9](#0-8) . Similar `throw Error(...)` calls exist in `aa_composer.js` for conditions such as missing cached unit props, base-AA-not-found, and secondary-AA bounce-with-response-unit combinations [10](#0-9) [11](#0-10) .

Critically, `network.js` installs a global `uncaughtException` handler that intentionally re-throws to crash the whole node process: `throw err; // crash the process to avoid ending up in an inconsistent state` [12](#0-11) . Because AA trigger processing (`handleAATriggers`/`handleTrigger`) runs deterministically and identically on every full node once a triggering unit is confirmed stable, any oscript construct that is accepted by `aa_validation.js`/AST parsing at definition time but drives the runtime `evaluate()` into one of these `throw Error(...)` branches (rather than a `setFatalError` branch) would crash every full node simultaneously as they process the same stable unit — unlike a normal validation error, which only affects a single unit/message and is contained by `try/catch` around unit validation.

### Impact Explanation
If such a code path is reachable at runtime (i.e., a state/type combination that static AA definition validation does not exclude but that the interpreter did not anticipate), a single malicious or buggy AA definition combined with an attacker-crafted trigger (reachable by any unprivileged AA trigger sender) could deterministically crash every full node processing that MC unit. Because the crash occurs identically on all nodes at the same point in DAG processing, this is not a resource-only or single-peer DoS — it can halt the entire network's ability to confirm new units (since AA processing blocks progression of stable state), matching the "network unable to confirm new units" bar in the validation criteria.

### Likelihood Explanation
Likelihood is Medium: reaching most of these `throw Error` branches likely requires finding an oscript expression/state combination that passes `aa_validation.js`'s static checks but produces at runtime a type/value that isn't handled by the corresponding `setFatalError` guards (e.g., an unexpected combination reaching the assignment-operator switch's default, or an internal-only opcode reachable via a crafted AST). This is analogous to the reported bug class (parser/decoder encountering unexpected structured input and throwing instead of gracefully rejecting), but concrete exploitability depends on finding a specific gap between static AA validation and runtime evaluation that has not been confirmed here.

### Recommendation
Audit every `throw Error(...)` inside `formula/evaluation.js`'s `evaluate()` and `aa_composer.js`'s `handleTrigger` path that is reachable from attacker-controlled trigger/state data, and convert them to `setFatalError(...)`/graceful bounce paths (as already done for the majority of cases), consistent with the Optimism report's recommendation to continue/skip rather than bubble up a hard error. Additionally, consider wrapping AA trigger processing (`handleAATriggers`) in a try/catch that safely bounces the offending AA/unit instead of allowing an exception to propagate to the global `uncaughtException` handler that crashes the process.

### Proof of Concept
Not constructed — a concrete PoC would require identifying a specific oscript AST/state combination that bypasses `aa_validation.js`'s static checks yet reaches one of the identified `throw Error` branches in `formula/evaluation.js` at runtime (e.g., via `evaluateFunctionExpression`'s `default: throw Error("unrecognized function argument...")` at [9](#0-8)  or the assignment-operator default at [8](#0-7) ). This gap is flagged as uncertain and would need dynamic testing/fuzzing of the oscript AST against the validator/evaluator pair to confirm exploitability.

### Citations

**File:** formula/evaluation.js (L472-486)
```javascript
						switch (operator) {
							case '==':
								return cb(val1 === val2);
							case '>=':
								return cb(val1 >= val2);
							case '<=':
								return cb(val1 <= val2);
							case '!=':
								return cb(val1 !== val2);
							case '>':
								return cb(val1 > val2);
							case '<':
								return cb(val1 < val2);
							default:
								throw Error("unknown comparison: " + operator);
```

**File:** formula/evaluation.js (L517-518)
```javascript
							default:
								throw Error("unknown comparison: " + operator);
```

**File:** formula/evaluation.js (L521-532)
```javascript
					if (typeof val1 === 'string' || typeof val2 === 'string') {
						if (typeof val1 !== 'string')
							val1 = val1.toString();
						if (typeof val2 !== 'string')
							val2 = val2.toString();
						switch (operator) {
							case '==':
								return cb(val1 === val2);
							case '!=':
								return cb(val1 !== val2);
							default:
								return setFatalError("not allowed comparison for string-casts: " + operator, {
```

**File:** formula/evaluation.js (L1392-1395)
```javascript
								else if (assignment_op === '%=')
									value = value.mod(res);
								else
									throw Error("unknown assignment op: " + assignment_op);
```

**File:** formula/evaluation.js (L2757-2758)
```javascript
			default:
				throw Error('unrecognized op '+op);
```

**File:** formula/evaluation.js (L3131-3132)
```javascript
		else
			throw Error("unrecognized function argument: " + func_expr);
```

**File:** aa_composer.js (L91-150)
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

**File:** aa_composer.js (L589-615)
```javascript
	function evaluateAA(arrDefinition, cb) {
		var locals = {};
		var f = getFormula(arrDefinition[1].getters);
		if (f === null) { // no getters
			return replace(arrDefinition, 1, '', locals, '', cb);
		}
		// evaluate getters before everything else as they can define a few functions
		delete arrDefinition[1].getters;
		var opts = {
			conn: conn,
			formula: f,
			trigger: trigger,
			params: params,
			locals: locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStatementsOnly: true,
			bGetters: true,
			objValidationState: objValidationState,
			address: address
		};
		formulaParser.evaluate(opts, [], '/getters', function (err, res) {
			if (res === null)
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			replace(arrDefinition, 1, '', locals, '', cb);
		});
	}
```

**File:** aa_composer.js (L1672-1674)
```javascript
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
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
