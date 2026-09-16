I found a concrete analog. The bug class mapped from the MariaDB "Server: Types" availability CVE is an unhandled-type crash: a value whose type falls outside the explicitly enumerated cases triggers an uncaught `throw Error(...)` deep inside asynchronous AA-processing code that every full node executes when stabilizing units — not something recoverable by a callback-based error path, so it can crash the node process (availability impact), analogous to the MariaDB "Types" DoS.

### Title
Uncaught type-handling exception in AA template substitution can crash nodes processing an AA trigger - (File: aa_composer.js)

### Summary
`replace()` in `aa_composer.js`, used by `handleTrigger()` to substitute formulas throughout an AA's message template on every trigger execution, ends its type-dispatch chain with an unconditional `throw Error('unknown type of value in ' + name)` for any value that is not a number, boolean, string, cases-object, if/init-object, array, or non-empty object [1](#0-0) . Because the throw happens inside deeply nested asynchronous callbacks (not wrapped in any surrounding try/catch), it becomes an uncaught exception that crashes the Node.js process on every node that evaluates the trigger, rather than failing gracefully via the existing `err`/`cb` error-propagation convention used throughout the rest of `handleTrigger`.

### Finding Description
`replace()` recursively walks message template fields and evaluates any embedded oscript formulas via `formulaParser.evaluate` [2](#0-1) . When a field value is an object carrying an `if` (and/or `init`) condition, `evaluateIf()` deletes the `if` key once the condition is satisfied and then re-invokes `replace()` on the very same `obj[name]` [3](#0-2) . If that object had no other keys besides `if`, the object becomes `{}` after the deletion. On re-entry, none of the type branches match: it is not a number/boolean/string, `hasCases({})` is false, `value.if`/`value.init` are no longer strings, it's not an array, and `isNonemptyObject({})` is false — so execution falls to the final `else { throw Error('unknown type of value in ' + name); }` [4](#0-3) . This throw is not caught anywhere in `handleTrigger`, `handlePrimaryAATrigger`, or the surrounding DB-transaction/batch-write flow [5](#0-4) , so it propagates as an uncaught exception and can terminate the Node.js process on every node that stabilizes/executes that trigger.

An AA author (an unprivileged unit poster who merely defines and posts an AA) fully controls the AA's `messages` template, including any message field written as `{ if: "<formula>" }` with no sibling keys. Any subsequent trigger sender can then trigger this AA to force evaluation of the malformed template, causing the crash to occur on every node that processes that trigger (all full nodes independently execute AA logic to determine consensus/state), which is a node-availability/DoS condition network-wide — directly analogous to the referenced CVE's "remote authenticated user affects availability via Server: Types" pattern, here realized as "any AA trigger sender affects node availability via unhandled value-type dispatch."

### Impact Explanation
Because AA execution is deterministic and re-executed by every full node to agree on state/stability, an uncaught exception here is not a single-node crash but a synchronized DoS across all nodes processing the same trigger unit, which can halt confirmation of new units on the network (matches the "network unable to confirm new units" acceptance criterion). This is a Medium/High-severity availability issue consistent in class and reachability with the MariaDB CVE (unprivileged-but-authorized actor → crash via unexpected type path).

### Likelihood Explanation
Reachability requires only posting a normal, otherwise-valid AA definition whose validation in `aa_validation.js` does not appear to forbid an `if`-only object with no other sibling fields in template message values, plus a trigger unit that satisfies the `if` condition. Both steps are within reach of any user (AA author + trigger sender), with no special privilege, hub/network-position, or leaked key required.

### Recommendation
In `replace()`, replace the trailing `throw Error(...)` with a graceful error callback (`cb({message: "unknown type of value in " + name, xpath})`), matching the error-handling convention used everywhere else in this function, so malformed/degenerate template values bounce the AA response instead of crashing the process. Additionally, harden `aa_validation.js`'s `validateAADefinition` to reject template objects whose only key is `if`/`init` with no accompanying literal value, closing the code path that produces an empty object after key deletion.

### Proof of Concept
1. Define and post an AA whose `messages` template contains a field structured as an object with only an `if` key and no other properties, e.g. a message field value of `{ if: "{trigger.data.x > 0}" }` with no sibling data in that object.
2. Post a trigger unit satisfying the `if` condition (e.g., `data: {x: 1}`).
3. When `handleTrigger` → `replace()` processes this field: `evaluateIf` evaluates the formula true, deletes `if`, leaving `{}`, and re-invokes `replace()` on the now-empty object.
4. `replace()` falls through all type branches to `throw Error('unknown type of value in ' + name)`, which is uncaught and crashes the Node.js process on every node executing this trigger.

Note: I was not able to fully verify from the index whether `aa_validation.js`'s template validation already blocks an `if`-only object with no sibling keys in every message field type (some paths, e.g. `output.if`/`output.init` in payments, were validated as strings, but general per-field object shapes across all message apps were not fully enumerated in what I could retrieve). Confirming this gap requires reading the complete `validateFieldWrappedInCases`/`validatePayload` logic in `aa_validation.js`, which a Devin session with full file access could verify precisely.

### Citations

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

**File:** aa_composer.js (L618-655)
```javascript
	function replace(obj, name, path, locals, xpath, cb) {
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(replace, obj, name, path, locals, xpath, cb);
		locals = _.clone(locals);
		var value = obj[name];
		if (typeof name === 'string') {
			xpath += '/' + name;
			var f = getFormula(name);
			if (f !== null) {
				var opts = {
					conn: conn,
					formula: f,
					trigger: trigger,
					params: params,
					locals: _.clone(locals),
					stateVars: stateVars,
					responseVars: responseVars,
					objValidationState: objValidationState,
					address: address
				};
				return formulaParser.evaluate(opts, [], xpath, function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + f + " failed: "+err);
					delete obj[name];
					if (res === '')
						return cb(); // the key is just removed from the object
					if (typeof res !== 'string')
						return cb({message: "result of formula " + name + " is not a string: " + res, xpath});
					if (ValidationUtils.hasOwnProperty(obj, res))
						return cb({message: "duplicate key " + res + " calculated from " + name, xpath});
					if (getFormula(res) !== null)
						return cb({message: "calculated value of " + name + " looks like a formula again: " + res, xpath});
					assignField(obj, res, value);
					replace(obj, res, path, locals, xpath, cb);
				});
			}
		}
```

**File:** aa_composer.js (L656-872)
```javascript
		if (typeof value === 'number' || typeof value === 'boolean')
			return cb();
		if (typeof value === 'string') {
			var f = getFormula(value);
			if (f === null)
				return cb();
		//	console.log('path', path, 'name', name, 'f', f);
			var bStateUpdates = (path === '/messages/state');
			if (bStateUpdates) {
				if (objStateUpdate)
					return cb({message: "second state update formula: " + f + ", existing: " + objStateUpdate.formula, xpath});
				objStateUpdate = {formula: f, locals: locals, xpath};
				return cb();
			}
			var opts = {
				conn: conn,
				formula: f,
				trigger: trigger,
				params: params,
				locals: locals,
				stateVars: stateVars,
				responseVars: responseVars,
				objValidationState: objValidationState,
				address: address,
				bObjectResultAllowed: true
			};
			formulaParser.evaluate(opts, [], xpath, function (err, res) {
			//	console.log('--- f', f, '=', res, typeof res);
				if (res === null)
					return cb(err.formattedError || "formula " + f + " failed: "+err);
				if (res === '' || isEmptyObjectOrArray(res)) { // signals that the key should be removed (only empty string or array or object, cannot be false as it is a valid value for asset properties)
					if (typeof name === 'string')
						delete obj[name];
					else
						assignField(obj, name, null);
				}
				else
					assignField(obj, name, res);
				cb();
			});
		}
		else if (hasCases(value)) {
			var thecase;
			xpath += '/cases';
			let idx = -1;
			async.eachSeries(
				value.cases,
				function (acase, cb2) {
					idx++;
					if (!("if" in acase)) {
						thecase = acase;
						return cb2('done');
					}
					var f = getFormula(acase.if);
					if (f === null)
						return cb2({message: "case if is not a formula: " + acase.if, xpath});
					var locals_tmp = _.clone(locals); // separate copy for each iteration of eachSeries
					var opts = {
						conn: conn,
						formula: f,
						trigger: trigger,
						params: params,
						locals: locals_tmp,
						stateVars: stateVars,
						responseVars: responseVars,
						objValidationState: objValidationState,
						address: address
					};
					formulaParser.evaluate(opts, [], xpath + '/' + idx + '/if', function (err, res) {
						if (res === null)
							return cb2(err.formattedError || "formula " + acase.if + " failed: " + err);
						if (res) {
							thecase = acase;
							locals = locals_tmp;
							return cb2('done');
						}
						cb2(); // try next
					});
				},
				function (err) {
					if (!err)
						return cb({message: "neither case is true in " + name, xpath});
					xpath += '/' + idx;
					if (err !== 'done')
						return cb(err);
					var replacement_value = thecase[name];
					if (!ValidationUtils.hasOwnProperty(thecase, name))
						return cb({message: "a case was selected but no replacement value in " + name, xpath}); // can happen if `name` is a formula (evaluated as object key of the `cases` but not per-case)
					assignField(obj, name, replacement_value);
					if (!thecase.init)
						return replace(obj, name, path, locals, xpath, cb);
					var f = getFormula(thecase.init);
					if (f === null)
						return cb({message: "case init is not a formula: " + thecase.init, xpath});
					var opts = {
						conn: conn,
						formula: f,
						trigger: trigger,
						params: params,
						locals: locals,
						stateVars: stateVars,
						responseVars: responseVars,
						bStatementsOnly: true,
						objValidationState: objValidationState,
						address: address
					};
					formulaParser.evaluate(opts, [], xpath + '/init', function (err, res) {
						if (res === null)
							return cb(err.formattedError || "formula " + f + " failed: " + err);
						replace(obj, name, path, locals, xpath, cb);
					});
				}
			);
		}
		else if (typeof value === 'object' && (typeof value.if === 'string' || typeof value.init === 'string')) {
			function evaluateIf(cb2) {
				if (typeof value.if !== 'string')
					return cb2();
				var f = getFormula(value.if);
				if (f === null)
					return cb({message: "if is not a formula: " + value.if, xpath});
				var opts = {
					conn: conn,
					formula: f,
					trigger: trigger,
					params: params,
					locals: locals,
					stateVars: stateVars,
					responseVars: responseVars,
					objValidationState: objValidationState,
					address: address
				};
				formulaParser.evaluate(opts, [], xpath + '/if', function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + value.if + " failed: " + err);
					if (!res) {
						if (typeof name === 'string')
							delete obj[name];
						else
							assignField(obj, name, null); // will be removed
						return cb();
					}
					delete value.if;
					cb2();
				});
			}
			evaluateIf(function () {
				if (typeof value.init !== 'string')
					return replace(obj, name, path, locals, xpath, cb);
				var f = getFormula(value.init);
				if (f === null)
					return cb({message: "init is not a formula: " + value.init, xpath});
				var opts = {
					conn: conn,
					formula: f,
					trigger: trigger,
					params: params,
					locals: locals,
					stateVars: stateVars,
					responseVars: responseVars,
					bStatementsOnly: true,
					objValidationState: objValidationState,
					address: address
				};
				formulaParser.evaluate(opts, [], xpath + '/init', function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + value.init + " failed: " + err);
					delete value.init;
					replace(obj, name, path, locals, xpath, cb);
				});
			});
		}
		else if (Array.isArray(value)) {
			async.eachOfSeries(
				value,
				function (elem, i, cb2) {
					const nXpath = xpath + '/' + i;
					replace(value, i, path, _.clone(locals), nXpath, cb2);
				},
				function (err) {
					if (err)
						return cb(err);
					var replacement_value = value.filter(function (elem) { return (elem !== null); });
					if (replacement_value.length === 0) {
						if (typeof name === 'string')
							delete obj[name];
						else
							assignField(obj, name, null); // to be removed
						return cb();
					}
					assignField(obj, name, replacement_value);
					cb();
				}
			);
		}
		else if (isNonemptyObject(value)) {
			async.eachSeries(
				Object.keys(value).sort(),
				function (key, cb2) {
					replace(value, key, path + '/' + key, _.clone(locals), xpath, cb2);
				},
				function (err) {
					if (err)
						return cb(err);
					if (Object.keys(value).length === 0) {
						if (typeof name === 'string')
							delete obj[name];
						else
							assignField(obj, name, null); // to be removed
						return cb();
					}
					cb();
				}
			);
		}
		else
			throw Error('unknown type of value in ' + name);
```
