Confirmed: `response_var_assignment` in `formula/evaluation.js:1408-1433` has **no runtime `bGetters` check at all**, unlike `state_var_assignment` (which is separately gated by `bStateVarAssignmentAllowed` at line 1309) and `response_unit` (gated by `bStateVarAssignmentAllowed` at line 2548). The static validator (`formula/validation.js:690-692`) rejects `response_var_assignment` when `bGetters` is set, but that is a compile-time guard on the top-level getters formula only — it does not protect code paths inside function bodies called from a getter context at evaluation time.

### Title
Missing runtime bGetters guard on response_var_assignment allows getter-mode formulas to write response vars - (File: formula/evaluation.js)

### Summary
`formula/validation.js` statically forbids `response[...]=...` when `bGetters` is true, but the actual interpreter in `formula/evaluation.js` never re-checks `bGetters` before executing a `response_var_assignment`, unlike sibling ops (`state_var_assignment`, `response_unit`) that are properly gated by `bStateVarAssignmentAllowed` at runtime.

### Finding Description
Getters (`arrDefinition[1].getters`) are meant to be a "safe", read-only formula-evaluation sandbox: they must not mutate state vars, must not set the response, and must not have side effects, so that they can be freely called by remote AAs and light clients without affecting the calling AA's outcome (`aa_composer.js:589-615`, `callGetter` in `formula/evaluation.js:3289-3377`). Static validation enforces `response_var_assignment not allowed in getters` (`formula/validation.js:690-692`) and `state var assignment not allowed here` when `bGetters` (`formula/validation.js:671`). Corresponding runtime enforcement exists for state var writes and `response_unit`, both explicitly checking `bStateVarAssignmentAllowed` (`formula/evaluation.js:1309`, `formula/evaluation.js:2548`). However the `response_var_assignment` handler at `formula/evaluation.js:1408-1433` performs no `bGetters`/`bStateVarAssignmentAllowed` check whatsoever — it unconditionally writes into `responseVars`. If any evaluation path reaches this opcode with `bGetters` intent but the validator's static guard is bypassed (e.g. any inconsistency between the AST accepted by the parser/validator and what the interpreter executes for this op, or any caller that invokes `evaluate()` on getter-sourced code without going through the exact same `bGetters` validation, such as different opt combinations across `evaluateAA`, `determineGetterProps`, and `callGetter`), the getter formula could pollute `responseVars` of the triggering unit, which directly influences the AA's bounce/response message content and can lead to unintended AA response output, similar in spirit to the Twig sandbox escape where a restricted "safe" execution context is used to reach functionality the sandbox was specifically designed to forbid.

### Impact Explanation
If reachable, an AA author (an "unprivileged unit poster/AA author" per allowed actors) could use a getter definition to inject arbitrary `response[...]` values into the triggering unit's AA response, which downstream code and other contracts may treat as authoritative response data—potentially enabling AA response spoofing or unexpected message construction that could mislead payment/refund logic in the composer. This falls under "AA fund loss or freezing" / "node disagreement on validity" impact classes if it changes computed responses inconsistently between nodes.

### Likelihood Explanation
Low-to-uncertain: I could not find a concrete second, independent code path where `evaluate()` is invoked on getter code with the validator's `bGetters` static check skipped or mismatched — every observed caller (`aa_composer.js:589-615`'s `evaluateAA`, `aa_validation.js` `validateDefinition`/`determineGetterProps`, and `formula/evaluation.js`'s own `callGetter`) always validates with `bGetters: true` first via `formula/validation.js`, and that static check does correctly reject `response_var_assignment`/`state_var_assignment` before evaluation ever runs. The missing runtime check in `evaluation.js` is a real inconsistency/defense-in-depth gap (mirroring the Twig CVE's root cause — an inner privileged/unsafe operation lacking its own gate and relying solely on outer sandboxing), but I was not able to prove a concrete reachable execution path in this codebase snapshot that bypasses the static validator to trigger it at runtime.

### Recommendation
Add an explicit runtime check in `formula/evaluation.js`'s `response_var_assignment` case (mirroring `state_var_assignment`'s `bStateVarAssignmentAllowed` gate) so that the interpreter does not solely rely on the static validator for this safety property, consistent with defense-in-depth used elsewhere (`response_unit`, `state_var_assignment`).

### Proof of Concept
Not constructed — no confirmed reachable path was found where evaluation-time `bGetters` differs from the validator's decision; this is reported as a hardening gap rather than a proven exploit. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** formula/evaluation.js (L1308-1310)
```javascript
			case 'state_var_assignment':
				if (!bStateVarAssignmentAllowed)
					return setFatalError("state var assignment not allowed here", { arr }, false, cb);
```

**File:** formula/evaluation.js (L1408-1433)
```javascript
			case 'response_var_assignment':
				var var_name_or_expr = arr[1];
				var rhs = arr[2];
				evaluate(var_name_or_expr, function (var_name) {
					if (fatal_error)
						return cb(false);
					if (typeof var_name !== 'string')
						return setFatalError("assignment: response var name must be string, " + var_name_or_expr + " evaluated to " + JSON.stringify(var_name) + ` (${typeof var_name})`, { arr }, false, cb);
					evaluate(rhs, function (res) {
						if (fatal_error)
							return cb(false);
						// response vars - strings, numbers, and booleans
						if (res instanceof wrappedObject)
							res = true;
						if (!isValidValue(res))
							return setFatalError("evaluation of rhs " + rhs + " in response var assignment failed: " + JSON.stringify(res), { arr }, false, cb);
						if (Decimal.isDecimal(res)) {
							res = res.toNumber();
							if (!isFinite(res))
								return setFatalError("not finite js number in response_var_assignment", { arr }, false, cb);
						}
						assignField(responseVars, var_name, res);
						cb(true);
					});
				});
				break;
```

**File:** formula/evaluation.js (L2547-2553)
```javascript
			case 'response_unit':
				if (!bAA || !bStateVarAssignmentAllowed)
					return setFatalError("response_unit outside state update formula", { arr }, false, cb);
				if (!objResponseUnit)
					return cb(false);
				cb(objResponseUnit.unit);
				break;
```

**File:** formula/evaluation.js (L3289-3331)
```javascript
function callGetter(conn, aa_address, getter, args, stateVars, objValidationState, astTrace, xpath, callerInfo, cb) {
	var i = 0;
	var locals = {};
	function getNextArgName() {
		i++;
		while (locals['arg' + i])
			i++;
		return 'arg' + i;
	}

	function addAstTrace(value) {
		if (astTrace) {
			astTrace.push(value);
		}
	}

	// no need to cloneDeep, we need to rewrite only storage size, assocBalances cache can be updated by reference
	let objGetterValidationState = _.clone(objValidationState);
	storage.readBaseAADefinitionAndParams(conn, aa_address, objValidationState.last_ball_mci, function (arrBaseDefinition, params, storage_size) {
		if (!arrBaseDefinition)
			return cb("remote AA not found: " + aa_address);
		// rewrite storage size with the storage size of the AA being called
		objGetterValidationState.storage_size = storage_size;
		var f = getFormula(arrBaseDefinition[1].getters);
		const caller_aa = callerInfo && callerInfo.caller_aa;
		const call_line = callerInfo && callerInfo.call_line;
		const call_xpath = callerInfo && callerInfo.call_xpath;

		addAstTrace({ system: 'enter to getters', aa: aa_address, formula: f, caller_aa, call_line, call_xpath });

		var opts = {
			conn: conn,
			formula: f,
			trigger: null,
			params: params,
			locals: locals,
			stateVars: stateVars,
			responseVars: null,
			bStatementsOnly: true,
			objValidationState: objGetterValidationState,
			address: aa_address
		};
		exports.evaluate(opts, astTrace, xpath, function (err, res) {
```

**File:** formula/validation.js (L670-702)
```javascript
			case 'state_var_assignment':
				if (!bAA || !bStateVarAssignmentAllowed || bGetters)
					return cb('state var assignment not allowed here');
				complexity++;
				var var_name_or_expr = arr[1];
				var rhs = arr[2];
				var assignment_op = arr[3];
				if (typeof var_name_or_expr === 'number' || typeof var_name_or_expr === 'boolean' || Decimal.isDecimal(var_name_or_expr))
					return cb('bad var name: ' + var_name_or_expr);
				if (!assignment_op)
					return cb('no assignment op in state var assignment');
				if (['=', '+=', '-=', '*=', '/=', '%=', '||='].indexOf(assignment_op) === -1)
					return cb('bad assignment op: ' + assignment_op);
				evaluate(var_name_or_expr, function (err) {
					if (err)
						return cb(err);
					evaluate(rhs, cb);
				});
				break;

			case 'response_var_assignment':
				if (bGetters)
					return cb("response var assignment not allowed in getters");
				var var_name_or_expr = arr[1];
				var rhs = arr[2];
				if (typeof var_name_or_expr === 'number' || typeof var_name_or_expr === 'boolean' || Decimal.isDecimal(var_name_or_expr))
					return cb('bad var name: ' + var_name_or_expr);
				evaluate(var_name_or_expr, function (err) {
					if (err)
						return cb(err);
					evaluate(rhs, cb);
				});
				break;
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
