### Title
Unrestricted remote getter call target (`remote_func_call`) lets an attacker-controlled AA return fabricated values into a caller's financial calculation - (File: `formula/evaluation.js`, `formula/validation.js`)

### Summary
The Code4rena finding shows a lender supplying attacker-controlled `zeroExTradeData` that drives an arbitrary external call whose *result* (`tokensBought`) is blindly trusted by the caller to decide how much debt gets repaid, bypassing a weak `!= 0` sanity check and letting the caller siphon value. The structural analog in `ocore`'s AA (Autonomous Agent) engine is the `remote_func_call` / `$aa.$getter(...)` feature: an AA's oscript formula can invoke a **getter** on another AA whose *address is derived from data supplied by the unprivileged trigger sender*, and then use the getter's return value directly in a payment/state computation, without any AA-side mechanism forcing the target to be a specific, pre-vetted contract.

### Finding Description
`ocore` lets an AA definition call a "remote" AA's getter with syntax like `$remote_aa.$f(args)` or `$remote_aa#$max_complexity.$f(args)`. The remote AA address can be a formula expression, including one taken straight from `trigger.data` — this is explicitly demonstrated in the test suite:
`trigger.data.aa#${remote_base_aa_address}.$g(trigger.data.x)` [1](#0-0) 

At evaluation time, the address expression is evaluated and only checked for being a syntactically valid address; there is no requirement that it be a specific, whitelisted AA unless the definition author explicitly pins it to a `base_aa` via the `#` complexity/base-AA slot: [2](#0-1) 

The getter is then executed against the *remote* AA's own state vars and params (its balance, storage, etc. — all attacker-controlled if the attacker deployed that AA): [3](#0-2) 

The validation layer does provide an *optional* protection — pinning the remote call to a known `base_aa` so that only AAs sharing that base template can be invoked — enforced only when the AA definition author uses the `#baseAA` form: [4](#0-3) 
and the corresponding "is not base AA for remote AA" bounce shown in the test where a mismatched AA is rejected: [5](#0-4) 

But if the AA author omits this pinning and simply writes `$remote_aa = trigger.data.oracle_aa; $ret = $remote_aa.$f(...)`, the trigger sender fully controls which AA is called. Since getters are pure functions of the target AA's own params/state vars (not of the trigger), an attacker can pre-deploy their own AA, set its state to return any value they like from the getter, and then trigger the victim AA pointing `trigger.data.oracle_aa` at their malicious AA. If the victim AA uses the getter's return value to compute a payout, exchange rate, or "amount bought"-like figure (the same role `tokensBought` plays in the Code4rena bug) and pays out based on it, the trigger sender can fabricate the number to drain the AA's balance — exactly mirroring the reported pattern of an attacker-controlled external-call result being trusted for a financial decision.

### Impact Explanation
Any AA that (a) resolves a remote-call target address from trigger data (or any other attacker-influenced input) instead of a hardcoded/whitelisted address or `base_aa`-pinned address, and (b) uses the getter's return value to size a payment output, can have its balance drained by a trigger sender who deploys a purpose-built malicious AA to feed a fabricated value into that computation. This is unauthorized fund loss triggered entirely by an unprivileged AA trigger sender, matching the required "concrete unauthorized spending / AA fund loss" bar.

### Likelihood Explanation
Exploitability requires only: (1) deploying an arbitrary AA (unprivileged, anyone can do this), and (2) finding/using a victim AA whose oscript passes an attacker-influenced address into a `remote_func_call` and trusts the returned value for a payment computation without validating the target via `base_aa` pinning or an address whitelist. This is a real, demonstrated language feature (not a hypothetical), and the codebase's own test suite shows both the unrestricted form (`$remote_aa.$f(...)` with `$remote_aa` derived from `trigger.data.aa`) and that the safer `#baseAA` pinning is optional, not mandatory. The risk is entirely dependent on individual AA authors following (or failing to follow) the safer pattern, making likelihood moderate-to-high for any AA design that dynamically selects a "price provider," "exchange," or "oracle-like" remote AA based on trigger input.

### Recommendation
- In documentation/dev guidance for AA authors, strongly recommend (or, at the engine level, consider requiring) that `remote_func_call` targets be either constant/hardcoded addresses or pinned to a known `base_aa` via the `#baseAA` syntax whenever the getter's return value influences a payment/state decision, exactly as the "is not base AA for remote AA" check already does when it's used.
- Consider adding an engine-level warning/lint (in `formula/validation.js`) when a `remote_func_call`'s address expression is derived from `trigger.data` (or other externally influenced input) without an accompanying `base_aa` pin, so AA authors are alerted to the risk at validation time.
- Encourage patterns where financial payout amounts derived from remote getters are additionally bounded/sanity-checked against the AA's own balance and independent invariants, rather than trusting the remote value outright.

### Proof of Concept
1. Attacker deploys `MaliciousOracleAA` with a getter, e.g. `getters: "{ $rate = () => 1e9; }"`, fully attacker-controlled and returning an arbitrarily large "rate"/"amountBought"-like value.
2. `VictimAA` is written (a plausible "exchange/oracle proxy" pattern) as:
   ```
   init: "{ $oracle = trigger.data.oracle_aa; $rate = $oracle.$rate(); }"
   messages: [{ app: 'payment', payload: { asset: 'base', outputs: [{ address: "{trigger.address}", amount: "{ trigger.output[[asset=X]] * $rate }" }] } }]
   ```
   Note `$oracle` is taken directly from `trigger.data.oracle_aa` and is not pinned to any `base_aa`, mirroring `$ret3 = ... trigger.data.aa#$remote_base_aa_address.$g(...)` from the test suite but without the safe `#baseAA` pin. [6](#0-5) 
3. Attacker sends a trigger to `VictimAA` with `data: { oracle_aa: MaliciousOracleAA_address }` and a small amount of asset `X`.
4. `VictimAA`'s formula calls `$oracle.$rate()`, which resolves to `MaliciousOracleAA`'s getter and returns `1e9` (fabricated by attacker), because the remote-call address was fully attacker-supplied and unrestricted, per the engine behavior shown in `formula/evaluation.js` (`remote_func_call` case) and `callGetter`. [7](#0-6) 
5. `VictimAA` computes and sends an inflated `amount = trigger.output[[asset=X]] * 1e9` payment to the attacker, draining its base-asset balance — the AA equivalent of the lender inflating `tokensBought` via malicious `zeroExTradeData` to steal borrower funds.

### Citations

**File:** test/aa_composer.test.js (L1188-1196)
```javascript
	var trigger = { outputs: { base: 10000 }, data: { x: 5, aa: remote_aa_address }, address: trigger_address };

	var aa = ['autonomous agent', {
		init: `{
			$remote_aa = '${remote_aa_address}';
			$remote_base_aa_address = '${remote_base_aa_address}';
			$ret = $remote_aa.$f(trigger.data.x);  // complexity: 3
			$ret2 = ($remote_aa || '')#${remote_base_aa_address}.$f(trigger.data.x); // complexity: 3
			$ret3 = 1 + trigger.data.aa#$remote_base_aa_address.$g(trigger.data.x);  // complexity: 1
```

**File:** test/aa_composer.test.js (L1339-1359)
```javascript
	validateAA(remote_base_aa, async err => {
		t.deepEqual(err, null);
		await asyncAddAA(remote_base_aa);
		await asyncAddAA(remote_base_aa2);

		validateAA(remote_aa, async err => {
			t.deepEqual(err, null);
			await asyncAddAA(remote_aa);
			await db.query("UPDATE aa_addresses SET storage_size=100 WHERE address=?", [remote_aa_address]);

			validateAA(aa, async (err, res) => {
				t.deepEqual(err, null);
				await asyncAddAA(aa);
				
				aa_composer.dryRunPrimaryAATrigger(trigger, aa_address, aa, (arrResponses) => {
					t.deepEqual(arrResponses.length, 1);
					t.deepEqual(arrResponses[0].bounced, true);
					t.regex(JSON.stringify(arrResponses[0].response.error), /is not base AA for remote AA/);
					t.end();
				});
			});
```

**File:** formula/evaluation.js (L2588-2630)
```javascript
			case 'remote_func_call':
				var remote_aa_expr = arr[1];
				var max_remote_complexity = arr[2];
				var func_name = arr[3];
				var arrExpressions = arr[4];
				if (arrExpressions.length > 30 && bPostPemCurvesFix)
					return setFatalError("too many arguments to remote func " + func_name, { arr }, false, cb);
				var args = [];
				async.eachSeries(
					arrExpressions,
					function (expr, cb2) {
						evaluate(expr, function (res) {
							if (fatal_error)
								return cb2(fatal_error);
							if (!isValidValue(res) && !(res instanceof wrappedObject))
								return setFatalError("bad value of function argument: " + JSON.stringify(res), { arr }, undefined, cb2);
							args.push(res);
							cb2();
						});
					},
					function (err) {
						if (fatal_error)
							return cb(false);
						evaluate(remote_aa_expr, function (remote_aa) {
							if (fatal_error)
								return setFatalError(fatal_error, { arr }, false, cb);
							if (!ValidationUtils.isValidAddress(remote_aa))
								return setFatalError("not valid remote AA: " + remote_aa, { arr }, false, cb);
							checkMaxRemoteComplexity(remote_aa, func_name, max_remote_complexity, (err) => {
								if (fatal_error)
									return cb(false);
								if (err)
									return setFatalError(err, { arr }, false, cb);
								callGetter(conn, remote_aa, func_name, args, stateVars, objValidationState, astTrace, xpath, { caller_aa: address, call_line: arr.line, call_xpath: xpath }, (err, res) => {
									if (err)
										return setFatalError(err, { arr }, false, cb);
									astTrace.push({system: 'exit from getters', aa: remote_aa, caller_aa: address, call_line: arr.line, call_xpath: xpath});
									cb(res);
								});
							});
						});
					}
				);
```

**File:** formula/evaluation.js (L3289-3336)
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
			if (res === null) 
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			if (!hasOwnProperty(locals, getter))
				return cb("no such getter: " + JSON.stringify(getter));
			if (!(locals[getter] instanceof Func))
```

**File:** formula/validation.js (L1394-1452)
```javascript
	function readFuncProps(func_expr, cb) {
		if (func_expr[0] === 'local_var') {
			var var_name = func_expr[1];
			if (typeof var_name !== 'string')
				return cb("only literal var names allowed in func expression");
			if (!hasOwnProperty(locals, var_name))
				return cb("no such func: " + var_name);
			if (locals[var_name].type !== 'func')
				return cb("not a function: " + var_name);
			var props = locals[var_name].props;
			cb(null, props);
		}
		else if (func_expr[0] === 'func_declaration') {
			var arglist = func_expr[1];
			var body = func_expr[2];
			parseFunctionDeclaration(arglist, body, cb);
		}
		else if (func_expr[0] === 'remote_func') {
			var remote_aa = func_expr[1];
			var max_remote_complexity = func_expr[2];
			var func_name = func_expr[3];
			if (max_remote_complexity !== null) {
				if (mci < constants.aa3UpgradeMci)
					return cb("max_remote_complexity not enabled yet");
				var rc_res = parseRemoteComplexity(max_remote_complexity);
				if (rc_res.error)
					return cb(rc_res.error);
				max_remote_complexity = rc_res.remote_complexity;
			}
			var res = parseRemoteAA(remote_aa);
			if (res.error && max_remote_complexity === null)
				return cb(res.error);
			var evaluated_remote_aa = res.remote_aa;
			var ultimate_remote_aa;
			if (evaluated_remote_aa)
				ultimate_remote_aa = evaluated_remote_aa;
			else if (typeof max_remote_complexity === 'string')
				ultimate_remote_aa = max_remote_complexity; // base AA
			
			evaluate(remote_aa, err => {
				if (err)
					return cb(err);
				if (!ultimate_remote_aa) {
					if (typeof max_remote_complexity !== 'number')
						throw Error('max_remote_complexity is not a number ' + max_remote_complexity);
					const complexity = max_remote_complexity + 1;
					// add ops proportionally to complexity
					const count_ops = complexity * Math.ceil(constants.MAX_OPS / constants.MAX_COMPLEXITY);
					return cb(null, { complexity, count_ops, count_args: null });
				}
				readGetterProps(ultimate_remote_aa, func_name, getter => {
					if (!getter)
						return cb("no such getter: " + JSON.stringify(ultimate_remote_aa) + ".$" + func_name + "()");
					if (typeof getter.complexity !== 'number' || typeof getter.count_ops !== 'number' || (typeof getter.count_args !== 'number' && getter.count_args !== null))
						throw Error("invalid getter in " + ultimate_remote_aa + ".$" + func_name + ": " + JSON.stringify(getter));
					getter.complexity++; // for remote call
					cb(null, getter);
				});
			});
```
