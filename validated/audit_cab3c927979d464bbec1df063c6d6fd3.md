### Title
Fractional exponentiation with a negative base calls `Decimal.ln()` on a negative number, throwing an uncaught DecimalError that crashes AA trigger processing - (File: `formula/evaluation.js`)

### Summary
In oscript's `^` operator handling, a fractional (non-integer) exponent on a negative base is evaluated by computing `prevV.ln()` without first checking whether `prevV` is negative. `Decimal.js`'s `ln()` throws a native `DecimalError` for negative arguments. Unlike every other risky operation in this evaluator (division, sqrt, ln, string parsing, etc.), which are guarded and routed through `setFatalError()` to gracefully bounce the AA, this path has no guard and the exception propagates unhandled through the `async.eachSeries` callback chain that drives `handleTrigger()`.

### Finding Description
The vulnerable code is in the arithmetic operator handler for `^`: [1](#0-0) 

```
if (f === 'pow'){
    if (prevV.eq(decimalE)){ // natural exponential
        ...
    }
    if (res.abs().gte(Number.MAX_SAFE_INTEGER))
        return setFatalError('too large exponent ' + res, { arr }, undefined, cb2);
    if (res.isInteger()) {
        prevV = prevV.pow(res);
        return cb2();
    }
    // fractional power ...
    prevV = toDoubleRange(toDoubleRange(prevV.ln()).times(res)).exp();
    return cb2();
}
```

Both `prevV` (the base) and `res` (the exponent) are each individually valid finite `Decimal` values that passed the earlier `isFiniteDecimal`/`toDoubleRange` checks (line 199-200 of the same function): ` [2](#0-1) `. Individually, a negative base and a non-integer exponent are both perfectly legal oscript values — there is no validation step that rejects `base < 0`. However, their *combination* — `base < 0` together with a fractional `exponent` — falls outside the domain of `Decimal.ln()`, which requires a strictly positive argument. This mirrors the reported Panoptic bug class exactly: two individually-bounded/valid inputs (`tickLower`, `tickUpper`) combine (via subtraction) into a value that exceeds the domain of a downstream function (`getSqrtRatioAtTick`), causing a deterministic revert instead of the expected "graceful failure" path.

By contrast, the dedicated `sqrt`/`ln`/`abs` case explicitly checks `res.isNegative()` before calling `.ln()`/`.sqrt()` and routes to `setFatalError` if it is: ` [3](#0-2) `. The `^` operator's fractional-power branch lacks this equivalent guard, so any formula such as `(-1)^0.5` reaches `prevV.ln()` with a negative `prevV` and throws synchronously inside the `async.eachSeries` iterator callback at line 187-233 of `evaluate`, rather than calling `cb2` at all.

### Impact Explanation
`evaluate()` (the oscript formula evaluator) is invoked from many places in `aa_composer.js` during AA trigger processing — including `init`, `messages`, `state` formulas, and the state-update formula executed via `executeStateUpdateFormula` (` [4](#0-3) `) and `replace()` (` [5](#0-4) `). None of these call sites wrap `formulaParser.evaluate(...)` in a `try/catch`; they all assume any failure is surfaced through the `(err, res)` callback via `setFatalError`, not a thrown exception. An uncaught throw from deep inside the async callback chain propagates outside `handleTrigger`'s control flow. Depending on the surrounding driver (`async.eachSeries`/`setImmediate`), this manifests as an unhandled exception that crashes the Node process running `aa_composer` (full node/hub), or otherwise leaves a trigger unit stuck in a state where it can never be fully processed (neither bounced nor completed) — a form of AA fund freezing, since coins sent to that AA are consumed but no response is produced and the node's unit-processing pipeline is disrupted. Because any unprivileged unit poster can compose an AA definition or a trigger containing such a formula, this is reachable by a single account with no special privileges, matching the reachability requirement (AA definition/trigger author). It is a validity/availability issue on the AA execution engine rather than a fund-theft bug, but it satisfies "AA fund loss or freezing" / "node disagreement on validity" categories since one node crashing on this input while others behave differently (e.g., a node using a different Decimal library) could also cause consensus disagreement on whether a trigger unit is processable.

### Likelihood Explanation
Likelihood is high: `(-1)^0.5`, `(-2)^1.5`, or any negative-base/fractional-exponent expression is trivial to construct in oscript and requires no special permissions — any user composing a unit or an AA can trigger it. The condition (negative base, non-integer exponent) is not filtered anywhere in `formula/validation.js`'s complexity/type checks for `^` (` [6](#0-5) `), which only checks that operands are not strings, not that a subsequent numeric computation stays in-domain — directly analogous to the RiskEngine only validating `tickLower`/`tickUpper` individually and not their derived difference.

### Recommendation
Before computing the fractional-power branch, check `prevV.isNegative()` and route to `setFatalError` (as already done for the standalone `ln`/`sqrt` operators), e.g.:
```
if (prevV.isNegative())
    return setFatalError('fractional power of negative base', { arr }, undefined, cb2);
prevV = toDoubleRange(toDoubleRange(prevV.ln()).times(res)).exp();
```
This ensures the failure is surfaced as a graceful AA bounce through the existing `fatal_error`/`setFatalError` mechanism instead of an uncaught exception that can crash the process or desynchronize node behavior.

### Proof of Concept
An AA (or any oscript formula context) containing:
```
messages: [{
  app: 'state',
  state: "{ $y = (-1) ^ 0.5; }"
}]
```
When triggered, evaluation reaches the `^` operator handler in `formula/evaluation.js`; `res.isInteger()` is false (`0.5`), so execution falls into the fractional-power branch and calls `prevV.ln()` with `prevV = -1`. `Decimal.js` throws `DecimalError: [DecimalError] Ln argument must be positive` synchronously, which is not caught by any `try/catch` in `evaluate()`'s `+`/`-`/`*`/`/`/`%`/`^` handler (` [7](#0-6) `) nor by `aa_composer.js`'s callers, propagating as an unhandled exception during trigger processing.

### Citations

**File:** formula/evaluation.js (L157-241)
```javascript
		switch (op) {
			case '+':
			case '-':
			case '*':
			case '/':
			case '%':
			case '^':
				var f = '';
				switch (op) {
					case '+':
						f = 'plus';
						break;
					case '-':
						f = 'minus';
						break;
					case '*':
						f = 'times';
						break;
					case '/':
						f = 'div';
						break;
					case '%':
						f = 'mod';
						break;
					case '^':
						f = 'pow';
						break;
				}
				var prevV;
				async.eachSeries(arr.slice(1), function (param, cb2) {
					evaluate(param, function (res) {
						if (fatal_error)
							return cb2(fatal_error);
						if (res instanceof wrappedObject)
							res = true;
						if (typeof res === 'boolean')
							res = res ? dec1 : dec0;
						else if (typeof res === 'string' && (!constants.bTestnet || mci > testnetStringToNumberInArithmeticUpgradeMci)) {
							var float = string_utils.toNumber(res, bLimitedPrecision);
							if (float !== null)
								res = createDecimal(res);
						}
						if (isFiniteDecimal(res)) {
							res = toDoubleRange(res);
							if (prevV === undefined) {
								prevV = res;
							} else {
								if (f === 'pow'){
									if (prevV.eq(decimalE)){ // natural exponential
										console.log('e^x');
										prevV = res.exp();
										return cb2();
									}
									if (res.abs().gte(Number.MAX_SAFE_INTEGER))
										return setFatalError('too large exponent ' + res, { arr }, undefined, cb2);
									if (res.isInteger()) {
										prevV = prevV.pow(res);
										return cb2();
									}
									// sqrt-pow2 would be less accurate
								//	var res2 = res.times(2);
								//	if (res2.isInteger() && res2.abs().lt(Number.MAX_SAFE_INTEGER)) {
								//		prevV = prevV.sqrt().pow(res2);
								//		return cb2();
								//	}
									// else fractional power.  Don't use decimal's pow as it might try to increase the precision of the intermediary result only by 15 digits, not infinitely.  Instead, round the intermediary result to our precision to get a reproducible precision loss
									prevV = toDoubleRange(toDoubleRange(prevV.ln()).times(res)).exp();
									return cb2();
								}
								prevV = prevV[f](res);
							}
							cb2();
						} else {
							return setFatalError('not a decimal in '+op+': '+ res, { arr }, undefined, cb2);
						}

					});
				}, function (err) {
					if (err)
						return cb(false);
					if (!isFiniteDecimal(prevV))
						return setFatalError('not finite in '+op, { arr }, false, cb);
					cb(toDoubleRange(prevV));
				});
				break;
```

**File:** formula/evaluation.js (L243-268)
```javascript
			case 'sqrt':
			case 'ln':
			case 'abs':
				evaluate(arr[1], function (res) {
					if (fatal_error)
						return cb(false);
					if (res instanceof wrappedObject)
						res = true;
					if (typeof res === 'boolean')
						res = res ? dec1 : dec0;
					else if (typeof res === 'string') {
						var float = string_utils.toNumber(res, bLimitedPrecision);
						if (float !== null)
							res = createDecimal(res);
					}
					if (isFiniteDecimal(res)) {
						if (op === 'abs')
							return cb(toDoubleRange(res.abs()));
						if (res.isNegative())
							return setFatalError(op + " of negative", { arr }, false, cb);
						evaluate(toDoubleRange(op === 'sqrt' ? res.sqrt() : res.ln()), cb);
					} else {
						return setFatalError('not a decimal in '+op, { arr }, false, cb);
					}
				});
				break;
```

**File:** aa_composer.js (L618-654)
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
```

**File:** aa_composer.js (L1431-1463)
```javascript
	function executeStateUpdateFormula(objResponseUnit, cb) {
		if (bBouncing)
			return cb();
		if (!objStateUpdate) {
			const rv_len = getResponseVarsLength();
			if (rv_len > constants.MAX_RESPONSE_VARS_LENGTH)
				return cb(`response vars too long: ${rv_len}`);
			return cb();
		}
		var opts = {
			conn: conn,
			formula: objStateUpdate.formula,
			trigger: trigger,
			params: params,
			locals: objStateUpdate.locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStateVarAssignmentAllowed: true,
			bStatementsOnly: true,
			objValidationState: objValidationState,
			address: address,
			objResponseUnit: objResponseUnit
		};
		formulaParser.evaluate(opts, [], objStateUpdate.xpath, function (err, res) {
		//	console.log('--- state update formula', objStateUpdate.formula, '=', res);
			if (res === null)
				return cb(err.formattedError || "formula " + objStateUpdate.formula + " failed: "+err);
			const rv_len = getResponseVarsLength();
			if (rv_len > constants.MAX_RESPONSE_VARS_LENGTH)
				return cb(`response vars too long: ${rv_len}`);
			cb();
		});
	}
```

**File:** formula/validation.js (L298-314)
```javascript
		switch (op) {
			case '+':
			case '-':
			case '*':
			case '/':
			case '%':
			case '^':
				if (op === '^')
					complexity++;
				async.eachSeries(arr.slice(1), function (param, cb2) {
					if (typeof param === 'string') {
						cb2("arithmetic operation " + op + " with a string: " + param);
					} else {
						evaluate(param, cb2);
					}
				}, cb);
				break;
```
