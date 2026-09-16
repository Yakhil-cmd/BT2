## Title
Unvalidated empty-argument list in `min`/`max`/`hypot` formula evaluation can crash the node process - (File: `formula/evaluation.js`)

### Summary
CVE-2024-8235 is a libvirt crash caused by a refactor that removed an implicit guarantee: a "get list" API could return a zero-length allocation that resolves to `NULL`, and the consuming code dereferenced it without a length/NULL check, crashing `virtinterfaced` for any unprivileged client on the read-only socket. The equivalent bug-class in ocore's Autonomous Agent (AA) oscript engine is a **length check that exists only in the static validator (`formula/validation.js`) but is missing from the corresponding runtime evaluator (`formula/evaluation.js`)** for the `min`/`max`/`hypot` operators, which take a variable-length argument list.

### Finding Description
`formula/validation.js` explicitly guards against a zero-argument call to `min`/`max`/`hypot`: [1](#0-0) 
```
case 'min':
case 'max':
case 'hypot':
    ...
    if (arr[1].length === 0)
        return cb("no arguments of " + op);
```

However, the corresponding runtime execution path in `formula/evaluation.js`, which actually calls into the `decimal.js` library, performs **no such check** before invoking `Decimal[op].apply(Decimal, vals)`: [2](#0-1) 

This mirrors the libvirt pattern exactly: a size/length check was added in one code path (the refactored list-fetching code in libvirt; the static AST validator here) but the corresponding consumer of the same data (`virtinterfaces()` dereferencing the list; `evaluate()` calling `Decimal.min/max/hypot`) was never updated to also defend against the zero-length case. If `arr[1]` (the parsed argument array for `min`/`max`/`hypot`) can ever reach `evaluate()` with `.length === 0` while bypassing or predating the validator's check, the call `Decimal[op].apply(Decimal, [])` is made with an empty array, which is not defended anywhere in the evaluator's `async.eachSeries` completion callback.

### Impact Explanation
If reachable, this would let an AA definition (attacker-controlled oscript, postable by anyone) crash the process evaluating AA formulas (a full node processing AA triggers) via an uncaught exception thrown from `Decimal[op].apply(Decimal, [])`, since the completion callback of `async.eachSeries` at line ~352-357 has no `try/catch` around `Decimal[op].apply`. An uncaught exception in this synchronous callback path would propagate and could crash the node process — denying the network's ability to process AA responses/confirm units, which matches the "network unable to confirm new units" impact bar in the validation rules.

### Likelihood Explanation
This is **speculative and not proven** with the evidence gathered. The AST-level validator in `formula/validation.js` is invoked when an AA is defined (`validateAADefinition` → `validateFormula`), and normally this validation runs before any trigger execution can reach `evaluation.js`'s `evaluate()` for that formula. I could not confirm within the available context:
1. Whether the oscript grammar (`formula/grammars/oscript.ne`) syntactically permits `min()`/`max()`/`hypot()` with zero arguments to be parsed into `arr[1] = []` in the first place (if the grammar requires at least one argument, this bug class is unreachable).
2. Whether there is an mci-gated version skew (i.e., the `arr[1].length === 0` check was added to `validation.js` at some upgrade point without a matching bugfix/backport such that AAs defined before that mci could have been saved with an empty argument list and would only fail at evaluation time going forward).
3. Whether every code path that calls `evaluation.js`'s `evaluate()` for a formula is guaranteed to have first passed `formula/validation.js`'s `evaluate()` for the identical AST node.

Given these open questions, I cannot confirm this analog crosses the "concrete, provable" bar required by the validation rules. It should be treated as a plausible defense-in-depth gap discovered by structural comparison (validator checks a case the evaluator does not), not a demonstrated exploitable crash.

### Recommendation
As a hardening measure (not confirmed exploitable), add the same `arr[1].length === 0` guard to the `min`/`max`/`hypot` case in `formula/evaluation.js` before calling `Decimal[op].apply(Decimal, vals)`, and audit all call sites that invoke `evaluation.js`'s `evaluate()` to confirm the corresponding formula was always successfully validated by `formula/validation.js` first (including AAs saved before any mci-gated introduction of this check). Wrapping `Decimal[op].apply` in a `try/catch` that reports a formula evaluation error instead of throwing would also close this class of gap regardless of reachability.

### Proof of Concept
Not established — a concrete PoC would require confirming (a) that the oscript grammar allows zero-argument `min`/`max`/`hypot` calls to parse, and (b) a code path where such a formula reaches `evaluation.js`'s `evaluate()` without first passing through `formula/validation.js`'s equivalent check (e.g., an AA defined under an older protocol version before the check existed, later executed under upgraded logic). I was not able to verify either condition with the tools available in this session.

### Citations

**File:** formula/validation.js (L337-351)
```javascript
			case 'min':
			case 'max':
			case 'hypot':
				if (op === 'hypot')
					complexity++;
				if (arr[1].length === 0)
					return cb("no arguments of " + op);
				if (arr[1].length > 30 && (mci >= constants.pemCurvesFixMci || require('../storage.js').getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb("too many arguments of " + op);
				async.eachSeries(arr[1], function (param, cb2) {
					if (typeof param === 'string')
						return cb2(op + ' of a string: ' + param);
					evaluate(param, cb2);
				}, cb);
				break;
```

**File:** formula/evaluation.js (L326-358)
```javascript
			case 'min':
			case 'max':
			case 'hypot':
				if (arr[1].length > 30 && bPostPemCurvesFix)
					return setFatalError("too many arguments of " + op, { arr }, false, cb);
				var vals = [];
				async.eachSeries(arr[1], function (param, cb2) {
					evaluate(param, function (res) {
						if (fatal_error)
							return cb2(fatal_error);
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
							vals.push(res);
							cb2();
						} else {
							return setFatalError('not a decimal in '+op, { arr }, undefined, cb2);
						}
					});
				}, function (err) {
					if (err) {
						return cb(false);
					}
					evaluate(Decimal[op].apply(Decimal, vals), cb);
				});
				break;
```
