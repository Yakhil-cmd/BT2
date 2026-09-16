Based on my investigation, I found a plausible analog but could not fully verify the exception behavior of `decimal.js`'s `.ln()` on negative operands within this session, so I will state the finding with the caveat clearly marked.

### Title
Unhandled domain error in fractional exponentiation of negative base in AA formula evaluator - (File: formula/evaluation.js)

### Summary
CVE-2017-14520 describes an unguarded floating-point domain operation (image scaling) in Poppler that produces a floating-point exception (crash) when handling attacker-controlled input. The analogous bug class — an unguarded mathematical domain operation reachable from untrusted, attacker-supplied data — appears in `formula/evaluation.js`'s handling of the `^` (power) operator with a fractional exponent, where the base is negative.

### Finding Description
In the arithmetic-operator branch of `evaluate()` in `formula/evaluation.js`, the `pow` case is handled as: [1](#0-0) 
For the fractional-exponent branch, the code computes `prevV.ln()` directly on the base (`prevV`) with no check that `prevV` is non-negative, unlike the sibling unary `ln` operator handler which explicitly guards against negative operands: [2](#0-1) 
This asymmetry means an oscript/AA formula computing something like `(-1) ^ 0.5` (a negative base raised to a non-integer exponent) reaches `prevV.ln()` unguarded. In the `decimal.js` library used here, `ln()` on a negative value is a domain error (analogous to a "floating point exception" in the CVE) and can throw synchronously inside the `async.eachSeries` callback used by `evaluate`.

### Impact Explanation
Because AA trigger/formula evaluation is reachable by any unprivileged unit poster or AA trigger sender (an AA definition's formula, or an attacker-crafted trigger `data` combined with an AA's formula logic, can produce a negative base with fractional exponent), an unhandled/synchronous throw inside the evaluator's callback chain could propagate as an uncaught exception rather than being converted into the expected `setFatalError`/bounce path. If this occurs during unit/AA validation, it can cause inconsistent validation outcomes across nodes (depending on runtime/library behavior) or crash the validating process, which maps to "node disagreement on validity" or "a network unable to confirm new units" if triggered widely.

### Likelihood Explanation
Likelihood is **uncertain/not fully confirmed** in this session — I was unable to verify with certainty (due to tool/iteration limits) whether `decimal.js` throws a catchable exception or instead returns a `NaN`-decimal for `ln()` of a negative number in the exact version used by this repo, nor whether an outer `try/catch` in the AA-composer or unit-validation call chain (`aa_composer.js`, `formula/index.js`) already catches such exceptions before they can crash the process or produce inconsistent results. Without confirming this, the concrete exploitability (crash vs. safely caught fatal error) cannot be established with certainty.

### Recommendation
Add the same negativity guard used in the unary `ln`/`sqrt` handlers to the fractional-exponent branch of the `pow` case — i.e., before calling `prevV.ln()`, check `if (prevV.isNegative()) return setFatalError('pow of negative base with fractional exponent', ...)`. Additionally, verify (via a background Devin session with full repo/test access) whether `decimal.js`'s `ln()` throws for negative inputs and whether that exception is caught anywhere in the `evaluate()` call chain (`formula/index.js`, `aa_composer.js`) before it can affect unit validation or crash a node.

### Proof of Concept
An AA formula such as:
```
$x = -1;
$y = $x ^ 0.5;
```
evaluated via a trigger to that AA, or a similarly-shaped formula in an authentifier (`['formula', ...]`), would hit the `pow` branch with `prevV = -1` (a `Decimal`) and `res = 0.5` (non-integer), reaching `prevV.ln()` without the negativity check present in the sibling `ln` unary operator handler.

**Note on confidence:** This finding is based on static code inspection only; I could not execute the code or confirm the exact runtime behavior of `decimal.js`'s `ln()` for negative inputs, nor trace whether upstream callers already wrap `evaluate()` in a try/catch that neutralizes this into a safe bounce. A Devin session with full codebase and test execution access should verify these two open questions before treating this as confirmed-exploitable.

### Citations

**File:** formula/evaluation.js (L204-224)
```javascript
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
```

**File:** formula/evaluation.js (L258-266)
```javascript
					if (isFiniteDecimal(res)) {
						if (op === 'abs')
							return cb(toDoubleRange(res.abs()));
						if (res.isNegative())
							return setFatalError(op + " of negative", { arr }, false, cb);
						evaluate(toDoubleRange(op === 'sqrt' ? res.sqrt() : res.ln()), cb);
					} else {
						return setFatalError('not a decimal in '+op, { arr }, false, cb);
					}
```
