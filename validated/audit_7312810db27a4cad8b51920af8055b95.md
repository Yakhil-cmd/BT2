### Title
AA formula evaluator can throw an uncaught exception on `base ^ fractional_exponent` with a negative base, crashing unit validation - ([File: formula/evaluation.js])

### Summary
The bug report describes `AMMGovernance.sol` failing to bound-check `emaAlpha` before feeding it into a logarithm calculation, allowing an out-of-range/negative value to reach `wln()`. The analogous root cause exists in ocore's formula evaluator: the `^` (power) operator's fractional-exponent branch calls `.ln()` on the base without first validating that the base is non-negative, even though the sibling `ln`/`sqrt` operators explicitly guard against negative inputs.

### Finding Description
In `formula/evaluation.js`, the `ln` and `sqrt` operators explicitly check for a negative operand and gracefully fail via `setFatalError` instead of calling the underlying decimal function: [1](#0-0) 

However, in the `^` operator's fractional-exponent branch (reached whenever the exponent is not an integer and the base is not Euler's number `e`), the code computes the fractional power as `exp(exponent * ln(base))` and calls `.ln()` directly on `prevV` (the base) with **no equivalent negativity check**: [2](#0-1) 

`Decimal.prototype.ln()` (decimal.js) throws a `DecimalError` for non-positive arguments rather than returning `NaN`. Unlike every other error path in this switch (which uses `setFatalError` to fail the formula gracefully and return `false`/`null` to the caller), this call site has no `try/catch` and no upfront guard, so the thrown error propagates as an uncaught exception out of `evaluate()`.

### Impact Explanation
Formula evaluation is invoked deterministically by every full node processing AA triggers (`formula/evaluation.js` is the shared oscript/AA formula interpreter). Any AA definition that contains an expression of the form `x ^ y` where `x` can become negative and `y` can become a non-integer (e.g., values derived from trigger data, state vars, or data-feed values under attacker influence) will trigger this code path identically on every node. Because the exception is unhandled at this call site (unlike the guarded `ln`/`sqrt` cases), it can crash or corrupt the node process handling unit/AA validation instead of failing the formula cleanly, which is a stronger consequence than the reported bug's "out-of-bounds emaAlpha" (which merely produced a bad numeric result). If nodes disagree on how this exception is handled (crash vs. surviving via some outer catch), this can lead to consensus divergence on unit validity/stability, or a broad denial of service preventing the network from confirming units that trigger the affected AA.

### Likelihood Explanation
Any unprivileged address can author an AA (or interact with a pre-existing AA) that performs a `^` operation where the base can be driven negative and the exponent can be made fractional using ordinary AA formula constructs (arithmetic on trigger data, state vars, or data feeds — all attacker/trigger-sender-influenceable inputs). No special privilege beyond normal AA authoring and posting a trigger unit is required, making this a directly reachable, low-barrier trigger path.

### Recommendation
Add the same guard used for the `ln`/`sqrt` operators to the fractional-power branch of `^`: before computing `prevV.ln()`, check `prevV.isNegative()` (or `prevV.lte(0)`) and, if true, call `setFatalError('fractional power of non-positive base', { arr }, undefined, cb2)` instead of invoking `.ln()`. This mirrors the existing negative-input handling pattern at `formula/evaluation.js:261-262` and ensures all numeric edge cases fail gracefully through the formula's controlled error path rather than throwing an uncaught exception.

### Proof of Concept
An AA (or oscript-evaluated address definition, post `formulaUpgradeMci`) containing a formula such as:
```
$base = -4;
$exp = 0.5;
$result = $base ^ $exp;
```
where `$base` is derived from trigger data controlled by an unprivileged trigger sender (e.g., `trigger.data.base`) and `$exp` is a non-integer, causes evaluation to reach the branch at `formula/evaluation.js:223` (`prevV.ln()`) with a negative `prevV`, which is not screened the way `ln($base)` would be at `formula/evaluation.js:261-263`, exercising the unguarded exception path during standard AA trigger processing.

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

**File:** formula/evaluation.js (L258-263)
```javascript
					if (isFiniteDecimal(res)) {
						if (op === 'abs')
							return cb(toDoubleRange(res.abs()));
						if (res.isNegative())
							return setFatalError(op + " of negative", { arr }, false, cb);
						evaluate(toDoubleRange(op === 'sqrt' ? res.sqrt() : res.ln()), cb);
```
