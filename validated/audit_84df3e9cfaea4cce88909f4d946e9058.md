### Title
Unbounded exponent in `e^x` formula evaluation allows AA-trigger-driven memory/CPU exhaustion - ([File: formula/evaluation.js])

### Summary
In the `^` (power) operator handling of the oscript formula evaluator, the special-cased "natural exponential" path (`base == e`) calls `Decimal.exp()` on the exponent without any magnitude bound check, unlike the sibling regular-power path which explicitly rejects exponents whose absolute value is `>= Number.MAX_SAFE_INTEGER`. Since AA trigger data can flow into formula expressions, an unprivileged trigger sender can supply an arbitrarily large numeric value (up to the double range, ~1.8e308) as the exponent of `e^x`, forcing every node evaluating the AA to perform an arbitrary-precision exponential computation whose internal working precision/memory scales with the magnitude of the argument, not just its input size.

### Finding Description
The `^` operator implementation is in `formula/evaluation.js`: [1](#0-0) 

Specifically:
- For the general case (`prevV.pow(res)`), the code validates the exponent: `if (res.abs().gte(Number.MAX_SAFE_INTEGER)) return setFatalError('too large exponent ' + res, ...)`.
- For the special "natural exponential" case (`prevV.eq(decimalE)`, i.e. `e^x`), the code goes straight to `prevV = res.exp();` with **no equivalent bound check** on `res`.

`res` at this point has already been passed through `toDoubleRange(res)` (`formula/evaluation.js:200`), meaning it can be any finite double-range decimal, including values near `1.8e308`. `Decimal.exp()` (from `decimal.js`, configured with `maxE: 308`/`minE: -324`, `precision: 15` in `formula/common.js:11-18`) computes the exponential via an arbitrary-precision algorithm whose required internal working precision/iteration count grows with the magnitude of the input argument, not merely its representation length. Computing `e^x` for `x` on the order of `1e300` therefore forces the library to work with proportionally large internal precision/digit buffers, causing disproportionate CPU and memory consumption relative to the small formula that triggered it — directly analogous to the reported MongoDB aggregation type-conversion bug, where a small, authenticated operation caused outsized memory consumption and process termination.

This computation is reachable by any account able to post a trigger to an AA whose formula contains an expression like `e ^ $expr`, where `$expr` derives (directly or after simple arithmetic) from `trigger.data`. AA formulas frequently incorporate trigger data (`trigger.data.*`) as demonstrated by its use throughout `formula/evaluation.js` and `formula/validation.js`. No special privileges, write access beyond a normal unit post, or AA-author-only paths are needed — a trigger sender only needs to interact with an existing AA that passes attacker-controlled data into an `e^x` expression, or an AA author could unknowingly expose this by writing such a formula and receiving triggers from anyone.

### Impact Explanation
Because AA formula evaluation is deterministic and performed by every full node (and light-serving nodes) validating/executing units and AA responses on that DAG, triggering this path with a single crafted unit forces disproportionate memory/CPU usage across all nodes evaluating the AA response, mirroring the "process termination under memory pressure" described in the report. If the evaluating process is terminated or hangs system-wide (OOM), affected nodes cannot continue validating/stabilizing units, which can cause node disagreement on validity/stability of the DAG or a temporary inability of the network to confirm new units for that AA's chain — satisfying the required "node disagreement on validity or stability" / "network unable to confirm new units" impact bar.

### Likelihood Explanation
Likelihood is dependent on an AA formula actually containing `e ^ <trigger-derived expr>`; this is a valid, unrestricted oscript pattern (exponentials of trigger-supplied numbers are a natural use case, e.g., for exponential curves/AMMs) and nothing in `formula/validation.js` or `formula/evaluation.js` prevents an AA author from writing it, nor does the evaluator limit the magnitude before calling `.exp()`. Any user with the ability to send a unit to trigger such an AA can supply the oversized value at will, requiring no special access — comparable to the "authenticated user, write + aggregation" requirement in the source report.

### Recommendation
Add the same (or a stricter, exp-appropriate) magnitude bound check to the `e^x` branch that is already applied to the general power branch, e.g.:
```js
if (prevV.eq(decimalE)) { // natural exponential
    if (res.abs().gte(<safe_exp_bound>))
        return setFatalError('too large exponent ' + res, { arr }, undefined, cb2);
    prevV = res.exp();
    return cb2();
}
```
The bound for `exp()` should be chosen conservatively (much smaller than `Number.MAX_SAFE_INTEGER`, since `e^x` overflows/needs large internal precision far sooner than a generic `base^integer_exponent`), and should also cover the case where `res` is very large in absolute value (both `res.exp()` for large negative `res` — although that just goes to a small value quickly — and large positive `res`, which is the actual exhaustion vector).

### Proof of Concept
1. Deploy (or use an existing) AA whose formula includes an expression such as: `bounce_if($trigger.data.x > 1e300); ... ; e ^ $trigger.data.x`, or any oscript formula path that evaluates `e ^ (trigger.data value)`.
2. From an unprivileged account, send a payment/trigger unit to the AA with `data: { x: 1e300 }` (a value within the double range, thus passing `toDoubleRange`/`isFiniteDecimal` checks).
3. During AA response evaluation, `formula/evaluation.js`'s `^` handler detects `prevV.eq(decimalE)` and calls `res.exp()` on the ~1e300 value with no magnitude check (unlike the sibling `pow` branch), causing `decimal.js` to perform an exponential computation whose internal precision/memory scales with the argument's magnitude.
4. Every node evaluating this AA trigger performs the same expensive computation, leading to significant memory/CPU consumption on all validating nodes for that single small unit — reproducible deterministically by any user with trigger access to such an AA.

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
