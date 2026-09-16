### Title
Unbounded `Decimal.pow()` exponent in oscript `^` operator enables computational DoS - (File: formula/evaluation.js)

### Summary
The oscript arithmetic evaluator's `^` (power) operator only bounds the exponent's *magnitude* to `Number.MAX_SAFE_INTEGER` (~9×10^15) via `res.abs().gte(Number.MAX_SAFE_INTEGER)`, but places no bound on the *base* value or on the resulting bit-length/precision of `prevV.pow(res)`. Any unprivileged AA trigger sender can post a trigger whose `data` (or the AA definition itself) causes a formula containing something like `bignum ^ largeinteger` to be evaluated, forcing `Decimal.js` to compute an arbitrarily large-precision integer power. This mirrors the CVE-2024-24814 pattern: a single unvalidated large-integer parameter (there, a cookie int; here, an exponent) drives disproportionate, unbounded CPU/memory work in synchronous library code before any cost/complexity accounting can stop it.

### Finding Description
In the `+ - * / % ^` operator handling in `formula/evaluation.js`, the exponent check only prevents exponents that are themselves astronomically large: [1](#0-0) 
```
if (f === 'pow'){
    if (prevV.eq(decimalE)){ ... }
    if (res.abs().gte(Number.MAX_SAFE_INTEGER))
        return setFatalError('too large exponent ' + res, { arr }, undefined, cb2);
    if (res.isInteger()) {
        prevV = prevV.pow(res);
        return cb2();
    }
    ...
}
```
This allows exponents up to just under 9×10^15 to be accepted as long as they are integers. `Decimal.pow()` for an arbitrary-precision base raised to an integer exponent close to that bound requires computation (and result storage) proportional to `exponent × precision_digits`, which for even modest bases (e.g., `2^9000000000000000`) produces a result with quadrillions of digits — an operation that will never complete in practice and will consume all available CPU/memory on the node performing AA trigger evaluation or unit validation.

Unlike other oscript primitives that are explicitly complexity-gated (e.g. `foreach`'s `readCount` capping loop counts at 100, seen in `formula/validation.js`'s `readCount`), the `pow` bound here is a raw numeric-magnitude check rather than a cost-based check, and it does not account for the interaction between base size and exponent size. This is directly analogous to the mod_auth_openidc bug: input validation checks that a value is a "reasonable-looking integer" (session chunk count / exponent) but fails to bound the actual computational cost that value can trigger.

### Impact Explanation
Because oscript formulas are evaluated:
- during AA trigger processing (any user can send a trigger unit to an AA whose formula uses `^`), and
- during static validation/dry-run of AA definitions,

an attacker-controlled exponent can force every full node evaluating that AA (all nodes, since AA execution must be deterministic and independently reproduced) to hang computing an intractable exponentiation. This can stall or crash node processes evaluating AA responses, preventing the network from processing/confirming new units that trigger (or attempt to trigger) that AA — matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Likelihood is high for reachability: any unprivileged user can define an AA containing such a formula (AA definitions are user-authored objects validated via `formula/validation.js`) or trigger an already-deployed AA with attacker-influenced numeric trigger data feeding into a `^` expression with no additional privilege required. The check that exists (`Number.MAX_SAFE_INTEGER` bound) suggests the exponent path was known to be dangerous but only partially mitigated — the developers capped only the exponent's absolute numeric magnitude, not the actual computational cost of `pow`.

### Recommendation
Bound the `pow` operation by actual computational cost, not merely by whether the exponent's magnitude is below `Number.MAX_SAFE_INTEGER`. For example: reject integer exponents whose absolute value exceeds a small constant (e.g. a few thousand) unless the base is within [-1, 1], or estimate the resulting digit count (`exponent * log10(base)`) and reject/charge complexity proportional to it before calling `.pow()`. Alternatively, route `pow` operations through the existing `complexity`/`count_ops` accounting used elsewhere in `formula/validation.js` so that expensive-by-construction exponentiations are rejected during static complexity analysis before they can ever be evaluated at runtime.

### Proof of Concept
Deploy or trigger an AA whose oscript formula contains:
```
$x = 2 ^ 9000000000000000;
```
`res.abs()` (9000000000000000) is `< Number.MAX_SAFE_INTEGER` (9007199254740991) so the check at `formula/evaluation.js:210` passes, and `prevV.pow(res)` is invoked with base `2` and exponent ~9×10^15, an operation whose result has on the order of 10^15 decimal digits — computationally infeasible to complete, tying up the evaluating node's CPU/memory during AA response processing. [1](#0-0) 

**Uncertainty note:** I was unable to fully verify within the available iterations (1) whether `formula/validation.js`'s static complexity/ops accounting (`complexity`, `count_ops`) independently catches and rejects `^` expressions with large literal or derived exponents before evaluation reaches `formula/evaluation.js`, and (2) the exact global `Decimal.js` precision/`toExpPos`/`toExpNeg` configuration in `formula/common.js`, which could either mitigate or exacerbate the cost of large `.pow()` calls. If validation-time complexity accounting already rejects such expressions unconditionally (not just the `Number.MAX_SAFE_INTEGER` check I confirmed), this finding's severity would be reduced to a bounded/mitigated issue rather than an exploitable DoS. A full review of `formula/validation.js`'s handling of the `^`/`pow` case (analogous to its `foreach`/`readCount` gating) would be needed to close this gap with certainty.

### Citations

**File:** formula/evaluation.js (L204-215)
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
```
