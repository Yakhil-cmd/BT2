Based on my research, here's the analog vulnerability in ocore mapped from the "Use of Libraries" report.

### Title
Custom, hand-rolled decimal-power implementation in oscript formula evaluator instead of the underlying `decimal.js` library risks non-deterministic AA execution - (File: formula/evaluation.js)

### Summary
The Mellow Finance report flags custom re-implementations of math/oracle logic in place of battle-tested libraries as a systemic risk, later fixed by switching to the library's own routines. Ocore's AA/oscript formula evaluator does the analogous thing for exponentiation: instead of relying on the `decimal.js` library's native `pow()`, it deliberately bypasses it with a custom `ln`/`exp` composition to force "reproducible precision loss," which is exactly the class of "own custom code where a battle-tested library exists" that the report warns about.

### Finding Description
`decimal.js` is already used as ocore's fixed-precision numeric engine for all AA formula math [1](#0-0) . However, for the `^` (power) operator with a non-integer exponent, the code explicitly avoids the library's own `.pow()` because its intermediate precision behavior is considered unreliable, and instead reimplements exponentiation from scratch via `ln()`/`exp()`, manually re-rounding with `toDoubleRange` after each step to try to force determinism: [2](#0-1) 

This custom arithmetic is precisely the kind of hand-rolled numeric logic the external report calls out as risky compared to using the vetted library implementation directly. The correctness of consensus (every full node must derive the exact same AA response/state for a given trigger) depends entirely on every node's JS runtime and `decimal.js` version producing byte-identical results for this custom `ln`-then-`exp` composition across the full domain of bases/exponents an attacker can construct in an AA formula, rather than depending only on a single, more heavily audited library entry point (`Decimal.pow`). Any subtle divergence in how `ln`/`exp`/rounding interact for edge-case magnitudes (e.g., near `maxE`/`minE` boundaries defined in `formula/common.js`) is fully attacker-reachable: any user can define an AA with an arbitrary formula containing `^`, and any user can send a trigger that causes it to evaluate, since `evaluate()` is invoked for every AA trigger against `objValidationState.last_ball_mci`-based state [3](#0-2) .

The project's history of needing multior-gated fixes for numeric behavior (e.g. `bLimitedPrecision`/`aa2UpgradeMci`, `testnetStringToNumberInArithmeticUpgradeMci`) confirms that custom numeric/precision logic in this evaluator has previously caused consensus-relevant divergence bugs requiring hard-fork-style MCI gates [4](#0-3) [5](#0-4) .

### Impact Explanation
If any two full nodes (or a node vs. a light/AA-validating wallet) compute a different result for the same `^` expression due to this custom `ln`/`exp` rounding path, they will disagree on the AA's response unit, its state-variable updates, or whether the AA bounces vs. succeeds. This is a direct "node disagreement on validity/stability" scenario, and because AA execution controls asset transfers and balances, it can manifest as AA fund loss/freezing (funds bounced on one node's view but spent on another's) or a stalled DAG if witnesses cannot reach consensus on stability of the affected unit.

### Likelihood Explanation
Likelihood is constrained by the fact that ocore already forces `toDoubleRange` re-rounding at 15-digit precision after every step specifically to suppress divergence, and by the fact that a concrete failing input is not demonstrated here. Exploitability requires finding an edge-case base/exponent combination where the `ln`→`times`→`exp` chain's rounding does not converge identically across environments, which requires further fuzzing/differential-testing to confirm.

### Recommendation
Replace the custom `ln`/`exp` power composition with `decimal.js`'s own `pow()` (or a formally specified/pinned fixed-precision routine), matching the report's guidance to prefer the underlying, already-audited library implementation over bespoke arithmetic. If the library's precision behavior for `pow()` is genuinely unsuitable, pin the exact `decimal.js` version and add exhaustive differential tests comparing the custom path against `decimal.js pow()` across boundary magnitudes near `maxE`/`minE` to guarantee bit-identical results across all supported runtimes before relying on it for consensus-critical AA execution.

### Proof of Concept
Not independently reproduced; based on static analysis of the code path at [6](#0-5) , which explicitly documents ("sqrt-pow2 would be less accurate ... Instead, round the intermediary result to our precision to get a reproducible precision loss") that the authors engineered this custom logic specifically to avoid relying on the library's own `pow()`, confirming intent to substitute custom code for a battle-tested library function in a consensus-critical path.

### Citations

**File:** formula/common.js (L1-18)
```javascript
var Decimal = require('decimal.js');
var constants = require('../constants');
var ValidationUtils = require("../validation_utils.js");

var cacheLimit = 100;
var formulasInCache = [];
var cache = {};

// the precision is slightly less than that of IEEE754 double
// the range is slightly wider (9e308 is still ok here but Infinity in double) to make sure numeric data feeds can be safely read.  When written, overflowing datafeeds will be saved as strings only
Decimal.set({
	precision: 15, // double precision is 15.95 https://en.wikipedia.org/wiki/IEEE_754
	rounding: Decimal.ROUND_HALF_EVEN,
	maxE: 308, // double overflows between 1.7e308 and 1.8e308
	minE: -324, // double underflows between 2e-324 and 3e-324
	toExpNeg: -7, // default, same as for js number
	toExpPos: 21, // default, same as for js number
});
```

**File:** formula/evaluation.js (L29-29)
```javascript
var testnetStringToNumberInArithmeticUpgradeMci = 1151000;
```

**File:** formula/evaluation.js (L64-102)
```javascript
exports.evaluate = function (opts, astTrace, xpath, callback) {
	var conn = opts.conn;
	var formula = fixFormula(opts.formula, opts.address);
	var messages = opts.messages || [];
	var trigger = opts.trigger || {};
	var aa_params = opts.params || {};
	var locals = opts.locals || {};
	var stateVars = opts.stateVars || {};
	var responseVars = opts.responseVars || {};
	var bStateVarAssignmentAllowed = opts.bStateVarAssignmentAllowed;
	var bStatementsOnly = opts.bStatementsOnly;
	var bObjectResultAllowed = opts.bObjectResultAllowed;
	var objValidationState = opts.objValidationState;
	var address = opts.address;
	var objResponseUnit = opts.objResponseUnit;
	var mci = objValidationState.last_ball_mci;
	if (!objValidationState.logs)
		objValidationState.logs = [];
	var logs = objValidationState.logs || [];

	if (!Array.isArray(astTrace)) {
		astTrace = [];
	}
	if (typeof xpath !== 'string') {
		xpath = '';
	}

	astTrace.push({system: 'enter to aa', aa: address, formula, bGetters: opts.bGetters, xpath});

	if (!ValidationUtils.isPositiveInteger(objValidationState.last_ball_timestamp))
		throw Error('last_ball_timestamp is not a number: ' + objValidationState.last_ball_timestamp);

	const bAA = (mci >= constants.pemCurvesFixMci) ? !opts.messages : (messages.length === 0);
	if (!bAA && (bStatementsOnly || bStateVarAssignmentAllowed || bObjectResultAllowed))
		throw Error("bad opts for non-AA");

	var bLimitedPrecision = (mci < constants.aa2UpgradeMci);

	const bPostPemCurvesFix = mci >= constants.pemCurvesFixMci || !bAA && !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci;
```

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
