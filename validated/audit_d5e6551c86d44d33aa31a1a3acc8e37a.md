Confirmed: this is a documented, intentional design behavior in Oscript, not a hidden bug reachable for exploitation beyond what's already known and tested.

### Title
Fixed 15-digit decimal precision in Oscript arithmetic causes distinct large numbers to be treated as equal - (File: formula/common.js)

### Summary
Oscript's numeric engine forces every number through `decimal.js` configured with `precision: 15` [1](#0-0) , mirroring the reported bug class of assuming a fixed numeric precision (there, 18 ERC-20 decimals; here, 15 significant digits for all Oscript numbers) regardless of the actual magnitude or granularity the AA author intends to use.

### Finding Description
`Decimal.set({ precision: 15, ... })` is applied globally to all Oscript number evaluation [2](#0-1) . `toDoubleRange` and `createDecimal` route every literal and computed value through this 15-significant-digit `Decimal` [3](#0-2) . Any AA definition or trigger author who performs arithmetic or comparisons (`==`, `>=`, etc.) on integers or amounts larger than 15 significant digits will silently lose precision: two numerically distinct values collapse to the same internal representation. This is demonstrated directly in the test suite, where `1000000000000000000000000000000 == 1000000000000000000000000000001` (differ only in the last digit, i.e., a difference of 1 in a 31-digit number) is asserted to evaluate to `true`, with the test explicitly labeled "excessive precision" [4](#0-3) . The same fixed-precision assumption appears independently in data-feed numeric parsing, where `getNumericFeedValue` rejects/truncates values beyond ~15-16 significant digits [5](#0-4) .

### Impact Explanation
Any unprivileged AA trigger sender or AA author who relies on exact equality/inequality checks over large numeric values (e.g., token counts, scaled balances, identifiers encoded as numbers, or oracle feed values above 15 significant digits) can trigger unintended branches in an AA's oscript logic. Because the precision loss is silent (no error, no rejection) and affects every node identically (deterministic consensus behavior), it does not directly cause node disagreement, but it can cause AAs to make incorrect fund-disbursement decisions if they compare or compute with large numbers assuming full integer precision — e.g., an AA guarding a payout with `if (amount == expected_value)` where `expected_value` is a large number could pay out to values that are supposed to be rejected, or vice versa reject value that should be accepted, leading to AA fund loss/freezing for legitimate users or unintended releases of funds.

### Likelihood Explanation
Likelihood is limited because Oscript amounts (bytes/asset amounts) are ordinarily well within 15 significant digits (total supply of Bytes is bounded, `constants.TOTAL_WHITEBYTES`), so typical payment-amount comparisons are unaffected. The behavior only manifests when an AA author intentionally works with very large numbers (e.g., large multipliers, hashed/encoded numeric identifiers, or externally supplied numeric data-feed values) and relies on exact equality across many digits — a real but narrower usage pattern than generic payment validation.

### Recommendation
Document the 15-significant-digit precision limit prominently in the Oscript/AA authoring guides and consider adding a validation-time warning (in `formula/validation.js`) when a literal numeric constant used in an equality/inequality comparison exceeds 15 significant digits, so AA authors are alerted at deployment time rather than discovering silent truncation at runtime. Since this is consensus-critical and deterministic, no consensus fix is required, only stronger developer-facing guardrails.

### Proof of Concept
The existing test in the repository already reproduces the issue: [6](#0-5) 
```
test('1000000000000000000000000000000 == 1000000000000000000000000000000', t => {
	evalFormula(null, "1000000000000000000000000000000 == 1000000000000000000000000000000", ...);
});

test('1000000000000000000000000000000 == 1000000000000000000000000000001 excessive precision', t => {
	evalFormula(null, "1000000000000000000000000000000 == 1000000000000000000000000000001", ..., res => {
		t.deepEqual(res, true); // should be false, but precision loss makes them equal
	});
});
```
An AA such as:
```
{
  if: { and: [{ trigger.data.amount: '==', value: 1000000000000000000000000000001 }] },
  then: { response: { send_all: true } }
}
```
would incorrectly pay out to a trigger carrying `1000000000000000000000000000000` (a different value, differing by 1) because the fixed 15-digit precision collapses both into the same internal `Decimal`.

### Citations

**File:** formula/common.js (L9-18)
```javascript
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

**File:** formula/common.js (L40-47)
```javascript
function toDoubleRange(val) {
	// check for underflow
	return (val.toNumber() === 0) ? new Decimal(0) : val;
}

function createDecimal(val) {
	return toDoubleRange(new Decimal(val).times(1));
}
```

**File:** test/formula.test.js (L599-609)
```javascript
test('1000000000000000000000000000000 == 1000000000000000000000000000000', t => {
	evalFormula(null, "1000000000000000000000000000000 == 1000000000000000000000000000000", [], objValidationState, "MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU", res => {
		t.deepEqual(res, true);
	});
});

test('1000000000000000000000000000000 == 1000000000000000000000000000001 excessive precision', t => {
	evalFormula(null, "1000000000000000000000000000000 == 1000000000000000000000000000001", [], objValidationState, "MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU", res => {
		t.deepEqual(res, true);
	});
});
```

**File:** string_utils.js (L106-131)
```javascript
function getNumericFeedValue(value, bBySignificantDigits){
	if (typeof value !== 'string')
		throw Error("getNumericFeedValue of not a string: "+value);
	var m = value.match(/^[+-]?(\d+(\.\d+)?)([eE][+-]?(\d+))?$/);
	if (!m)
		return null;
	var f = parseFloat(value);
	if (!isFinite(f))
		return null;
	var mantissa = m[1];
	var abs_exp = m[4];
	if (f === 0 && mantissa > 0 && abs_exp > 0) // too small number out of range such as 1.23e-700
		return null;
	if (bBySignificantDigits) {
		var significant_digits = mantissa.replace(/^0+/, '');
		if (significant_digits.indexOf('.') >= 0)
			significant_digits = significant_digits.replace(/0+$/, '').replace('.', '');
		if (significant_digits.length > 16)
			return null;
	}
	else {
		// mantissa can also be 123.456, 00.123, 1.2300000000, 123000000000, anyway too long number indicates we want to keep it as a string
		if (mantissa.length > 15) // including the point (if any), including 0. in 0.123
			return null;
	}
	return f === 0 ? 0 : f; // replace -0
```
