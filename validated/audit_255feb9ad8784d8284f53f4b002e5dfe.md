## Title
Missing validation that `at_least <= at_most` (and `amount_at_least <= amount_at_most`) in address/asset spending-condition filters allows permanently unsatisfiable conditions - (File: definition.js)

### Summary
`definition.js`'s `validateDefinition()` validates the `sum` operator's `at_least`/`at_most` fields, and `getFilterError()` validates `amount_at_least`/`amount_at_most` fields used by `has`, `has one`, and `seen`. In both cases each bound is checked to be a positive integer independently, but there is no check that the lower bound does not exceed the upper bound, mirroring the `minimumDelay`/`maximumDelay` bug pattern in the external report.

### Finding Description
In `getFilterError()`, `amount_at_least` and `amount_at_most` are each validated to be positive integers, and the code only rejects combining them with `amount`, never comparing them to each other: [1](#0-0) 

Likewise, for the `sum` operator, `at_least` and `at_most` can both be specified together (only `equals` is mutually exclusive with them), and each is checked independently for being a positive integer, with no cross-check: [2](#0-1) 

At authentication/evaluation time, the `sum` condition is evaluated by summing matching inputs/outputs and independently comparing against `at_least` and `at_most`: [3](#0-2) 

The `amount_at_least`/`amount_at_most` filter fields are similarly applied independently when matching payment inputs/outputs in `evaluateFilter()`: [4](#0-3) 

If a definer sets `at_least` (or `amount_at_least`) strictly greater than `at_most` (or `amount_at_most`), the resulting boolean condition `sum >= at_least AND sum <= at_most` (or the equivalent for filtered inputs/outputs) becomes mathematically impossible to satisfy for any spend, since no value can simultaneously be `>= at_least` and `<= at_most` when `at_least > at_most`. This passes `validateDefinition()` without error because the code never compares the two bounds against each other — exactly the class of bug described in the external report (two related threshold variables validated independently but never against each other).

### Impact Explanation
An address (including AA-controlled spending/escrow addresses that embed user- or trigger-data-driven definitions) whose definition contains a `sum`/`has`/`seen` branch with `at_least > at_most` (or `amount_at_least > amount_at_most`) can end up with a spending branch that can never be satisfied. If this is the only viable spending path (e.g., in a single-branch definition or the only currently-satisfiable branch of an `and`/`or` tree), funds locked under that address become permanently unspendable — a fund-freezing condition. This is especially relevant for AA-authored/templated definitions where the bounds may be derived from formulas or `trigger.data`, meaning a poorly-bounded template (or a trigger sender supplying data reaching an unchecked formula-derived bound) can freeze funds without any explicit error being raised at definition-validation time.

### Likelihood Explanation
Likelihood is moderate: this requires a specific, likely accidental (or induced via templated/formula-driven bounds) misconfiguration of a definition by the address's own definer. It is not directly triggerable by an unrelated third party against an existing address, but the validation layer that is supposed to catch invalid/impossible definitions silently accepts an unsatisfiable condition, which is the exact class of defect flagged in the report.

### Recommendation
In `getFilterError()`, add a check that if both `amount_at_least` and `amount_at_most` are present, `amount_at_least <= amount_at_most`, returning an error such as "amount_at_least must not exceed amount_at_most" otherwise. Similarly, in the `sum` case validation, add a check that if both `at_least` and `at_most` are present, `at_least <= at_most`, returning an error such as "at_least must not exceed at_most" otherwise.

### Proof of Concept
1. Construct an address definition using the `sum` operator with `{filter: {what: "output", asset: "base"}, at_least: 1000, at_most: 100}`.
2. Submit this definition via `validateDefinition()` (e.g., as part of a new address definition or definition change) — validation succeeds because each bound is checked independently for being a positive integer (`definition.js` lines 577-586), and no cross-check exists.
3. Attempt to spend from this address using the `sum` condition as the (sole) authentication path: any output sum simultaneously satisfying `sum >= 1000` and `sum <= 100` is impossible, so the branch can never authenticate a spend (`definition.js` lines 1168-1174), permanently freezing funds controlled by that condition.

### Citations

**File:** definition.js (L68-76)
```javascript
		if ("amount" in filter && !isPositiveInteger(filter.amount))
			return "amount must be positive int";
		if ("amount_at_least" in filter && !isPositiveInteger(filter.amount_at_least))
			return "amount_at_least must be positive int";
		if ("amount_at_most" in filter && !isPositiveInteger(filter.amount_at_most))
			return "amount_at_most must be positive int";
		if (filter.amount && (filter.amount_at_least || filter.amount_at_most))
			return "can't have amount and amount_at_least/most at the same time";
		return null;
```

**File:** definition.js (L577-586)
```javascript
				if ("equals" in args && !isNonnegativeInteger(args.equals))
					return cb("equals must be nonnegative int");
				if ("at_least" in args && !isPositiveInteger(args.at_least))
					return cb("at_least must be positive int");
				if ("at_most" in args && !isPositiveInteger(args.at_most))
					return cb("at_most must be positive int");
				if ("equals" in args && ("at_least" in args || "at_most" in args))
					return cb("can't have equals and at_least/at_most at the same time")
				if (!("equals" in args) && !("at_least" in args) && !("at_most" in args))
					return cb("at least one of equals, at_least, at_most must be specified");
```

**File:** definition.js (L1168-1174)
```javascript
						if (typeof args.equals === "number")
							return cb2(sum === args.equals);
						if (typeof args.at_least === "number" && sum < args.at_least)
							return cb2(false);
						if (typeof args.at_most === "number" && sum > args.at_most)
							return cb2(false);
						cb2(true);
```

**File:** definition.js (L1327-1332)
```javascript
					if (filter.amount && augmented_input.amount !== filter.amount)
						continue;
					if (filter.amount_at_least && augmented_input.amount < filter.amount_at_least)
						continue;
					if (filter.amount_at_most && augmented_input.amount > filter.amount_at_most)
						continue;
```
