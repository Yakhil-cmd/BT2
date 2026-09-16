### Title
Unchecked `at_least > at_most` (and `amount_at_least > amount_at_most`) in address/asset spending-condition definitions permanently locks funds - (File: definition.js)

### Summary
`validateDefinition()` in `definition.js` validates the `sum` operator's `at_least`/`at_most` fields (and the `amount_at_least`/`amount_at_most` fields used by `has`, `has one`, and `seen`) only for individual type/positivity, but never checks that `at_least <= at_most` (or `amount_at_least <= amount_at_most`). This mirrors the reported class of bug: two boundary parameters are validated independently but their mutual ordering invariant is never enforced, so a syntactically "valid" definition can encode a logically impossible (permanently unsatisfiable) condition.

### Finding Description
When validating a `sum` condition inside an address or asset spending-condition definition, `getFilterError` only checks that `at_least`/`at_most` are individually positive integers, and that `equals` is not combined with them: [1](#0-0) 

There is no cross-check that `args.at_least <= args.at_most`. The same missing cross-check exists for the `amount_at_least`/`amount_at_most` pair used by `has`, `has one`, and `seen` filters: [2](#0-1) 

At authentication time, the `sum` operator is evaluated by summing matching inputs/outputs and separately comparing against `at_least` and `at_most`: [3](#0-2) 

If `at_least > at_most` (e.g., `at_least: 1000000, at_most: 100`), the condition `sum >= at_least AND sum <= at_most` can never be satisfied by any value of `sum`, because both branches are checked independently and there is no value that is simultaneously `>= 1000000` and `<= 100`. The identical logic applies to `amount_at_least`/`amount_at_most` filters evaluated in `evaluateFilter`: [4](#0-3) 

Any single unprivileged unit author who controls (or co-designs) an address definition — e.g., a shared/escrow/multisig address, or a private-payment counterparty address — can embed such a self-contradictory `sum`/`has`/`seen` spending clause. The definition passes `validateDefinition()` without error because each bound is checked in isolation.

### Impact Explanation
Once funds are sent to an address whose spending-authorization branch requires satisfying an impossible `sum`/`amount_at_least`/`amount_at_most` range, no unit can ever be validly signed to release them via that branch: `validateAuthentifiers()` will always evaluate the `sum`/`has`/`seen` condition to `false` for every possible spend amount. If this is the only (or last remaining) branch of an `or`/`and` definition available to a counterparty (e.g., in an escrow-style shared address where one party controls the "good path" and the other only has this pathological fallback), those funds become permanently frozen — a fund-freezing outcome analogous to the referenced report's protocol-disruption impact.

### Likelihood Explanation
Likelihood is moderate: this requires a party (potentially adversarial in a multi-party address or asset condition setup) to craft the definition with inconsistent bounds, and a counterparty to accept/fund that address without independently verifying the logical satisfiability of the condition. Since `ocore` performs no automatic sanity check, nothing in the network prevents such a definition from being posted and accepted as valid.

### Recommendation
In `getFilterError()` and in the `sum` case of `validateDefinition()` (`definition.js`), add an explicit cross-field check:
- Reject filters where `filter.amount_at_least` and `filter.amount_at_most` are both present and `amount_at_least > amount_at_most`.
- Reject `sum` conditions where both `at_least` and `at_most` are present and `at_least > at_most`.

### Proof of Concept
1. Construct an address definition containing a branch such as:
```json
["sum", {"filter": {"what": "output", "asset": "base"}, "at_least": 1000000, "at_most": 100}]
```
2. Submit this as part of a valid (or the sole) branch of an address definition; `validateDefinition()` accepts it because `at_least` and `at_most` are each individually positive integers (`definition.js:579-582`).
3. Fund the resulting address.
4. Attempt to spend using this branch: for any output sum, either `sum < at_least` or `sum > at_most` holds per `definition.js:1170-1173`, so the branch never authenticates, permanently freezing the funds allocated to that spending path.

### Citations

**File:** definition.js (L68-75)
```javascript
		if ("amount" in filter && !isPositiveInteger(filter.amount))
			return "amount must be positive int";
		if ("amount_at_least" in filter && !isPositiveInteger(filter.amount_at_least))
			return "amount_at_least must be positive int";
		if ("amount_at_most" in filter && !isPositiveInteger(filter.amount_at_most))
			return "amount_at_most must be positive int";
		if (filter.amount && (filter.amount_at_least || filter.amount_at_most))
			return "can't have amount and amount_at_least/most at the same time";
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
