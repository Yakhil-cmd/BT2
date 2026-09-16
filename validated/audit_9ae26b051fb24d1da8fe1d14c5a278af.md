### Title
Missing validation that `amount_at_least` ≤ `amount_at_most` (and `at_least` ≤ `at_most`) in address/asset spending-condition filters permanently freezes funds - (File: definition.js)

### Summary
`definition.js`'s `getFilterError()` and the `'sum'` condition validator independently bound-check `amount_at_least`/`amount_at_most` (and `at_least`/`at_most`) as positive integers but never verify that the lower bound is not greater than the upper bound, mirroring the reported `setExecutabilityAge` flaw where `_minExecutabilityAge` and `_maxExecutabilityAge` are validated in isolation but never checked against each other.

### Finding Description
`getFilterError()`, used to validate `'has'`, `'has one'`, `'seen'`, and `'has equal'`/`'has one equal'` filter objects inside address/asset definitions, checks: [1](#0-0) 
It validates `amount_at_least` and `amount_at_most` are each positive integers, and that they are not combined with plain `amount`, but never checks `amount_at_least <= amount_at_most`.

The `'sum'` operator validator has the identical gap for `at_least`/`at_most`: [2](#0-1) 

At evaluation time (`validateAuthentifiers`/`evaluateFilter`), the two bounds are applied as independent, unrelated filters: [3](#0-2) 
and for `'sum'`: [4](#0-3) 

If `amount_at_least > amount_at_most` (e.g. `amount_at_least: 1000`, `amount_at_most: 10`), no input/output amount can ever satisfy both conditions simultaneously (`amount >= 1000 AND amount <= 10` is never true), and for `'sum'` no achievable sum can be `>= at_least` and `<= at_most` at once when `at_least > at_most`. This is exactly analogous to `min_x > max_x` producing an unsatisfiable window in the reported `FlatcoinVault.setExecutabilityAge` bug.

### Impact Explanation
Address definitions and asset `transfer_condition`/`issue_condition` trees are authored and posted by any unprivileged address/asset owner. If such a contradictory `amount_at_least`/`amount_at_most` (or `at_least`/`at_most`) pair is embedded as a required branch of an `'and'` condition that must be satisfied to spend from the address or transfer the asset, that branch becomes permanently unsatisfiable — no unit, however constructed, can ever make the filter return true. Where this is the only signing/spending path (or the only path combined with `and`), funds controlled by that definition become permanently frozen, matching the "AA fund loss or freezing" impact category. Because the network performs no sanity check when the definition is created, the mistake is undetectable until spending is attempted and always fails thereafter, with no possibility of correction (definitions are immutable once set/used as the address/asset condition).

### Likelihood Explanation
This requires only a single self-authored address definition or asset definition unit with a `sum`/`has`/`seen` filter where `amount_at_least > amount_at_most` (or `at_least > at_most`). No colluding party, hub, or network condition is needed — any wallet or AA author constructing such a definition through normal usage (e.g., through minor value swaps or automated definition-generation tooling) can trigger irreversible fund lock-up. Given that these numeric bound fields are user-supplied without cross-field validation, the mistake is plausible especially in programmatically generated definitions.

### Recommendation
In `definition.js`, add cross-field validation in `getFilterError()`:
```js
if ("amount_at_least" in filter && "amount_at_most" in filter && filter.amount_at_least > filter.amount_at_most)
    return "amount_at_least must be <= amount_at_most";
```
and in the `'sum'` case validator:
```js
if ("at_least" in args && "at_most" in args && args.at_least > args.at_most)
    return cb("at_least must be <= at_most");
```

### Proof of Concept
1. Author an address definition such as:
```js
["sig", {pubkey: "..."}]
```
replaced/augmented with a required `'and'` branch:
```js
["and", [
  ["sig", {pubkey: "..."}],
  ["seen", {what: "output", asset: "base", amount_at_least: 1000, amount_at_most: 10}]
]]
```
2. `validateDefinition` accepts this definition because `getFilterError` only checks each bound independently (`definition.js` lines 68-76).
3. Once this becomes the address's active definition, any attempt to spend funds requires the `'seen'` condition to be true, but `evaluateFilter`/`augmentMessagesAndEvaluateFilter` (lines 1327-1332) can never find an output with `amount >= 1000 AND amount <= 10` — the branch is permanently false.
4. All funds controlled by that address definition are permanently unspendable, i.e., frozen forever.

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

**File:** definition.js (L565-592)
```javascript
			case 'sum':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["filter", "equals", "at_least", "at_most"]))
					return cb("unknown fields in "+op);
				var err = getFilterError(args.filter);
				if (err)
					return cb(err);
				if (args.filter.amount || args.filter.amount_at_least || args.filter.amount_at_most)
					return cb("sum filter cannot restrict amounts");
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
				if (!args.filter.asset || args.filter.asset === 'base' || bAssetCondition && args.filter.asset === "this asset")
					return cb();
				determineIfAnyOfAssetsIsPrivate([args.filter.asset], function(bPrivate){
					bPrivate ? cb("asset must be public") : cb();
				});
				break;
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
