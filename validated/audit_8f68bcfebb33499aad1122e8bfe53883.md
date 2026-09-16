### Title
Missing `at_least ≤ at_most` (and `amount_at_least ≤ amount_at_most`) range check in address/asset spending-condition definitions can permanently brick fund conditions - (File: `definition.js`)

### Summary
The `_MIN_FEE > _MAX_FEE` bug class (a setter accepting a boundary value without validating it against a correlated boundary, producing an unsatisfiable/broken state) has a direct analog in `definition.js`'s validation of the `sum` operator and of the shared `getFilterError()` helper used by `has`, `has one`, and `seen`. Neither function checks that `at_least` (or `amount_at_least`) is less than or equal to `at_most` (or `amount_at_most`) when both are supplied together.

### Finding Description
`validateDefinition()` in `definition.js` validates address definitions and asset `issue_condition`/`transfer_condition` expressions. For the `sum` operator: [1](#0-0) 

the code checks that `at_least` and `at_most` are each individually valid positive integers, and that `equals` is not combined with either, but it never verifies `args.at_least <= args.at_most`. Likewise, `getFilterError()`, which is shared by the `has`, `has one`, and `seen` operators, validates `amount_at_least` and `amount_at_most` independently: [2](#0-1) 

but never checks `filter.amount_at_least <= filter.amount_at_most`.

Because both bounds can be specified together and are accepted with no cross-check, an address or asset condition such as `["sum", {filter: {...}, at_least: 1000, at_most: 500}]` or `["has", {..., amount_at_least: 1000, amount_at_most: 500}]` passes definition validation even though the resulting numeric range is empty ("sum ≥ 1000 AND sum ≤ 500" can never be true). This is the exact same root cause as `GluexRouter.setMinFee()`: a boundary-pair is accepted without the required `min <= max` invariant, so the resulting condition can never be satisfied.

### Impact Explanation
- For asset `issue_condition`/`transfer_condition` (set once by the asset issuer via `validateAssetDefinition()` / `Definition.validateDefinition(..., true, ...)`, reachable from an ordinary unprivileged asset issuer), an impossible `sum`/`has` range makes the asset's issue or transfer condition permanently unsatisfiable for every future issuer/holder of that asset, i.e. it economically bricks the asset's issuance/transfer logic network-wide — matching the report's "render the fee logic unusable ... violate economic assumptions" impact class, but here it is "render issuance/transfer logic unusable" for anyone who subsequently tries to use that asset.
- For a shared/multisig address definition containing such a clause in an `and`/`or` branch, funds sent to that address by any counterparty can become permanently unspendable through that branch, again due to an unenforced bound relationship that should have been rejected at definition-validation time.

### Likelihood Explanation
Any unprivileged actor authoring an asset definition or an address definition can trigger this by simply supplying `at_least > at_most` (or `amount_at_least > amount_at_most`). No special privilege, race condition, or malicious peer is required — it is a pure validation-logic gap reachable from a single posted unit, exactly like the router's `onlyTreasury`-callable but unchecked `setMinFee`.

### Recommendation
Add a cross-field check in both `getFilterError()` and the `sum` case of `validateDefinition()` (and the corresponding runtime evaluators) that rejects definitions where both bounds are present and `at_least > at_most` / `amount_at_least > amount_at_most`:

```diff
 if ("at_least" in args && !isPositiveInteger(args.at_least))
     return cb("at_least must be positive int");
 if ("at_most" in args && !isPositiveInteger(args.at_most))
     return cb("at_most must be positive int");
+if ("at_least" in args && "at_most" in args && args.at_least > args.at_most)
+    return cb("at_least cannot exceed at_most");
```

```diff
 if ("amount_at_least" in filter && !isPositiveInteger(filter.amount_at_least))
     return "amount_at_least must be positive int";
 if ("amount_at_most" in filter && !isPositiveInteger(filter.amount_at_most))
     return "amount_at_most must be positive int";
+if ("amount_at_least" in filter && "amount_at_most" in filter && filter.amount_at_least > filter.amount_at_most)
+    return "amount_at_least cannot exceed amount_at_most";
```

### Proof of Concept
1. An asset issuer posts an `asset` definition message with `transfer_condition: ["sum", {filter: {what: "output", asset: "this asset"}, at_least: 1000, at_most: 500}]`.
2. `validateAssetDefinition()` calls `Definition.validateDefinition(conn, payload.transfer_condition, ..., true, cb)`, which reaches the `sum` case at `definition.js:565-586`; both `at_least` and `at_most` pass their individual `isPositiveInteger` checks, so the definition is accepted and the asset unit is committed.
3. From then on, any unit attempting to transfer this asset is evaluated against the `sum ≥ 1000 AND sum ≤ 500` condition via `Definition.evaluateAssetCondition()`, which can never be satisfied, permanently blocking all transfers of the asset.

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

**File:** definition.js (L565-586)
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
```
