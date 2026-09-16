### Title
`has equal`/`has one equal` spending-condition allows search_criteria[0] to trivially self-match search_criteria[1], defeating the intended cross-check between two independent puts - (File: definition.js)

### Summary
The external report flags a class of bug where a contract fails to require that two logically-distinct entities (`token0`/`token1`) are actually different, letting the code silently operate on a degenerate case it never intended to support. The analogous pattern exists in ocore's oscript address-definition language: the `has equal` / `has one equal` operators are meant to prove that **two independent** sets of inputs/outputs share certain field values (e.g., "some output paying address X" equals "some input from address Y"), but nothing prevents `search_criteria[0]` and `search_criteria[1]` from describing the *same* set of messages/puts, in which case the check degenerates into "does this put match itself," which is always true whenever anything matches at all.

### Finding Description
`validateDefinition` in [1](#0-0)  validates the shape of the `has equal`/`has one equal` arguments (`equal_fields`, `search_criteria`), but it never checks that `search_criteria[0]` and `search_criteria[1]` are non-identical or reference disjoint sets of puts (unlike, e.g., an "asset must differ" or "address must differ" style check). It only validates each filter individually via `getFilterError` and checks whether any referenced asset is private.

At authentication time, `validateAuthentifiers` evaluates the operator in [2](#0-1) : it independently runs `augmentMessagesAndEvaluateFilter("has", args.search_criteria[0], ...)` and `...search_criteria[1], ...)`, then counts pairs of objects (one from each result set) whose `equal_fields` values match, via `getKey`. If the two search criteria are identical (or simply select overlapping/identical puts), `arrFirstObjects` and `arrSecondObjects` are the same set, so every element trivially matches itself, and `count_equal_pairs` becomes non-zero as soon as a single matching put exists — with no requirement that two *distinct* puts satisfy the equality relationship. This is the oscript analog of `token0 == token1`: a condition whose logic implicitly assumes two different objects are being compared, but the code never asserts that assumption, so it silently accepts the degenerate case.

There is no test coverage in the repository exercising this specific case (`grep` for `has equal`/`has one equal` in `test/**` returns no matches), so the degenerate self-match behavior has not been validated against.

### Impact Explanation
`has equal`/`has one equal` is a building block for shared/multi-owner spending conditions and swap-like address definitions (e.g., "release funds only if there is an input from address A whose amount equals an output to address B" for an atomic-swap style co-signed address). If the two `search_criteria` end up describing overlapping/identical message sets — either through a co-signer's honest mistake when constructing a shared-address definition template, or through a malicious co-signer deliberately proposing such a definition to other cosigners — the condition can be satisfied by a single self-referential put instead of requiring the intended second, independent counterparty put. This defeats the purpose of the spending condition and can allow spending funds from the shared address without the counterparty-side payment that the definition was designed to enforce, i.e., unauthorized spending relative to the address's stated authorization policy.

### Likelihood Explanation
Reachability requires only that some address (e.g. a wallet-defined-by-addresses / arbiter-contract shared address, reachable by any unprivileged unit poster who is a co-signer) is defined using `has equal`/`has one equal` with search criteria that end up equal or overlapping. Because `validateDefinition` performs no structural check to reject this, and there is no runtime test coverage catching it, this is a plausible authoring mistake or engineered omission in cooperatively-defined spending conditions, not merely a theoretical edge case.

### Recommendation
In `validateDefinition`'s handling of `has equal` / `has one equal` (definition.js, function scope shown at [1](#0-0) ), reject definitions where `search_criteria[0]` and `search_criteria[1]` are deep-equal, and additionally, in the runtime evaluator ( [2](#0-1) ), exclude a candidate object in `arrFirstObjects` from matching itself in `arrSecondObjects` (i.e., require the matched pair to come from two distinct puts) so that a single put can never satisfy the "equal" relationship on its own.

### Proof of Concept
Construct an address definition:
```
["has equal", {
  equal_fields: ["address", "amount"],
  search_criteria: [
    {what: "output", asset: "base"},
    {what: "output", asset: "base"}
  ]
}]
```
Any unit that pays a single output from this address will produce `arrFirstObjects` and `arrSecondObjects` containing the same single output object; `getKey` will match it against itself, `count_equal_pairs` becomes 1, and both `has equal` and `has one equal` evaluate to `true` — even though only one output exists and no genuine second, independent matching put was ever provided. This confirms the check can be satisfied trivially, analogous to `token0 == token1` being silently accepted in Base.sol.

### Citations

**File:** definition.js (L522-563)
```javascript
			case 'has equal':
			case 'has one equal':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["equal_fields", "search_criteria"]))
					return cb("unknown fields in "+op);
				
				if (!isNonemptyArray(args.equal_fields))
					return cb("no equal_fields");
				var assocUsedFields = {};
				for (var i=0; i<args.equal_fields.length; i++){
					var field = args.equal_fields[i];
					if (typeof field !== 'string')
						return cb("fields must be strings");
					if (["asset", "address", "amount", "type"].indexOf(field) === -1)
						return cb("unknown field: "+field);
					if (assocUsedFields[field])
						return cb("duplicate "+field);
					assocUsedFields[field] = true;
				}
				
				if (!isArrayOfLength(args.search_criteria, 2))
					return cb("search_criteria must be 2-elements array");
				var arrAssets = [];
				for (var i=0; i<2; i++){
					var filter = args.search_criteria[i];
					var err = getFilterError(filter);
					if (err)
						return cb(err);
					if (!(!filter.asset || filter.asset === 'base' || bAssetCondition && filter.asset === "this asset"))
						arrAssets.push(filter.asset);
				}
				if (args.equal_fields.indexOf("type") >= 0 && (args.search_criteria[0].what === "output" || args.search_criteria[1].what === "output"))
					return cb("outputs cannot have type");
				if (arrAssets.length === 0)
					return cb();
				determineIfAnyOfAssetsIsPrivate(arrAssets, function(bPrivate){
					bPrivate ? cb("all assets must be public") : cb();
				});
				break;
```

**File:** definition.js (L1117-1153)
```javascript
			case 'has equal':
			case 'has one equal':
				// ['has equal', {equal_fields: ['address', 'amount'], search_criteria: [{what: 'output', asset: 'asset1', address: 'BASE32'}, {what: 'input', asset: 'asset2', type: 'issue', address: 'ANOTHERBASE32'}]}]
				const needsAugment = args.search_criteria.map(f => f.what).includes("input") && _.intersection(args.equal_fields, ["address", "amount"]).length > 0;
				augmentMessagesIfNeeded(needsAugment, (err) => {
					if (err)
						return cb2(false);
					augmentMessagesAndEvaluateFilter("has", args.search_criteria[0], function(res1, arrFirstObjects){
						if (!res1)
							return cb2(false);
						augmentMessagesAndEvaluateFilter("has", args.search_criteria[1], function(res2, arrSecondObjects){
							if (!res2)
								return cb2(false);
							// build a key from the equal_fields values so that matching pairs can be counted
							// in O(n+m) instead of O(n*m) by grouping arrSecondObjects into a map of key->count
							// (amounts are numbers, address/type/asset are strings, only type can be undefined,
							// and none of them can equal "" or the literal string "undefined", so join() is safe)
							const getKey = obj => args.equal_fields.map(field => obj[field]).join('\x1f');
							let mapSecondKeyToCount = new Map();
							for (let j = 0; j < arrSecondObjects.length; j++) {
								const key = getKey(arrSecondObjects[j]);
								mapSecondKeyToCount.set(key, (mapSecondKeyToCount.get(key) || 0) + 1);
							}
							var count_equal_pairs = 0;
							for (var i = 0; i < arrFirstObjects.length; i++)
								count_equal_pairs += mapSecondKeyToCount.get(getKey(arrFirstObjects[i])) || 0;
							if (count_equal_pairs === 0)
								return cb2(false);
							if (op === "has one equal" && count_equal_pairs === 1)
								return cb2(true);
							if (op === "has equal" && count_equal_pairs > 0)
								return cb2(true);
							cb2(false);
						});
					});
				});
				break;
```
