### Title
Null-pointer/type-confusion crash in address definition validation via unguarded `mci`/`age`/`timestamp` operator args - (File: definition.js)

### Summary
`upx`'s CVE-2021-30500 is a null pointer dereference in `PackLinuxElf::canUnpack()` caused by a code path that dereferences an attacker-crafted structure without first verifying its shape/type, leading to a crash on a malicious input. The analogous root cause exists in ocore's oscript **address-definition validator**, `definition.js`, in the `evaluate()` closure inside `validateDefinition()`, specifically the `case 'mci': case 'age': case 'timestamp':` branch [1](#0-0) . The shape check on `args` is conditioned on an mci gate instead of being unconditional, so a crafted definition can reach `args[0]`/`args[1]` while `args` is not a 2-element array (e.g. `null`, a number, or a non-array object), throwing an uncaught `TypeError`.

### Finding Description
In `evaluate(arr, path, bInNegation, cb)`, `args` is simply `arr[1]`, whose only prior guarantee is that `arr` is a 2-element array (`isArrayOfLength(arr, 2)`, see [2](#0-1) ) — `args` itself can be any JSON value: `null`, a string, a number, an object, etc.

For the `'mci'`/`'age'`/`'timestamp'` operators, the validator is supposed to require `args` to be a 2-element array before touching `args[0]`/`args[1]`:
```
if (!isArrayOfLength(args, 2) && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
    return cb(op + " must have 2 args");
var relation = args[0];
var value = args[1];
``` [3](#0-2) 

The rejection only fires when **both** `!isArrayOfLength(args, 2)` **and** the mci-gate condition are true. When the mci-gate condition is false (i.e. the unit's `last_ball_mci` is below `constants.pemCurvesFixMci`, or the unit is unstable/light with `hasBall` false and the node's min retrievable mci is below that upgrade point), the malformed-shape check is skipped entirely and execution falls straight into `args[0]` / `args[1]`. If `args` is `null` or `undefined` this throws `TypeError: Cannot read properties of null/undefined (reading '0')`. Other similarly-gated ops in the same file (`'weighted and'`'s `required > 1000` check, `arg.weight > 1000` check) show the same conditional-only-after-upgrade pattern, but those don't dereference an unchecked argument the way `mci`/`age`/`timestamp` does.

This is reached from `validateDefinition()`, which is invoked whenever a unit defines a new address or asset-issuance condition (author's `definition` field, `definition_template`, `definition_chash` messages, asset `is_transferrable`/`spender_attested` conditions, etc.) — i.e. directly from content posted by any ordinary unit author, with no special privilege required [4](#0-3) .

### Impact Explanation
An uncaught `TypeError` thrown synchronously inside the `evaluate()` recursion of `validateDefinition()` is not wrapped in a `try/catch` at this call site (unlike several neighboring branches that explicitly wrap risky operations in `try { ... } catch(e) { return cb(...) }`, e.g. the `'address'` case at [5](#0-4) ). An unhandled exception thrown from deep inside the async validation callback chain propagates out of the event loop turn and crashes the ocore node process (denial of service), or at minimum causes divergent behavior between nodes whose local mci happens to straddle the `pemCurvesFixMci` gate (one node crashes/rejects, another accepts), which can produce disagreement on unit validity — matching the "node disagreement on validity" impact class called out for analog acceptance.

### Likelihood Explanation
Likelihood depends on whether `objValidationState.last_ball_mci` for currently-processed units is already above `constants.pemCurvesFixMci` on the live network. If the network's current mci has already passed this upgrade point, the vulnerable branch is not reachable for new units on stable network state, which would make this **not exploitable today on mainnet** — it would only be reachable for a light client evaluating older/unstable content (`!objValidationState.hasBall` with `storage.getMinRetrievableMci()` below the upgrade), or for other networks/testnets that haven't crossed that mci. I was not able to fully verify, within the available tool budget, the current value of `constants.pemCurvesFixMci` relative to live mainnet mci, nor whether an outer generic `try/catch` around the whole `validateDefinition`/`validateAuthor` async chain in `validation.js` converts this exception into an `ifUnitError` instead of crashing the process. Both of these facts materially affect real-world exploitability and should be confirmed by a maintainer/agent with full repository and runtime access before treating this as immediately live.

### Recommendation
Make the `args` shape check for `'mci'`/`'age'`/`'timestamp'` (and any other operator following the same "gated by mci" pattern) **unconditional**, independent of `pemCurvesFixMci`/`hasBall`/`getMinRetrievableMci`:
```
if (!isArrayOfLength(args, 2))
    return cb(op + " must have 2 args");
```
If backward compatibility with pre-upgrade historical units is the reason for the gate, wrap the subsequent `args[0]`/`args[1]` access (and the whole switch dispatch in `evaluate()`) in a `try/catch` that converts any thrown error into a normal `cb(err)`/`ifUnitError` result rather than letting it propagate as an uncaught exception.

### Proof of Concept
1. Construct a unit whose author defines a new address (or an asset condition) using a definition array containing the expression `['mci', null]` (or `['age', 42]`, `['timestamp', {}]`) as the address definition or a sub-expression of it.
2. Ensure the unit is processed by a node in a validation context where `objValidationState.last_ball_mci < constants.pemCurvesFixMci`, or as a light unit with `hasBall` false and the node's `storage.getMinRetrievableMci() < constants.pemCurvesFixMci`.
3. When `validateDefinition()` reaches this sub-expression, `isArrayOfLength(args, 2)` is false but the mci-gate is also false, so the guard is skipped and `args[0]` is evaluated on `null`/a non-array, throwing `TypeError`, propagating out of the async validation chain.

### Citations

**File:** definition.js (L42-43)
```javascript
// validate definition of address or asset spending conditions
function validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, handleResult){
```

**File:** definition.js (L112-115)
```javascript
		if (!isArrayOfLength(arr, 2))
			return cb("expression must be 2-element array");
		var op = arr[0];
		var args = arr[1];
```

**File:** definition.js (L286-296)
```javascript
					//		return cb(null, true);
						var bAllowUnresolvedInnerDefinitions = true;
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function (author) {
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb("failed to calc definition hash of co-author "+other_address+": "+e.message);
						}
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
```

**File:** definition.js (L480-495)
```javascript
			case 'mci':
			case 'age':
			case 'timestamp':
				if (!isArrayOfLength(args, 2) && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb(op + " must have 2 args");
				var relation = args[0];
				var value = args[1];
				if (!isNonemptyString(relation))
					return cb("no relation");
				if (["=", ">", "<", ">=", "<=", "!="].indexOf(relation) === -1)
					return cb("invalid relation: " + JSON.stringify(relation));
				if (!isNonnegativeInteger(value))
					return cb(op+" must be a non-neg number");
				if (op === 'timestamp' && objValidationState.last_ball_mci < constants.timestampUpgradeMci)
					return cb('timestamp op not allowed yet');
				return cb();
```
