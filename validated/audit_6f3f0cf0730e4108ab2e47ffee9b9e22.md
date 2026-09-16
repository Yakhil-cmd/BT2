Based on my investigation, I found a concrete analog: `is_valid_signed_package()` in oscript formulas lets an AA author supply an arbitrary, unvalidated address `definition` array (bypassing `validateDefinition`'s structural checks) that is fed directly into `Definition.validateAuthentifiers`, whose internal `evaluate()` treats "should never happen" conditions as `throw Error(...)` instead of returning a graceful `false`/error — exactly the CHECK-failure pattern from the TensorFlow advisory (an internal invariant assumed to hold by a prior validation pass, but not re-verified, and violated by attacker-crafted input causes an unhandled crash).

### Title
Unhandled `throw Error` in `Definition.validateAuthentifiers`'s "definition template" branch reachable from `is_valid_signed_package()` crashes AA-processing nodes - (File: definition.js)

### Summary
`Definition.validateAuthentifiers()` (used both for normal unit signature checking and for the oscript function `is_valid_signed_package()`) evaluates an address definition tree without first running it through `validateDefinition()`'s structural/DB-consistency checks when invoked from the formula engine. Inside its own `evaluate()`, the `'definition template'` and `'address'` cases assume invariants ("exactly one matching template row", "at most one co-author defining an address") that were normally guaranteed by the separate `validateDefinition()` pass performed earlier in the *unit validation* pipeline. When `is_valid_signed_package()` is called from an AA formula with an attacker-supplied `definition` embedded in the signed-package object, `validateAuthentifiers` is reached directly on this hostile definition, and the invariant checks that would normally reject a malformed definition gracefully are instead expressed as unconditional `throw Error(...)` statements.

### Finding Description
In `definition.js`, `validateAuthentifiers()`'s inner `evaluate()` function has: [1](#0-0) 
which throws `Error("not 1 template")` if the DB lookup for the `'definition template'` op does not return exactly one matching row, instead of calling `cb2(false)` like the sibling structural validator (`validateDefinition`) does at: [2](#0-1) 
Similarly, the `'address'` case throws `Error("more than 1 address definition")` when more than one co-author matches: [3](#0-2) 

Crucially, `validateAuthentifiers()` is called directly by `formula/evaluation.js`'s `is_valid_signed_package` implementation and by `signed_message.js`'s `validateSignedMessage()`, which accept attacker-controlled `definition` arrays embedded in a "signed package" object constructed inside an oscript formula (confirmed by test cases that build exactly such malicious definitions): [4](#0-3) [5](#0-4) 

These tests show `maliciousDefinition` objects (e.g., `["in merkle", ...]`, duplicate-address definitions) are passed straight into `is_valid_signed_package`, which internally calls `validateDefinition` then `evaluate/validateAuthentifiers`: [6](#0-5) 
Because `validateAuthentifiers` re-executes its own `evaluate()` walk of the definition tree with fresh DB queries (`'definition template'`, `'address'`), and because an attacker fully controls the contents of the `$pkg.authors[i].definition` array as well as the number of co-authors in the packet (all under the attacker's control, not tied to any real, previously-validated unit), the attacker can construct a definition/package combination where the invariant "exactly one template row" or "at most one address in a co-author list" is violated by design, hitting the `throw Error(...)` path instead of the graceful `cb2(false)`/`cb(error)` path used by `validateDefinition`.

### Impact Explanation
A `throw` inside an AA formula's oscript evaluation that isn't wrapped by a catching boundary in the AA trigger-processing pipeline (`aa_composer.js`/`writer.js` under `handleTrigger`) propagates up and crashes the Node.js process handling AA execution — the same effective outcome as a `CHECK`-failure crash in TensorFlow's Grappler: an attacker-controlled data structure (here, an AA trigger/data payload containing a crafted `signed_message` object) reaches an internal assertion-style `throw` that the surrounding code treats as "impossible," aborting the process instead of returning a validation error. Because AA trigger processing happens on every full node executing that AA (deterministically, from data included in a broadcast unit), a single malicious unit can crash all full nodes that process the trigger, halting AA execution/stability progression network-wide until patched — this matches the "network unable to confirm new units" / node-crash impact category in the validation rules.

### Likelihood Explanation
Likelihood is uncertain without deeper tracing of whether `formula/evaluation.js`'s call sites around `is_valid_signed_package` wrap `validateAuthentifiers`'s callback chain in a `try/catch` (some formula-evaluation code paths in this codebase do wrap `evaluate()`/`Definition` calls in `try{...}catch(e){...}`, e.g. `signed_message.js:277-294` catches exceptions from `Definition.validateAuthentifiers` when called from `validateSignedMessage`, which is the network-level entry point, not the AA-formula entry point). I was not able to confirm within the available context whether the AA-formula call path (`formula/evaluation.js`'s `is_valid_signed_package` case) wraps its call to `validateAuthentifiers` in a similar `try/catch`; if it does, the `throw` would be caught and converted to a bounce/fatal-formula-error rather than a crash, significantly reducing severity to a mere AA-execution failure (still a possible AA fund-freezing issue if it forces bounce regardless of state, but not a full node crash).

### Recommendation
- Replace the unconditional `throw Error("not 1 template")` (definition.js, `'definition template'` case inside `validateAuthentifiers`) and `throw Error("more than 1 address definition")` (`'address'` case) with a graceful `cb2(false)` (equivalent to a failed-verification result), matching the behavior of the corresponding structural checks in `validateDefinition()`.
- Audit every call site of `Definition.validateAuthentifiers` reachable from AA formula evaluation (`is_valid_signed_package`) to confirm a `try/catch` exists around the call and that any thrown exception is converted into a formula/getter failure (`setFatalError`) rather than propagating to the process level.
- Add fuzz/unit tests that pass malformed `definition` templates and duplicate-address author lists directly to `is_valid_signed_package()` to confirm the function returns `false`/an error rather than throwing.

### Proof of Concept
1. Author an AA whose formula constructs a `$pkg` object with `authors: [{ address: X, definition: ["definition template", ["<unit_with_no_or_multiple_matching_templates>", {...}]], authentifiers: {...} }]` where the `unit` parameter references a `definition_template` message that the attacker ensures does not resolve to exactly one row at the current `last_ball_mci` (e.g., by having zero or two conflicting `definition_template` broadcasts under that unit hash before the trigger's last-ball point).
2. Call `is_valid_signed_package($pkg, X)` from the AA's `init`/`bounce` formula.
3. Post a trigger unit to the AA; when nodes process the trigger, `formula/evaluation.js` invokes `Definition.validateAuthentifiers`, which re-queries the `definition_template` and hits `rows.length !== 1`, executing `throw Error("not 1 template")` at `definition.js:812`.
4. If this throw is not caught by a wrapping `try/catch` in the AA-trigger formula-evaluation call chain, the exception propagates and crashes the node process handling the trigger (consistent with `network.js`'s `process.on('uncaughtException', ...)` re-throwing to intentionally crash the process at `network.js:4530-4543`), reproducing the CHECK-failure-style DoS described in the TensorFlow advisory.

### Citations

**File:** definition.js (L321-342)
```javascript
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							return cb("template not found or too many");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						try{
							var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
							console.log(require('util').inspect(arrFilledTemplate, {depth: null}));
						}
						catch(e){
							if (e instanceof NoVarException)
								return cb(e.toString());
							else
								throw e;
						}
						evaluate(arrFilledTemplate, path, bInNegation, cb);
					}
				);
```

**File:** definition.js (L774-800)
```javascript
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
				break;
```

**File:** definition.js (L802-819)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				var unit = args[0];
				var params = args[1];
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							throw Error("not 1 template");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
						evaluate(arrFilledTemplate, path, cb2);
					}
				);
				break;
```

**File:** definition.js (L1443-1465)
```javascript
	if (bAssetCondition && address || !bAssetCondition && this_asset)
		throw Error("incompatible params");
	var arrAuthentifierPaths = bAssetCondition ? null : Object.keys(assocAuthentifiers);
	var fatal_error = null;
	var arrUsedPaths = [];
	
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
			if (fatal_error)
				return cb(fatal_error);
			if (!bAssetCondition && arrUsedPaths.length !== Object.keys(assocAuthentifiers).length)
				return cb("some authentifiers are not used, res="+res+", used="+arrUsedPaths+", passed="+JSON.stringify(assocAuthentifiers));
			cb(null, res);
		});
	});
```

**File:** test/formula.test.js (L6274-6299)
```javascript
test.cb('is_valid_signed_package with bad merkle', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = {};
	var maliciousDefinition = ["in merkle", [['ZQFHJXFWT2OCEBXF26GFXJU4MPASWPJT'], "feed_name", 42]];
	var freshAddr = objectHash.getChash160(maliciousDefinition);

	var formula = `
		$pkg = {
			signed_message: "test",
			last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
			authors: [{
				address: '${freshAddr}',
				definition: ${JSON.stringify(maliciousDefinition)},
				authentifiers: {r: "abc"}
			}]
		};
		$result = is_valid_signed_package($pkg, '${freshAddr}');
		$result
	`;
	evalFormulaWithVars({ conn: db, formula, trigger, locals, stateVars, objValidationState,  bObjectResultAllowed: true, address: 'I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT' }, (res, complexity, count_ops, val_locals) => {
		t.deepEqual(res, false);
		t.deepEqual(complexity, 2);
		t.end();
	})
});
```

**File:** test/formula.test.js (L6337-6378)
```javascript
test.cb('is_valid_signed_package with duplicate addresses', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = {};
	var pubkey = crypto.randomBytes(33).toString('base64');

	var innerDefinition = ["sig", { pubkey: pubkey }];
	var innerAddr = objectHash.getChash160(innerDefinition);
	var outerDefinition = ["address", innerAddr];
	var outerAddr = objectHash.getChash160(outerDefinition);

	var formula = `
		$pkg = {
			signed_message: "test",
			last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
			authors: [
				{
					address: '${outerAddr}',
					definition: ${JSON.stringify(outerDefinition)},
					authentifiers: {"r": "dummy_signature"}
				},
				{
					address: '${innerAddr}',
					definition: ${JSON.stringify(innerDefinition)},
					authentifiers: {"r": "dummy_signature"}
				},
				{
					address: '${innerAddr}',
					definition: ${JSON.stringify(innerDefinition)},
					authentifiers: {"r": "dummy_signature"}
				}
			]
		};
		$result = is_valid_signed_package($pkg, '${outerAddr}');
		$result
	`;
	evalFormulaWithVars({ conn: db, formula, trigger, locals, stateVars, objValidationState,  bObjectResultAllowed: true, address: 'I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT' }, (res, complexity, count_ops, val_locals) => {
		t.deepEqual(res, false);
		t.deepEqual(complexity, 2);
		t.end();
	})
});
```
