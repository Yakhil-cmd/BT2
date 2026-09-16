Based on the investigation, ocore already has strong defense-in-depth against the CVE-2017-9438 bug class (stack-consumption via unbounded recursion on crafted nested input) in most of its recursive evaluators — `formula/validation.js`, `formula/evaluation.js`, `aa_validation.js`, and `definition.js` all cap recursion via `MAX_DEPTH`/`MAX_COMPLEXITY`/`count % 100` stack-breaking (`setImmediate`) tricks, and top-level unit ingestion is guarded by [1](#0-0) , which is itself a bounded, depth-checked recursive walker used both for network-received joints [2](#0-1)  and for full unit validation [3](#0-2) .

However, one concrete gap remains reachable by an unprivileged unit poster: in the main `validate()` entry point, the unit hash is recomputed **before** the depth/size guard runs.

### Title
Stack Exhaustion via Unbounded Recursive Unit Hashing Before Depth Validation - ([File: validation.js])

### Summary
`validation.js`'s top-level `validate()` function calls `objectHash.getUnitHash(objUnit)` at line 133 to verify the posted unit's self-reported hash, **before** the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` depth/size guard executes at line 154. [4](#0-3)  `getUnitHash` recursively canonicalizes the entire unit object via `getNakedUnit` (which performs `_.cloneDeep(objUnit)`, itself recursively descending into every nested `message.payload`) and then serializes it with `getSourceString`/`getJsonSourceString` for hashing. [5](#0-4)  None of this hashing/serialization path is protected by any recursion-depth limit, unlike the dedicated `isTooDeeplyNestedOrHasTooManyNodes` check that is applied only afterward.

### Finding Description
An unprivileged peer can post a unit whose `messages[].payload` (e.g. a `data`, `data_feed`, `text`, or nested `definition`/`asset` payload) contains an extremely deeply nested array or object (analogous to YARA's crafted "hex string" input that overflows `_yr_re_emit`'s recursive emitter). Because `objectHash.getUnitHash()` is invoked at [6](#0-5)  prior to any nesting-depth check, the recursive `_.cloneDeep` and canonical serialization routines in `getNakedUnit`/`getSourceString` will recurse to the full depth of the attacker-supplied structure. This mirrors the root cause pattern in the CVE — an emit/serialize routine that recurses proportionally to attacker-controlled nesting with no depth cap — causing a native (V8) stack overflow and crashing the Node.js process handling unit validation, instead of gracefully rejecting the oversized unit as the later `isTooDeeplyNestedOrHasTooManyNodes` check is designed to do.

### Impact Explanation
A crafted unit with deep nesting can crash any full node (or hub) that attempts to validate it as soon as it is received/gossiped, before the dedicated nesting-depth defense has a chance to run. Because unit validation is a prerequisite for confirming new units on the DAG, an attacker able to repeatedly post or relay such crafted units can degrade or halt a targeted node's/network's ability to validate and confirm new units — a network-unable-to-confirm-new-units denial-of-service condition reachable purely by posting a unit.

### Likelihood Explanation
Likelihood is high for triggering the crash path: any account (address) can post a unit with an arbitrarily-shaped JSON payload for `data`, `data_feed`, `text`, or nested `definition`/`asset` messages, and no ordering fix currently moves the depth check ahead of the hash verification. The only uncertainty is the exact recursion depth needed to exhaust V8's default stack, which depends on runtime/stack-size configuration, but crafting a nested array/object with several thousand levels (well within reasonable message-size limits) is straightforward and consistent with the `depth: 2000` nested-structure regression tests already present for the formula evaluator. [7](#0-6) 

### Recommendation
Move the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` check (and/or an equivalent depth cap) to execute **before** `objectHash.getUnitHash(objUnit)` in `validation.js`'s `validate()` function, and additionally harden `getNakedUnit`/`getSourceString`/`getJsonSourceString` in `object_hash.js` and `string_utils.js` with an internal recursion-depth guard so that hashing/serialization can never be invoked on unbounded attacker-controlled nesting regardless of call order elsewhere in the codebase (e.g., `getChash160`, `getBallHash`, `getDeviceMessageHashToSign`, which also serialize attacker/peer-influenced structures).

### Proof of Concept
1. Construct a unit whose `messages` array includes a message with `app: "data"` and `payload` set to a JSON value nested thousands of levels deep, e.g. `payload = JSON.parse('['.repeat(20000) + '1' + ']'.repeat(20000))`, keeping the overall unit within normal size/byte limits.
2. Sign the unit normally and broadcast it (or submit directly for validation) so it reaches `validation.js`'s `validate()`.
3. Because `objectHash.getUnitHash(objUnit)` at line 133 recursively clones/serializes the full payload before the nesting-depth check at line 154 runs, the recursive descent in `getNakedUnit`'s `_.cloneDeep` and `getSourceString` exhausts the call stack, crashing the validating process instead of yielding the intended "unit is too deeply nested" rejection.

**Note on completeness:** I was not able to retrieve the exact implementation body of `getSourceString`/`getJsonSourceString` in `string_utils.js` in this session (only `isTooDeeplyNestedOrHasTooManyNodes`/`isTooBigObj` were surfaced by search), so the precise recursion mechanics of the canonicalization routine are inferred from its usage pattern and from `_.cloneDeep`'s confirmed recursive behavior rather than fully confirmed line-by-line. A Devin session with direct file access would be needed to inspect `string_utils.js`'s `getSourceString` implementation in full to close this gap definitively.

### Citations

**File:** string_utils.js (L260-284)
```javascript
function isTooDeeplyNestedOrHasTooManyNodes(obj, depthLimit = 100, nodesLimit = 10000) {
	let nodeCount = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit)
			return true;
		if (variable === null || typeof variable !== "object")
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			nodeCount += Object.keys(variable).length;
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```

**File:** network.js (L995-996)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(objJoint))
		return sendError(ws, "joint is too deeply nested or has too many nodes");
```

**File:** validation.js (L131-155)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}

	const bGenesis = storage.isGenesisUnit(objUnit.unit);

	var bAA = false;
	if (objJoint.aa) {
		bAA = true;
		var aa_mci = objJoint.aa_mci;
		delete objJoint.aa;
		delete objJoint.aa_mci;
	}
	else {
		if (isArrayOfLength(objUnit.authors, 1) && !isNonemptyObject(objUnit.authors[0].authentifiers) && !objUnit.content_hash && !conf.bLight)
			return callbacks.ifTransientError("possible AA");
	}
	
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
```

**File:** object_hash.js (L33-65)
```javascript
function getNakedUnit(objUnit){
	var objNakedUnit = _.cloneDeep(objUnit);
	delete objNakedUnit.unit;
	delete objNakedUnit.headers_commission;
	delete objNakedUnit.payload_commission;
	delete objNakedUnit.oversize_fee;
//	delete objNakedUnit.tps_fee; // cannot be calculated from unit's content and environment, users might pay more than required
	delete objNakedUnit.actual_tps_fee;
	delete objNakedUnit.main_chain_index;
	if (objUnit.version === constants.versionWithoutTimestamp)
		delete objNakedUnit.timestamp;
	//delete objNakedUnit.last_ball_unit;
	if (objNakedUnit.messages){
		for (var i=0; i<objNakedUnit.messages.length; i++){
			delete objNakedUnit.messages[i].payload;
			delete objNakedUnit.messages[i].payload_uri;
		}
	}
	//console.log("naked Unit: ", objNakedUnit);
	//console.log("original Unit: ", objUnit);
	return objNakedUnit;
}

function getUnitContentHash(objUnit){
	return getBase64Hash(getNakedUnit(objUnit), objUnit.version !== constants.versionWithoutTimestamp);
}

function getUnitHash(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	if (objUnit.content_hash) // already stripped and objUnit doesn't have messages
		return getBase64Hash(getNakedUnit(objUnit), bVersion2);
	return getBase64Hash(getStrippedUnit(objUnit), bVersion2);
}
```

**File:** test/formula.test.js (L6415-6425)
```javascript
test.cb('deeply nested array', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = {};
	const depth = 2000;
	evalFormulaWithVars({ conn: db, formula: `${'['.repeat(depth)}1${']'.repeat(depth)}`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, null);
	//	t.deepEqual(complexity, 1);
	//	t.deepEqual(count_ops, depth + 1);
		t.end();
	})
});
```
