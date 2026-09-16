## Analog found

### Title
Off-chain-computed AA/child-AA address (`chash160()`) can permanently trap funds if the corresponding `definition` message is later rejected by validation - (File: `aa_validation.js`, `validation.js`, `aa_composer.js`)

### Summary
Obyte's AA definitions and addresses are the direct on-chain analog of Solidity's `CREATE2` counterfactual deployment pattern reported in the external report. An AA (or regular) address is nothing more than the hash (`chash160`) of its definition content, computed identically off-chain and on-chain. Anyone — an unprivileged AA author writing an `init` script, or an ordinary user preparing a definition to post later — can compute the deterministic address of a not-yet-registered AA with `chash160(definition)` and send funds to it before the `definition` message that "deploys" it is ever posted, exactly as counterfactual funding is done with `CREATE2` addresses. If the definition later fails the mandatory validation performed in `aa_validation.validateAADefinition()` / `validation.js`'s `definition` message-type handler, the definition can never be published, and — because changing anything in the definition to fix the problem changes the resulting address — the funds already sent to the precomputed address become permanently unspendable.

### Finding Description
Address derivation is by design collision-resistant and content-bound: `address = objectHash.getChash160(arrDefinition)` [1](#0-0)  and, for AAs specifically, `getChash160` uses the JSON source string of the two-element `['autonomous agent', template]` array [1](#0-0) .

Obyte natively supports and even documents/tests the "factory" pattern seen in the report: an AA computes a brand-new child AA definition inside an `init` formula, derives its address purely off-chain with `chash160($child_aa)`, and in the *same* response emits both a `definition` message (to register it) and a `payment` message that sends funds to that computed address: [2](#0-1) 

The `definition` app message is validated generically by consensus rules in `validateInlinePayload()`, independent of who posts it (an AA response or a plain user-authored unit): [3](#0-2) 

That validation delegates to `aa_validation.validateAADefinition()`, which enforces a large set of hard, content-dependent rules — allowed field names, `bounce_fees` bounds, `doc_url`, `getters` syntax, and (via `validateFieldWrappedInCases`/`validateDefinition`) the formula complexity/op-count limits of every message in `messages`: [4](#0-3) 

For a parameterized AA (`base_aa` + `params`), the address is computed purely from `base_aa` and `params` before the `base_aa` needs to exist or be valid, but publishing the definition later requires the referenced base AA to already exist and be a "regular" (non-parameterized) AA: [5](#0-4) [6](#0-5) 

Crucially, once an address is bound to `['autonomous agent', ...]` content, it can never be redefined with different content, and it can never be treated as a normal spendable address either — `validateAuthor()` explicitly refuses to accept an `['autonomous agent', ...]` array as a spending definition: [7](#0-6) 

So an AA-shaped address whose definition fails `validateAADefinition` (e.g., because a message's formula exceeds the complexity/op limits, uses a disallowed field, or references a `base_aa` that will never itself be validly deployed as a "regular" AA) is a dead end: the exact bytes that hash to that address can never be posted as a valid `definition` message, and the address can never be spent as a `sig`/`and`/`or`/etc. address either, since the `'autonomous agent'` op is not a recognized spending-condition op and is explicitly rejected in `validateAuthor`.

### Impact Explanation
Any unprivileged unit poster (or an AA's own `init` script that computes a child address before its `definition` message is confirmed to be valid) can be tricked, or can mistakenly compute, a target address for an AA definition that will be rejected by consensus validation. Bytes/assets sent to that address — whether via a normal `payment` message from a user, or via an AA's own outgoing payment (as in the factory pattern above) — become permanently frozen: there is no clawback, no owner key, and no way to "fix" the definition without altering the address itself. This mirrors the reported Sablier issue precisely: a deterministic, content-derived address is fundable before its "deployment" succeeds, and if the deployment parameters don't validate, the funds are unrecoverable.

### Likelihood Explanation
This is directly reachable by any ordinary AA author or user, no special privileges required. The factory-AA pattern (computing `chash160()` of a not-yet-defined AA and paying it in the same response) is an officially supported and tested usage pattern [8](#0-7) , so the preconditions (an off-chain/pre-registration computed address receiving funds before its definition message is confirmed valid) occur in normal usage, not just adversarial edge cases. The only requirement for the loss to materialize is that the definition ultimately fails one of the many hard checks in `aa_validation.validateAADefinition` (complexity limits, disallowed fields, `base_aa` never becoming a valid non-parameterized AA, etc.) — plausible via a coding mistake, a formula that inadvertently exceeds the complexity ceiling, or a base AA that is deprecated/never deployed.

### Recommendation
- Avoid designs where funds can be sent to an address before the corresponding `definition` message has been confirmed valid; require the `definition` message and any transfer to it to be validated/atomic within the same unit whenever possible (as the built-in factory pattern already partially does), and reject/bounce the whole unit if the `definition` payload fails validation before any payment executes.
- For AA `init`-script–driven, self-generated child-AA addresses, perform the same `validateAADefinition` checks in-formula (or expose a formula built-in that mirrors these checks) before allowing a `payment` message to target the derived address, so that a definition-composition mistake cannot silently create an unfundable/unreachable target.
- Consider adding a recovery path (documented in the AA/definition spec) analogous to Sablier's accepted clawback fix — e.g., allow an "escape" transaction for base-Byte or asset outputs sent to addresses whose only known `definition` has permanently failed validation, gated by strict conditions to avoid abuse.

### Proof of Concept
1. Author AA `factory_aa` whose `init` formula builds a child AA definition `$child_aa` containing a `messages` array whose formulas are engineered to exceed the AA complexity/op-count limits enforced by `validateDefinition`/`validateFieldWrappedInCases` inside `aa_validation.validateAADefinition` (see `aa_validation.js:769` `validateFieldWrappedInCases(template, 'messages', validateMessages, ...)`), then computes `$child_aa_address = chash160($child_aa)`.
2. In the same response, `factory_aa` emits (a) a `definition` message with `payload.definition = $child_aa` and (b) a `payment` message sending funds to `$child_aa_address`, exactly as in the existing test at [2](#0-1) .
3. When this response unit is processed by consensus validation (`validation.js` `case "definition"` → `aa_validation.validateAADefinition`, `validation.js:1767`), the definition fails the complexity/op check.
4. Because `$child_aa_address` is uniquely and irreversibly derived from the exact (invalid) definition content, no alternative valid definition can ever hash to the same address, and the `'autonomous agent'` array can never be used as a spending definition per `validation.js:1179-1180`.
5. Any funds already sent to `$child_aa_address` (from this or any other payment) are permanently unspendable — the analog of losing funds sent to a `CREATE2` address whose deployment parameters fail validation.

### Citations

**File:** object_hash.js (L10-13)
```javascript
function getChash160(obj) {
	var sourceString = (Array.isArray(obj) && obj.length === 2 && obj[0] === 'autonomous agent') ? getJsonSourceString(obj) : getSourceString(obj);
	return chash.getChash160(sourceString);
}
```

**File:** test/aa_composer.test.js (L922-1010)
```javascript
test.cb.serial('AA with generated definition of new AA and immediately sending to this new AA', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var child_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
					]
				}
			}
		]
	}];
	var child_aa_address = objectHash.getChash160(child_aa);
	
	var factory_aa = ['autonomous agent', {
		init: `{
			$child_aa = ['autonomous agent', {
				bounce_fees: { base: 10000 },
				doc_url: 'https://myapp.com/description.json',
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							init: "{response['received_amount'] = trigger.output[[asset=base]];}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
							]
						}
					}
				]
			}];
			$child_aa_address = chash160($child_aa);
		}`,
		messages: [
			{
				app: 'definition',
				payload: {
					definition: `{$child_aa}`
				}
			},
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [{address: `{$child_aa_address}`, amount: 8000}]
				}
			},
			{
				app: 'state',
				state: `{
					var['child_aa1'] = $child_aa_address;
					var['child_aa2'] = unit[response_unit].messages[[.app='definition']].payload.address;
				}`
			}
		]
	}];

	validateAA(factory_aa, err => {
		t.deepEqual(err, null);

		var factory_address = objectHash.getChash160(factory_aa);
		addAA(factory_aa);
		
		aa_composer.dryRunPrimaryAATrigger(trigger, factory_address, factory_aa, (arrResponses) => {
			t.deepEqual(arrResponses.length, 2);
			t.deepEqual(arrResponses[0].bounced, false);
			t.deepEqual(arrResponses[0].updatedStateVars[factory_address].child_aa1.value, child_aa_address);
			t.deepEqual(arrResponses[0].updatedStateVars[factory_address].child_aa2.value, child_aa_address);
			t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'definition'); }).payload.definition, child_aa);
			t.deepEqual(arrResponses[1].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger_address); }).amount, 5000);
			fixCache();
			t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
			t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
			t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
			t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
			t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
			t.end();
		});
	});
});
```

**File:** validation.js (L1177-1183)
```javascript
	var arrAddressDefinition = objAuthor.definition;
	if (isNonemptyArray(arrAddressDefinition)){
		if (arrAddressDefinition[0] === 'autonomous agent')
			return callback('AA cannot be defined in authors');
		// todo: check that the address is really new?
		validateAuthentifiers(arrAddressDefinition);
	}
```

**File:** validation.js (L1747-1781)
```javascript
		case "definition": // for AAs only
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "definition"])) // AA definition cannot be changed and its address is also its definition_chash
				return callback("unknown fields in app definition");
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
			if (constants.bTestnet && ['BD7RTYgniYtyCX0t/a/mmAAZEiK/ZhTvInCMCPG5B1k=', 'EHEkkpiLVTkBHkn8NhzZG/o4IphnrmhRGxp4uQdEkco=', 'bx8VlbNQm2WA2ruIhx04zMrlpQq3EChK6o3k5OXJ130=', '08t8w/xuHcsKlMpPWajzzadmMGv+S4AoeV/QL1F3kBM=', '4N5fsU9qJSn2FuS70cChKx8QqgcesPRPs0dNfzOhoXw='].indexOf(objUnit.unit) >= 0)
				return callback();
			const top_mci = objValidationState.aa_mci || objValidationState.last_ball_mci;
			var readGetterProps = function (aa_address, func_name, cb) {
				storage.readAAGetterProps(conn, aa_address, func_name, top_mci, cb);
			};
			if (!objValidationState.hasBall && !objValidationState.bAA && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci && objValidationState.last_ball_mci < constants.pemCurvesFixMci)
				return callback(createTransientError("AA definition attached to an old part of the DAG"));
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
				if (err)
					return callback(err);
				var template = payload.definition[1];
				if (template.messages)
					return callback(); // regular AA
				// else parameterized AA
				storage.readAADefinition(conn, template.base_aa, top_mci, function (arrBaseDefinition) {
					if (!arrBaseDefinition)
						return callback("base AA not found");
					if (!arrBaseDefinition[1].messages)
						return callback("base AA must be a regular AA");
					callback();
				});
			});
```

**File:** aa_validation.js (L721-781)
```javascript
	var complexity = 0;
	var count_ops = 0;
	var getters = null;
	var count = 0;
	if (!isArrayOfLength(arrDefinition, 2))
		return callback("AA definition must be 2-element array");
	if (arrDefinition[0] !== 'autonomous agent')
		return callback("not an AA");
	var address = constants.bTestnet ? objectHash.getChash160(arrDefinition) : null;
	var arrDefinitionCopy = _.cloneDeep(arrDefinition);
	var template = arrDefinitionCopy[1];
	if (!isNonemptyObject(template))
		return callback('definition must be a non-empty object');
	if (template.base_aa) { // parameterized AA
		if (hasFieldsExcept(template, ['base_aa', 'params']))
			return callback("foreign fields in parameterized AA definition");
		if (!isNonemptyObject(template.params))
			return callback("no params in parameterized AA");
		if (!variableHasStringsOfAllowedLength(template.params))
			return callback("some strings in params are too long");
		if (!isValidAddress(template.base_aa))
			return callback("base_aa is not a valid address");
		return callback(null);
	}
	// else regular AA
	if (hasFieldsExcept(template, ['bounce_fees', 'messages', 'init', 'doc_url', 'getters']))
		return callback("foreign fields in AA definition");
	if ('bounce_fees' in template){
		if (!isNonemptyObject(template.bounce_fees))
			return callback("empty bounce_fees");
		for (var asset in template.bounce_fees){
			if (asset !== 'base' && !isValidBase64(asset, constants.HASH_LENGTH))
				return callback("bad asset in bounce_fees: " + asset);
			var fee = template.bounce_fees[asset];
			if (!isNonnegativeInteger(fee) || fee > constants.MAX_CAP)
				return callback("bad bounce fee: "+JSON.stringify(fee));
		}
		if ('base' in template.bounce_fees && template.bounce_fees.base < constants.MIN_BYTES_BOUNCE_FEE)
			return callback("too small base bounce fee: "+template.bounce_fees.base);
	}
	if ('doc_url' in template && !isNonemptyString(template.doc_url))
		return callback("invalid doc_url");
	if ('getters' in template) {
		if (mci < constants.aa2UpgradeMci)
			return callback("getters not activated yet");
		if (getFormula(template.getters) === null)
			return callback("invalid getters");
	}
	validateFieldWrappedInCases(template, 'messages', validateMessages, function (err) {
		if (err)
			return callback(err);
		validateDefinition(arrDefinitionCopy, function (err) {
			if (err) {
				if (validationErrorDetails)
					return callback(err, validationErrorDetails);
				return callback(err);
			}
			console.log('AA validated, complexity = ' + complexity + ', ops = ' + count_ops);
			callback(null, { complexity, count_ops, getters });
		});
	});
```
