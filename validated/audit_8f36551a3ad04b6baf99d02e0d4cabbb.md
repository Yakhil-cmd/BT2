### Title
Parameterized AA addresses are derived only from `base_aa` + `params` with no deployer-specific salt, causing unrelated triggers to collide on the same AA address and share state/funds - ([File: aa_validation.js])

### Summary
A parameterized Autonomous Agent's address is computed deterministically as `objectHash.getChash160(['autonomous agent', {base_aa, params}])`, exactly analogous to the Sherlock finding where a `CREATE2` salt derived only from user-supplied constructor args (`rewardRecipient`, `duration`) allows two unrelated deployers to collide on the same contract address.

### Finding Description
When a unit defines a parameterized AA (via an author's own address definition, or via an in-AA `definition` message), the resulting address is:
`address = getChash160(['autonomous agent', {base_aa, params}])`
as seen in `test/aa_composer.test.js:684-689` (`parameterized_aa_address = objectHash.getChash160(parameterized_aa)`), and the runtime redirect logic that treats `base_aa` + `params` as the sole identity of a parameterized AA is at [1](#0-0) . Validation of a new parameterized AA definition only checks that `base_aa` exists and is a regular AA — it never checks whether this exact `(base_aa, params)` pair was already claimed by an unrelated party for a different real-world purpose: [2](#0-1) . The `aa_validation.validateAADefinition` function likewise only validates structural correctness of `params`, not uniqueness of intent: [3](#0-2) .

Because the address encodes only `base_aa` and `params` (no deployer/trigger identity, no nonce), any two independent triggers or AAs that happen to choose the same `base_aa` and the same `params` values (e.g., the same recipient address and the same duration/fee, exactly the collision described in the Sherlock report) will resolve to the identical AA address. All balance and `state` vars for that address are stored keyed only by that address in `aa_addresses`/state tables, e.g. `readAAGetterProps`/`readBaseAADefinitionAndParams` in [4](#0-3) , so once collided, the two "different" logical deployments become one and the same on-chain object, sharing balance and state.

### Impact Explanation
If a `base_aa` template implements something like an escrow/vesting/vault pattern keyed by `params` (recipient, amount thresholds, duration, etc.), an attacker (or even benign second user) who independently deploys with the same `params` will end up funding/controlling the exact same AA instance as the first user. Funds sent by the second party commingle with the first party's balance and state at that address, and subsequent AA logic (payouts, unlocks, distributions) operates on the merged balance/state rather than per-depositor isolation the users each believed they had. This can lead to AA fund loss/misallocation for one of the two colliding parties, matching the "AA fund loss or freezing" impact criterion.

### Likelihood Explanation
Collision requires only that two independent actors choose an identical `base_aa` and identical `params` object (byte-for-byte, since `params` is hashed as part of the definition) — plausible whenever a `base_aa` template is popularized with a small/finite set of natural parameter values (e.g., "everyone escrows to the platform fee address for 30 days"), exactly the scenario flagged in the original report. No malicious network position is needed; it can happen from ordinary concurrent use of a popular `base_aa`.

### Recommendation
Include an explicit uniqueness component in the parameterized-AA address derivation or provide a supported mechanism (e.g., an application-level nonce/creator field required in `params`, or validation that rejects re-definition of an already-existing `base_aa`+`params` combination that was created by a different address/trigger) so that independent deployments cannot silently collapse into a single shared AA instance. At minimum, document this determinism clearly so template authors are required to bind `params` to a unique identifier (e.g., include the creator's address in `params`) to guarantee address uniqueness.

### Proof of Concept
1. Deploy `base_aa` implementing an escrow that pays `params.recipient` after `params.duration` from `trigger.address`'s deposit, tracked via `balance[base]`/`state` vars scoped to `this_address` only.
2. User X posts a `definition` message with `{base_aa, params: {recipient: R, duration: 30}}`, deriving address `Z = getChash160([...])`, and sends 1000 bytes to `Z`, as in [5](#0-4)  pattern for generated child AA addresses.
3. User Y, unaware of X, independently wants an escrow with the same recipient `R` and same `duration: 30` (natural, common values) and sends funds to the same computed address `Z`.
4. Because `aa_validation.validateAADefinition` and `validation.js`'s `definition` app handler at [2](#0-1)  perform no owner/creator uniqueness check, both deposits land in the same AA address `Z`, and the escrow's state vars/balance are shared — payout logic distributes the combined balance according to a single state, not per-depositor, causing fund misallocation between X and Y.

### Citations

**File:** aa_composer.js (L433-445)
```javascript
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
		});
		return;
	}
```

**File:** validation.js (L1770-1781)
```javascript
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

**File:** aa_validation.js (L734-744)
```javascript
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
```

**File:** storage.js (L813-828)
```javascript
function readBaseAADefinitionAndParams(conn, address, to_mci, handleDefinitionAndParams) {
	if (!handleDefinitionAndParams)
		return new Promise(resolve => readBaseAADefinitionAndParams(conn, address, to_mci, (arrBaseDefinition, params, storage_size) => resolve({ arrBaseDefinition, params, storage_size })));
	readAADefinition(conn, address, to_mci, function (arrDefinition, unit, storage_size) {
		if (!arrDefinition)
			return handleDefinitionAndParams(null);
		var base_aa = arrDefinition[1].base_aa;
		if (!base_aa)
			return handleDefinitionAndParams(arrDefinition, null, storage_size);
		readAADefinition(conn, base_aa, to_mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + base_aa);
			handleDefinitionAndParams(arrBaseDefinition, arrDefinition[1].params, storage_size);
		});
	});
}
```

**File:** test/aa_composer.test.js (L944-976)
```javascript
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
```
