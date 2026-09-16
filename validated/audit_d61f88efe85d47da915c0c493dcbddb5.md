## Title
Uncaught exception crashes full nodes when a parameterized AA references a non-existent `base_aa` at trigger time - (File: aa_composer.js)

## Summary
This is analogous to the Ghostscript null-pointer dereference (`ALPINE-CVE-2020-16306`): a crafted-but-structurally-valid input causes an unchecked code path to dereference a missing value and crash the process. In ocore, an unprivileged unit poster can define a parameterized AA whose `base_aa` field is a syntactically valid address that does not correspond to any actual AA definition. When any unprivileged trigger sender later sends a payment to that AA, `aa_composer.js` throws an uncaught `Error` deep inside an asynchronous callback chain, which is never caught and crashes the Node.js process via the global `uncaughtException` handler.

## Finding Description
`validateAADefinition` in [1](#0-0)  only checks that `template.base_aa` is a *syntactically* valid address (`isValidAddress`). It never verifies that `base_aa` actually resolves to an existing/valid AA definition at the time the parameterized AA definition itself is posted and validated — this is by design, since the base AA could legitimately be defined later.

However, when a trigger for such a parameterized AA is executed, `handleTrigger` in `aa_composer.js` unconditionally reads the base AA definition and throws if it is missing, with no `try/catch` around the call: [2](#0-1) 

This code runs inside the asynchronous callback chain `handleAATriggers` → `handlePrimaryAATrigger` → `readUnit` → `handleTrigger`, none of which wrap the call in a `try/catch`: [3](#0-2) 

Because the `throw` happens inside a database-callback (asynchronous) context rather than inside a synchronous call stack protected by a `try`, it becomes an uncaught exception. ocore's global handler explicitly re-throws to crash the process rather than recover: [4](#0-3) 

## Impact Explanation
Any full node (light nodes are unaffected since they don't execute AAs) that processes the trigger unit for a parameterized AA with a dangling `base_aa` will crash with an uncaught exception. Because AA triggers are processed deterministically by every full node that has caught up to that main-chain index, this is not a local crash but a network-wide fault: every full node (witnesses included) that reaches the same trigger will crash identically, halting main-chain progression and the network's ability to confirm new units — matching the "network unable to confirm new units" bar required by the validation rules.

## Likelihood Explanation
The prerequisite is trivial and fully within reach of a single unprivileged unit poster:
1. Post an AA definition of the form `['autonomous agent', {base_aa: '<any syntactically valid but AA-less address>', params: {...}}]`. This passes `validateAADefinition` unconditionally, per [1](#0-0) .
2. Send a payment (trigger) to the resulting AA address.

No special privileges, timing, or race conditions are required — the crash occurs deterministically as soon as `handlePrimaryAATrigger` processes the trigger.

## Recommendation
In `aa_composer.js`, replace the `throw Error(...)` at [5](#0-4)  with a graceful bounce of the trigger (treat it the same way other invalid-AA-state conditions are handled elsewhere in `handleTrigger`, i.e., call the bounce/`onDone` path with an error message) instead of throwing. Additionally, consider validating at definition-acceptance time (or at minimum at trigger time before touching balances) that `base_aa` currently resolves to a valid AA, and reject/bounce triggers targeting AAs whose `base_aa` cannot be resolved, rather than letting an unhandled exception propagate.

## Proof of Concept
1. Post unit `U1` defining AA `A` at address `addrA`:
   ```json
   ["autonomous agent", { "base_aa": "<VALID_FORMAT_ADDRESS_WITH_NO_AA_DEFINITION>", "params": { "x": 1 } }]
   ```
   This passes validation per [1](#0-0) .
2. Post unit `U2`: a payment sending funds to `addrA`, satisfying `checkAAOutputs` bounce-fee requirements (see [6](#0-5) ).
3. When `U2` stabilizes, `handleAATriggers` picks it up and calls `handlePrimaryAATrigger` → `handleTrigger`, which attempts `storage.readAADefinition(conn, template.base_aa, mci, ...)`. Since no AA is defined at that address, `arrBaseDefinition` is `null`/falsy, and the `throw Error("base AA not found: " + template.base_aa)` executes inside the async callback with no enclosing `try/catch`, propagating to `process.on('uncaughtException')` in [4](#0-3)  and crashing the node.

Note: I was not able to fully verify within the available search budget whether `validateAATrigger` (referenced in `validation.js`) or another pre-trigger-execution check independently blocks acceptance of triggers to AAs with an unresolved `base_aa`; if such a check exists, it would need to be confirmed to fully close this path. Based on the code paths I was able to inspect, no such guard was found before `handleTrigger` dereferences the base AA definition.

### Citations

**File:** aa_validation.js (L734-743)
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
```

**File:** aa_composer.js (L91-101)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
```

**File:** aa_composer.js (L433-444)
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
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

**File:** aa_addresses.js (L120-156)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (err, rows) {
		if (err)
			return handleResult(err);
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
}
```
