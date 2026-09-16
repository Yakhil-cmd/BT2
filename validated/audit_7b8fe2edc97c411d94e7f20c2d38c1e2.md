### Title
Unhandled exception when a self-composed AA response unit fails joint-level validation crashes every full node - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `handleTrigger()` builds an AA response unit from the AA definition's `messages` template combined with attacker-controlled `trigger.data`/`trigger.output` values, and then calls `validation.validate()` on the unit it just constructed via `validateAndSaveUnit()`. Every non-`ifUnitError` outcome of that internal validation call (`ifJointError`, `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`, non-`good` sequence) is treated as "impossible" and handled by `throw Error(...)` instead of being converted into a graceful AA bounce, exactly mirroring the SvelteKit bug where a value assumed to always be safe (a header value / a self-built unit) is not validated before use and an exceptional branch throws an unhandled error. [1](#0-0) 

### Finding Description
`validateAndSaveUnit()` wraps the response unit in a joint and calls `validation.validate()`: [1](#0-0) 

`validation.validate()` performs structural checks before any business-logic checks, including a nesting/size check and a well-formed-string check, both of which return `ifJointError` (not `ifUnitError`) when they fail: [2](#0-1) 

Because `bAA` units go through the same `ifJointError` path (`return bAA ? callbacks.ifUnitError(...) : callbacks.ifJointError(...)` only applies to the nesting check for `objJoint.aa`; note line 155 routes AA units to `ifUnitError` for nesting, but `isObjectWellFormed` on line 157-158 always returns `ifJointError` regardless of `bAA`), a response unit whose message content contains a lone surrogate or a null byte will hit `ifJointError` in `validateAndSaveUnit()`, which unconditionally does:
```js
ifJointError: function (err) { throw Error("AA validation joint error: " + err); },
``` [3](#0-2) 

The message content of the composed response unit is directly derived from attacker-controlled `trigger.data`, which oscript AA definitions are explicitly designed to forward verbatim into outgoing messages (documented/tested pattern of "sending prepared objects through trigger.data"): [4](#0-3) 

This `throw` happens synchronously inside the stabilization pipeline (`markMcIndexStable` → `handlePrimaryAATrigger` → `handleTrigger` → `sendUnit` → `validateAndSaveUnit`), with no surrounding `try/catch` to convert it into a bounce. It therefore propagates all the way up to Node's `uncaughtException` handler, which deliberately rethrows to crash the process: [5](#0-4) 

Since stabilization of the same main-chain unit and the same AA response is computed deterministically and independently by every full node, any trigger unit that drives an AA definition into constructing a response unit whose payload trips `isObjectWellFormed`/nesting limits will crash *every* full node processing that MCI at the same point, not just the attacker's own node.

### Impact Explanation
An unprivileged party posts a single ordinary unit that triggers an AA (any AA whose `messages` template echoes `trigger.data` fields, as in the documented pattern above) with a data field crafted to be an ill-formed string (e.g. a lone UTF-16 surrogate or embedded NUL byte) or a deeply/broadly nested object that exceeds the size/nesting limits once merged into the composed unit. When this trigger unit becomes stable, all full nodes execute `handleTrigger`, build the same non-well-formed response unit, hit `ifJointError` in `validateAndSaveUnit`, and crash via the uncaught-exception handler. This halts stabilization and unit confirmation network-wide until operators restart nodes — a network-unable-to-confirm-new-units denial of service, matching the CWE-755 "improper handling of exceptional condition" class from the reported SvelteKit advisory.

### Likelihood Explanation
Reachable by any address posting a normal payment/trigger unit to a pre-existing, unprivileged AA that forwards `trigger.data` into its outgoing messages — a supported and tested oscript pattern, not a hypothetical misuse. No special privileges, keys, or network position are required; only crafting the string/object shape of the posted trigger data.

### Recommendation
In `aa_composer.js`'s `validateAndSaveUnit`, do not `throw` on `ifJointError`/`ifTransientError`/`ifNeedHashTree`/`ifNeedParentUnits`/non-`good` sequence outcomes for internally composed units; instead treat them as an AA execution failure and call `bounce()`/`cb(err)` the same way `ifUnitError` is already handled. Additionally, proactively validate/sanitize (or reject) `trigger.data` values and templated message payloads for well-formedness and nesting/size limits before composing the response unit, so failures surface as ordinary bounces rather than uncaught exceptions.

### Proof of Concept
1. Deploy an AA whose `messages` echoes `trigger.data` into an outgoing message payload, e.g. the pattern in `test/samples/sending_prepared_objects_through_trigger_data.oscript` (`payload: "{trigger.data.d}"`).
2. Post a trigger unit whose `data.d` is (or decodes/concatenates within the formula engine to) a string containing a lone surrogate code point or embedded NUL byte, sized so the resulting composed response unit fails `isObjectWellFormed` in `validation.js`.
3. When the trigger unit stabilizes, every full node's `handleTrigger` → `sendUnit` → `validateAndSaveUnit` receives `ifJointError`, which throws, is caught by `process.on('uncaughtException')`, and crashes the node process, halting confirmation of new units network-wide.

### Citations

**File:** aa_composer.js (L1800-1824)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
```

**File:** validation.js (L154-158)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");

	if (!isObjectWellFormed(objJoint))
		return bAA ? callbacks.ifUnitError("unit contains invalid string (lone surrogate or null byte)") : callbacks.ifJointError("unit contains invalid string (lone surrogate or null byte)");
```

**File:** test/samples/sending_prepared_objects_through_trigger_data.oscript (L1-32)
```text
{
	messages: [
		{
			if: `{trigger.data.d}`,
			app: 'data',
			payload: `{trigger.data.d}`
		},
		{
			if: `{trigger.data.sub}`,
			app: 'data',
			payload: {
				xx: 66.3,
				sub: `{trigger.data.sub}`
			}
		},
		{
			if: `{trigger.data.output}`,
			app: 'payment',
			payload: {
				asset: "base",
				outputs: [
					`{trigger.data.output}`
				]
			}
		},
		{
			if: `{trigger.data.payment}`,
			app: 'payment',
			payload: `{trigger.data.payment}`
		},
	]
}
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
