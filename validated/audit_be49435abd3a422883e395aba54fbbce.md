### Title
Unauthenticated Unit Processing Can Trigger an Uncaught `throw Error` That Crashes the Node Process (DoS) - (File: `validation.js`, `network.js`)

### Summary
CVE-2018-11782 describes an Apache Subversion `svnserve` crash: a well-formed, read-only client request drives the server into a code path that has an unhandled `assert`/exit condition, killing the process for all users. `ocore` has an architecturally identical DoS pattern: `validation.js` (the module that validates every unit/joint received from any peer, including units posted by an unprivileged wallet/AA/asset/vote sender) contains numerous "should never happen" `throw Error(...)` statements embedded in asynchronous DB-query callbacks that are **not wrapped in try/catch**. Any such throw escapes the event loop and is caught only by the global `process.on('uncaughtException', ...)` handler in `network.js`, which **deliberately re-throws to crash the whole node process**.

### Finding Description
`validateInlinePayload`'s `vote` handling assumes a poll's `(unit, choice)` pair is unique: [1](#0-0) 

```js
conn.query(
    "SELECT main_chain_index, sequence FROM polls JOIN poll_choices USING(unit) JOIN units USING(unit) WHERE unit=? AND choice=?",
    [payload.unit, payload.choice],
    function(poll_unit_rows){
        if (poll_unit_rows.length > 1)
            throw Error("more than one poll?");
```

This callback runs inside `conn.query`'s asynchronous completion — outside any `try/catch` in the validation call stack (`validate` → `validateMessages` → `validateMessage` → `validateInlinePayload`, see [2](#0-1)  for the only try/catch in the outer `validate()` function, which only wraps the unit-hash computation, not the message-validation phase). If an attacker can get two `poll_choices` rows to exist for the same `(unit, choice)` combination — e.g. by posting a `poll` message whose `choices` array is not checked for duplicate entries before being persisted — a subsequent, perfectly well-formed `vote` message referencing that `unit`/`choice` will cause `poll_unit_rows.length` to be `2`, hitting the `throw`.

Because this throw happens inside a DB callback (not inside the `async.series`/`callback(err)` machinery that `validate()` expects), it is never captured by any of `validate()`'s `ifUnitError`/`ifJointError`/`ifTransientError` handlers. It propagates as an uncaught exception, reaching the top-level handler: [3](#0-2) 

```js
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	...
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

which intentionally rethrows to kill the process. This is the same bug class as CVE-2018-11782: a syntactically valid, unprivileged request drives the server into an internal consistency-check failure that terminates the process rather than being handled as a normal validation error.

The general pattern is not limited to this one `throw`: `handleJoint` in `network.js` also explicitly documents that validation errors can "crash" and that the crashing peer's host is deliberately *not* cleared to slow down repeat DoS attempts, confirming the developers are aware that unit validation can throw and bring the process down: [4](#0-3) 

### Impact Explanation
Any full/relay node that receives and validates the crafted joint (via normal p2p broadcast of a unit, exactly as an ordinary transaction/vote propagates) executes the vulnerable code path and crashes. Because the unit is well-formed and passes all the surrounding structural checks, it will propagate to every peer that has not yet validated it, causing repeated crashes across the network as nodes restart, re-fetch, and re-validate the same poisoned unit — "a network unable to confirm new units" for as long as the poisoned unit keeps being served/retried. This matches the impact bar requested (network disruption / node crash on validation of a legitimately reachable unit).

### Likelihood Explanation
Reachability is high in principle: `vote` and `poll` are both ordinary, unprivileged message apps that any unit poster can include. The only uncertainty (not fully verifiable from the indexed code available) is whether `poll` message validation enforces uniqueness of entries in `payload.choices` before inserting into `poll_choices`; if it does not, constructing the duplicate-choice precondition is trivial and fully within reach of a single crafted unit. This should be confirmed by reviewing the `poll` app's `validateInlinePayload` branch (choices array handling) before this is treated as immediately exploitable, but the crash-on-`throw`/`uncaughtException` design flaw itself is confirmed and applies to this and structurally similar `throw Error(...)` statements scattered through `validation.js`/`definition.js`/`witness_proof.js` reachable from attacker-supplied unit content.

### Recommendation
- Wrap all DB-query callbacks in the message/authentifier/definition validation call chain in `try/catch`, converting unexpected internal-consistency failures into `ifUnitError`/`ifJointError` results instead of allowing them to become uncaught exceptions.
- Change `process.on('uncaughtException', ...)` in `network.js` to avoid an unconditional process-wide crash for errors that originate from validating untrusted, attacker-supplied unit content; at minimum, isolate joint validation in a scope where such exceptions are caught and turned into a validation rejection rather than a full node crash.
- Enforce uniqueness of `poll_choices` (or any other structure whose later `SELECT`s assume row-uniqueness) at `poll`-definition validation time, and audit all other "should never happen" `throw Error(...)` statements in `validation.js`, `definition.js`, and `witness_proof.js` for similar attacker-reachable violations of their invariants.

### Proof of Concept
1. Attacker posts a unit A containing a `poll` message whose `choices` payload contains a duplicate string (e.g. `["yes", "yes"]`), assuming this is not rejected by poll validation, resulting in two `poll_choices` rows with `choice='yes'` for the same poll unit.
2. Once unit A is stable/serial, attacker posts unit B containing a `vote` message with `payload = { unit: <A>, choice: "yes" }`.
3. Any node that validates unit B executes the `vote` case in `validateInlinePayload` (`validation.js:1826-1834`); the `SELECT ... WHERE unit=? AND choice=?` returns 2 rows, triggering `throw Error("more than one poll?")`.
4. The throw escapes uncaught to `network.js`'s `process.on('uncaughtException', ...)` handler, which rethrows, crashing the node process for every peer that validates/relays unit B.

### Citations

**File:** validation.js (L118-138)
```javascript
function validate(objJoint, callbacks, external_conn) {
	
	var objUnit = objJoint.unit;
	if (typeof objUnit !== "object" || objUnit === null)
		throw Error("no unit object");
	if (!objUnit.unit)
		throw Error("no unit");
	
	console.log("\nvalidating joint identified by unit "+objJoint.unit.unit);
	
	if (!isStringOfLength(objUnit.unit, constants.HASH_LENGTH))
		return callbacks.ifJointError("wrong unit length");
	
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** validation.js (L1826-1834)
```javascript
			conn.query(
				"SELECT main_chain_index, sequence FROM polls JOIN poll_choices USING(unit) JOIN units USING(unit) WHERE unit=? AND choice=?", 
				[payload.unit, payload.choice],
				function(poll_unit_rows){
					if (poll_unit_rows.length > 1)
						throw Error("more than one poll?");
					if (poll_unit_rows.length === 0)
						return callback("invalid choice "+payload.choice+" or poll "+payload.unit);
					var objPollUnitProps = poll_unit_rows[0];
```

**File:** network.js (L1166-1173)
```javascript
		mutex.lock(['handleJoint'], function(unlock){
			if (ws && !conf.bLight)
				currentJointHost = ws.host;
			// clear host only if validation completed with any result, otherwise it crashed and we keep it for a while to avoid DoS from the same peer
			const clearHost = () => {
				if (ws && !conf.bLight)
					currentJointHost = null;
			};
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
