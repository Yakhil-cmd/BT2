## Title
Uncaught TypeError from a malformed AA-getter/attestation formula crashes the node - (File: formula/evaluation.js)

## Summary
The external report describes a NULL-pointer dereference in LibSass's `Sass::Inspect::operator` — attacker-controlled input reaching a code path that dereferences an unchecked pointer and crashes the process. The analogous bug class in `ocore` is an **unchecked/undefined property dereference inside AA formula evaluation** that throws an uncaught `TypeError`, which is explicitly configured to **crash the whole node process**.

## Finding Description
`network.js` installs a global handler that intentionally kills the process on any uncaught exception: [1](#0-0) 

This means any unhandled JS exception thrown while validating a unit, executing an AA trigger, or evaluating an oscript formula is fatal to the whole node (full/witness/hub), not just to the individual request. This makes exception-based crashes in reachable, attacker-influenced code paths a first-class DoS vector, structurally analogous to the LibSass NULL dereference.

`formula/evaluation.js` — the oscript interpreter invoked whenever any user posts a trigger to an AA, or an AA's own formula runs against attacker-supplied `trigger.data`/`params` — contains multiple code paths that read a property off a value without first verifying its type/existence, instead of returning a graceful "fatal_error" via `setFatalError`. For example, in the `attestation` operator handler: [2](#0-1) 

`params.address` is accessed unconditionally at `params.address.value` (line 912) even though `params.address` may be absent if the AA author's formula omits it or a getter/param evaluates to an object lacking the key; likewise `params.attestors.value` is dereferenced at line 908 with no existence check before the `typeof` guard at line 906. Any code path of this shape — property access on a value whose presence was never validated — throws a plain JS `TypeError: Cannot read properties of undefined`, which is **not** caught by the `try/catch` that only wraps the nearley parser instantiation (`formula/evaluation.js:108-121`); it propagates up through `evaluate`'s callback chain, out of `formulaParser.evaluate`, through `aa_composer.js`'s `handleTrigger`/`evaluateAA`, and ultimately becomes an uncaught exception at the process level.

The equivalent formula/AA definitions (including `attestation[[...]]`) are ordinary constructs that any AA author can define, and any address can trigger by simply sending a unit to the AA — no special privilege, no malicious peer/hub, no p2p manipulation is required, matching this scan's reachability constraints (unprivileged unit poster / AA trigger sender).

## Impact Explanation
Because the process purposefully calls `throw err` inside the `uncaughtException` handler to "crash the process to avoid ending up in an inconsistent state" [3](#0-2) , triggering such a TypeError deep in formula evaluation brings down the entire node (witness, hub, or full node) that processes the trigger. If reproduced consistently against multiple witnesses/hubs (each independently evaluating the same AA trigger unit as it becomes part of the DAG), this becomes a network-wide denial-of-service that prevents confirmation of new units — the same "denial of service (application crash)" impact class cited in CVE-2018-11696, but here escalated by ocore's fail-fast crash policy.

## Likelihood Explanation
Medium-High. Exploitation requires:
1. An AA whose oscript uses `attestation[[...]]` (or another formula construct) in a way where a referenced field can become `undefined` at evaluation time (e.g., via a conditional `params`/getter path, or a value computed through user-controllable `trigger.data`).
2. An attacker to post a trigger unit that drives execution into that branch.

Because AA definitions are permissionless (anyone can post an `autonomous agent` definition) and triggers are permissionless (anyone can send a payment/data message to any AA address), an attacker who controls or can influence an AA definition (or who finds an existing public AA with such a formula bug) can reliably reach this crash. This is lower-effort than a targeted memory-safety bug: it's a straightforward JS type-confusion issue exploitable purely through oscript.

## Recommendation
- Audit `formula/evaluation.js` for every place that accesses `.value`/nested properties on `params`, `evaluated_params`, or getter-returned objects without a `hasOwnProperty`/type check, and route all such failures through `setFatalError(...)` (which safely resolves via the `cb`/`fatal_error` mechanism) rather than letting a raw property access throw.
- Wrap the top-level `evaluate()` dispatcher (or at least each `case` handler) in a `try/catch` that converts any unexpected exception into a `setFatalError` result instead of letting it propagate to `aa_composer.js` and ultimately to the process-level `uncaughtException` handler.
- Add a regression test corpus of formulas that intentionally omit optional AST fields (`attestors`, `address`, `ifseveral`, `type`, etc.) to ensure they fail gracefully (return `null`/bounce) rather than throwing.
- Consider making the process-level `uncaughtException` handler distinguish between validation/formula-evaluation errors (recoverable — bounce the trigger, do not crash) and genuinely unrecoverable state-corruption errors, rather than crashing on every uncaught exception.

## Proof of Concept
Conceptual PoC (would need to be validated in a running testnet/AA-testing harness since this analysis is based on static code review, not execution):
1. Publish an AA whose response formula includes an `attestation[[...]]` expression where the `address` (or another required sub-field) is supplied via a param/getter path that can legitimately evaluate to `false`/omitted for some trigger inputs, e.g.:
   ```
   {
     messages: [{
       app: 'data',
       payload: { r: `attestation[[attestors=$oracle, address=$maybe_missing]].email` }
     }]
   }
   ```
   where `$maybe_missing` is derived from `trigger.data` such that, for a crafted trigger, the evaluated `params.address` ends up `undefined` rather than a string.
2. Send a trigger unit to this AA with `trigger.data` chosen so that the `address` parameter path evaluates to a value lacking a `.value` property (e.g., an object literal that omits the key), reaching `formula/evaluation.js:912` (`params.address.value`).
3. Observe the AA-composer's formula evaluation throw an uncaught `TypeError`, which is not caught anywhere in the call chain and reaches `network.js`'s `process.on('uncaughtException', ...)`, causing `throw err` and terminating the witness/hub/full node process.

**Uncertainty**: I was not able to execute the AA formula engine to confirm the exact conditions under which `params.address` (or similarly accessed fields) becomes `undefined` rather than `false`/a validated string — this would require dynamic testing of the oscript parser/validator (`formula/validation.js`) to determine whether it already rejects all such malformed ASTs at validation time (before evaluation). If `formula/validation.js` fully guarantees that these fields are always present and string-typed by the time `evaluate()` runs, this specific example would be mitigated at validation and a different unguarded-access site in `evaluation.js` would need to be identified as the concrete crash vector. I recommend a Devin session with code execution access to fuzz `formulaParser.validate`/`formulaParser.evaluate` with malformed but validation-passing ASTs to confirm a concrete unguarded dereference.

### Citations

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

**File:** formula/evaluation.js (L906-931)
```javascript
						if (typeof params.attestors.value !== 'string')
							return setFatalError('attestors is not a string', { arr }, false, cb);
						var arrAttestorAddresses = params.attestors.value.split(':');
						if (!arrAttestorAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad attestors', { arr }, false, cb);

						var v = params.address.value;
						if (!ValidationUtils.isValidAddress(v))
							return setFatalError('bad address in attestation: ' + v, { arr }, false, cb);

						var ifseveral = 'last';
						if (params.ifseveral) {
							ifseveral = params.ifseveral.value;
							if (ifseveral !== 'last' && ifseveral !== 'abort')
								return setFatalError('bad ifseveral ' + ifseveral, { arr }, false, cb);
						}

						var type = 'auto';
						if (params.type) {
							type = params.type.value;
							if (type !== 'string' && type !== 'auto')
								return setFatalError('bad att type ' + type, { arr }, false, cb);
						}

						if (field === null) // special case when we are not interested in any field, just the fact of attestation
							field = false;
```
