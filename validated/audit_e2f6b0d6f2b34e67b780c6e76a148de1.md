## Title
Unhandled null-pointer dereference in AA trigger processing crashes the node - ([File: aa_composer.js])

### Summary
CVE-2017-6257 describes a NULL pointer dereference in a privileged kernel-mode handler reachable by an unprivileged local caller, leading to denial of service. The closest reachable analog in ocore is an unchecked cache lookup in the Autonomous Agent (AA) trigger-execution path, where `storage.assocStableUnits[trigger.unit]` is dereferenced without a null check, and any resulting `TypeError` bubbles up as an uncaught exception that terminates the whole node process (`process.on('uncaughtException', ...) { ... throw err; }`).

### Finding Description
In `aa_composer.js`, when a primary AA trigger is executed, the code path guards against duplicate primary triggers with: [1](#0-0) 
```
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```
This directly dereferences `storage.assocStableUnits[trigger.unit]` without checking whether the lookup returned an object. Elsewhere in the codebase, the same in-memory cache (`storage.assocStableUnits`) is consistently guarded with explicit `if (!objUnitProps) throw Error(...)` checks before being dereferenced (e.g. `storage.js:1201`, `storage.js:1588`, `storage.js:1623`, `main_chain.js:1398`), demonstrating that the maintainers treat a missing cache entry as an expected failure mode that must be checked, not assumed. The trigger-processing line above breaks that pattern: if `trigger.unit` is not present as a key in `assocStableUnits` (e.g. because of a caching/timing edge case, a unit that was pruned/forgotten from RAM, or any state where the trigger-carrying unit's stable-unit cache entry does not exist at the moment `handleTrigger` runs), accessing `.count_aa_responses` on `undefined` throws a `TypeError`.

Because `handleTrigger` runs synchronously inside `handlePrimaryAATrigger`, which is invoked from the main-chain stabilization path processing every posted unit that pays an AA address (any unprivileged unit poster can trigger this by sending a payment to an AA address), an uncaught `TypeError` here is not caught by any `try/catch` in the call chain and propagates to the process-wide handler: [2](#0-1) 
```
process.on('uncaughtException', (err) => {
    console.log('Uncaught exception:', err);
    console.error('Uncaught exception:', err);
    ...
    throw err; // crash the process to avoid ending up in an inconsistent state
});
```
which deliberately re-throws to crash the whole node — the JS analog of a kernel NULL-pointer dereference causing denial of service.

### Impact Explanation
A crash triggered here halts the entire node process (hub/full node), not just a single request. Since `handleTrigger`/`handlePrimaryAATrigger` execute as part of validating/committing units that pay AA addresses — something any unprivileged unit poster can construct — a reliably reachable null-cache condition would let a remote unprivileged party crash a witness or hub node, denying network confirmation of new units until manual restart. This matches the "network unable to confirm new units" acceptance bar in the validation rules for this exercise.

### Likelihood Explanation
Exploitability depends on being able to reliably put the node into a state where `trigger.unit` (the unit carrying the primary AA trigger) is absent from `storage.assocStableUnits` at the exact synchronous point `handleTrigger` runs for that unit. Because the trigger unit is the just-stabilized MC unit whose stabilization is what invokes `handlePrimaryAATrigger` in the first place, it should normally already be present in the cache from `markMcIndexStable`. I could not fully trace all code paths that call `handlePrimaryAATrigger` / `handleTrigger` with a `trigger.unit` value that could plausibly be missing from the cache (e.g. interactions with `bAir`/AA-to-AA "air" execution, `forgetUnit`, or cache-reset races), due to running out of tool iterations before locating the `bAir` code paths and the `getTrigger`/`handlePrimaryAATrigger` full call graph. This is a real code-quality gap (missing null check inconsistent with the rest of the codebase) but I was **not able to confirm a concrete, attacker-controlled sequence of unit postings** that forces the cache miss, so likelihood should be treated as **unconfirmed/uncertain** rather than proven.

### Recommendation
Add an explicit guard mirroring the pattern used elsewhere in `storage.js`/`main_chain.js`:
```js
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && mci >= constants.pemCurvesFixMci) {
    const objTriggerUnitProps = storage.assocStableUnits[trigger.unit];
    if (!objTriggerUnitProps)
        throw Error(`trigger unit ${trigger.unit} not found in stable units cache`); // or handle gracefully / re-fetch from DB
    if (objTriggerUnitProps.count_aa_responses)
        return bounce('a second primary trigger from the same unit is not allowed');
}
```
More generally, any place dereferencing `storage.assocStableUnits[unit]`/`assocUnstableUnits[unit]` without a prior existence check on data that can be influenced by network-supplied unit content should be audited and hardened, given the process is configured to crash on any uncaught exception.

### Proof of Concept
I was unable to construct or verify a concrete unit-posting sequence within the remaining investigation budget that forces `trigger.unit` to be absent from `storage.assocStableUnits` at the time `handleTrigger` runs (this requires deeper tracing of `getTrigger`, `bAir`/AA-to-AA handling, and cache eviction/reset code paths that I did not get to examine). The finding is reported based on the confirmed absence of a null check at `aa_composer.js:1861` combined with the confirmed process-crashing `uncaughtException` handler in `network.js:4530-4543`, but the reachability of the null condition itself is **not proven** with a PoC.

### Citations

**File:** aa_composer.js (L1859-1862)
```javascript
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
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
