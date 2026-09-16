## Title
Missing null check on `storage.assocStableUnits[trigger.unit]` before property access can crash the full node during AA-trigger processing - (File: `aa_composer.js`)

### Summary
CVE-2021-32844 is a missing-null-check bug in HyperKit's `vi_pci_write`/`vc_cfgwrite` path where a guest-controlled call reaches code that dereferences a value without verifying it is non-null, crashing the host process (DoS). The analogous pattern in ocore is a direct property access on a cache-map lookup that is not guaranteed to be populated, located in the AA-trigger execution path that is reachable by any unprivileged unit poster who sends a payment to an Autonomous Agent address.

### Finding Description
In `handleTrigger()`, right before evaluating an AA's oscript, there's a check meant to prevent a second primary trigger from the same unit: [1](#0-0) 

```js
// skip this check for dry-run which uses genesis unit as trigger unit
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```

`storage.assocStableUnits[trigger.unit]` is a plain object-map lookup that returns `undefined` if `trigger.unit` is not currently cached as a stable unit (e.g., it has been forgotten via `forgetUnit()`, or the cache was reset/pruned, or the trigger comes from a code path where the unit hasn't yet been (re-)inserted into `assocStableUnits`). The code immediately accesses `.count_aa_responses` on that result without a null/undefined guard, unlike every other lookup of this cache elsewhere in the codebase (e.g., `aa_composer.js:104-106`, which explicitly checks `if (!objUnitProps) throw Error(...)` before use). If `storage.assocStableUnits[trigger.unit]` is `undefined` at this call site, `.count_aa_responses` throws an uncaught `TypeError: Cannot read properties of undefined`.

This is the same bug class as the CVE: a value obtained from an internal data structure is not verified for existence/null before being dereferenced in a code path reachable from an external, untrusted actor (a guest device in HyperKit; an unprivileged unit-poster/AA-trigger sender in ocore), and the result is a process crash rather than a graceful error. [2](#0-1) 

### Impact Explanation
`handleTrigger()` is invoked for every primary AA trigger executed when an MCI stabilizes (`handlePrimaryAATrigger` → `handleTrigger`), a path triggered purely by posting a payment unit to an AA address — something any network participant can do without special privileges. If the guard condition can be hit with `storage.assocStableUnits[trigger.unit]` being `undefined` (e.g. due to cache eviction/forgetting timing, light-vs-full node cache differences, or restart/replay scenarios where the trigger unit isn't yet re-populated in the in-memory cache), the resulting uncaught `TypeError` is thrown synchronously inside the trigger-processing chain in `stabilizeMci()`/`handleAATriggers()`. Because there is no `try/catch` around this specific access and the network layer's `uncaughtException` handler (`network.js`) is the last line of defense, this can abort the process that is actively stabilizing units — i.e., a node crash during core consensus-critical unit stabilization. If reproducible deterministically by a crafted trigger, this could be leveraged to repeatedly crash full nodes (a denial-of-service against the network's ability to process/confirm units), which matches the "network unable to confirm new units" impact bar.

### Likelihood Explanation
The likelihood is moderate to low-confidence without dynamic reproduction: I could not fully verify from static analysis alone the exact conditions under which `storage.assocStableUnits[trigger.unit]` would be `undefined` at this specific call site for a *primary* (non-dry-run) trigger, since `assocStableUnits` is normally populated when a unit becomes stable (which happens just before triggers for that unit are processed). It is plausible under cache-reset paths (e.g. `storage.resetMemory`), long-running catch-up/replay flows, or interactions with `forgetUnit()`/pruning that could desynchronize the in-memory cache from the trigger execution timing. This uncertainty should be resolved by dynamic testing/tracing of `assocStableUnits` population versus `handleTrigger` invocation timing, which requires runtime access beyond what static code search can confirm.

### Recommendation
Add an explicit existence check before dereferencing the cache entry, mirroring the pattern already used elsewhere in the same file:
```js
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && mci >= constants.pemCurvesFixMci) {
    var objTriggerUnitProps = storage.assocStableUnits[trigger.unit];
    if (objTriggerUnitProps && objTriggerUnitProps.count_aa_responses)
        return bounce('a second primary trigger from the same unit is not allowed');
}
```
Additionally, audit all other direct `storage.assocStableUnits[...]`, `assocUnstableUnits[...]`, and similar cache-map accesses across `aa_composer.js`, `main_chain.js`, and `storage.js` for missing null guards before property access, since this is a recurring pattern class rather than a single isolated instance.

### Proof of Concept
A deterministic, network-reachable PoC could not be fully constructed via static review alone; exploitation would require crafting a scenario where a primary AA trigger unit's entry is absent from `storage.assocStableUnits` at the moment `handleTrigger()` runs the bounce-fee/duplicate-trigger check (e.g., by controlling cache eviction/restart timing relative to submitting a trigger unit to an AA). This requires dynamic testing against a running node/testnet to confirm reachability and reliability, which was outside the scope of static code search.

### Citations

**File:** aa_composer.js (L91-109)
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
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
```

**File:** aa_composer.js (L1860-1862)
```javascript
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
```
