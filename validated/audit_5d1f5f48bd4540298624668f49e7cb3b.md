### Title
Unguarded property access on `storage.assocStableUnits[trigger.unit]` in AA primary-trigger bounce check causes a crash inside an open DB write transaction - (File: aa_composer.js)

### Summary
`CVE-2018-19624` is a NULL-pointer-dereference crash in Wireshark's PVFS dissector reached by feeding it attacker-controlled, malformed data that the dissector assumed was always well-formed. The structural analog in `ocore` is `handleTrigger()` in `aa_composer.js`, which assumes `storage.assocStableUnits[trigger.unit]` is always a populated object and dereferences `.count_aa_responses` on it without a null/undefined check, unlike every other access to this same map elsewhere in the codebase, which does check with `if (!objUnitProps) throw ...` (see `aa_composer.js:104-106` and `main_chain.js:1588-1589`).

### Finding Description
In `aa_composer.js`, inside `handleTrigger()`: [1](#0-0) 

```
if (!bSecondary) {
    if ((trigger.outputs.base || 0) < bounce_fees.base) {
        return bounce('received bytes are not enough to cover bounce fees');
    }
    for (var asset in trigger.outputs) { ... }
    // skip this check for dry-run which uses genesis unit as trigger unit
    if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
        return bounce('a second primary trigger from the same unit is not allowed');
}
```

`storage.assocStableUnits[trigger.unit]` is indexed directly and `.count_aa_responses` is read from the result without checking that the lookup returned an object. Every other place in the codebase that performs this exact same lookup pattern treats a missing entry as a fatal, must-not-happen condition and guards it explicitly: [2](#0-1) [3](#0-2) 

This shows the codebase's own invariant is that `assocStableUnits[unit]` can legitimately be `undefined` in edge cases and must be defended against — the code at line 1861 violates that invariant. `handleTrigger()` is invoked from `handlePrimaryAATrigger()`, which is itself invoked from `handleAATriggers()`, called synchronously from within `writer.saveJoint()`'s post-commit continuation and from `stabilizeMci()`/`markMcIndexStable()` — all of which are running **inside or immediately after an open DB transaction with `mutex.lock(['write']/['aa_triggers'])` held** (see `main_chain.js:1263-1276`, `writer.js:724-727`, `aa_composer.js:59-89, 91-97`). If the property lookup throws a `TypeError: Cannot read properties of undefined (reading 'count_aa_responses')`, this is an uncaught synchronous exception thrown deep inside an `async.eachSeries`/callback chain with no surrounding `try/catch`, which will propagate up and crash the Node.js process (uncaught exception) while a `BEGIN`ed transaction and the `aa_triggers`/`write` mutex are held.

### Impact Explanation
Because this code runs during main-chain stabilization and AA-trigger dispatch — a path every full node must execute identically to remain in consensus — an uncaught crash here:
- Terminates node processing while a database transaction/mutex is held, which on restart can require replay/recovery and, in mixed fleets, causes different nodes to diverge on whether/when a given MCI's AA triggers were fully processed (node disagreement on stability/validity).
- Because AA trigger execution is mandatory for reaching consensus on subsequent units (bounce/response units, balances, state vars all depend on it), repeated crashes at this line effectively halt a node's ability to confirm new units built on top of the affected MCI, matching the "network unable to confirm new units" impact class.

This is a Medium-severity, single-poster-reachable crash class, analogous to the Wireshark PVFS dissector NULL deref (crash on malformed/unexpected data reachable by an ordinary user), not an RCE.

### Likelihood Explanation
The reachability of `storage.assocStableUnits[trigger.unit]` being `undefined` at this exact call site could not be fully confirmed from the available code/index: in the normal flow, `markMcIndexStable()` populates `storage.assocStableUnits[unit]` for every unit stabilized in the current MCI batch before `handleAATriggers()` is invoked (`main_chain.js:1296-1307` runs prior to `main_chain.js:1691-1723`/`aa_composer.js:59-89`), which would normally guarantee the entry exists for a genuine primary-trigger unit. However:
- The lookup is unconditionally unguarded, unlike the equivalent lookups elsewhere in the same file and in `main_chain.js`, which strongly suggests the original authors considered this map access unsafe in general and simply missed guarding this specific occurrence.
- Any code path that races the trigger dispatch queue against cache eviction/reset (e.g., `storage.resetMemory()` called from `writer.js:712` on a rollback of a *different*, concurrently processed unit, or interactions between `estimatePrimaryAATrigger`/`dryRunPrimaryAATrigger`'s cache mutation-and-revert via `revertResponsesInCaches()` and the real `handlePrimaryAATrigger` queue) could plausibly leave `assocStableUnits[trigger.unit]` stale/absent when the real trigger is processed later from the persistent `aa_triggers` table (`handleAATriggers()` reads it back from SQL independently of the in-memory cache state).

I could not fully trace every code path in `main_chain.js`/`writer.js` that mutates or resets `storage.assocStableUnits` relative to the exact timing of `handleTrigger()`'s bounce-fee check to give a definitive proof-of-concept trigger sequence; this would require deeper tracing of `storage.resetMemory()` and the AA response revert paths than is possible from the indexed excerpts alone. I am flagging this with the confidence appropriate to a plausible-but-unconfirmed crash primitive, not a proven one.

### Recommendation
Add the same defensive guard used two call sites earlier in the same function (`aa_composer.js:104-106`) at line 1861:
```js
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && mci >= constants.pemCurvesFixMci) {
    const objTriggerUnitProps = storage.assocStableUnits[trigger.unit];
    if (!objTriggerUnitProps)
        throw Error(`handleTrigger: unit ${trigger.unit} not found in cache`); // or bounce gracefully
    if (objTriggerUnitProps.count_aa_responses)
        return bounce('a second primary trigger from the same unit is not allowed');
}
```
Additionally, audit all other direct `storage.assocStableUnits[...]` / `storage.assocUnstableUnits[...]` index accesses in `aa_composer.js`, `main_chain.js`, and `writer.js` for the same unguarded-access pattern, and ensure any thrown error during AA trigger handling is caught and converted into a controlled bounce/rollback rather than an uncaught process-level exception while transaction/mutex resources are held.

### Proof of Concept
A concrete reproducible trigger sequence could not be fully constructed from the code available in the index (see Likelihood Explanation for the specific gap — the interaction between `estimatePrimaryAATrigger`/`dryRunPrimaryAATrigger` cache mutation/revert and the real `handlePrimaryAATrigger` queue would need to be traced in full, live code, ideally with a Devin session that can run the test suite and instrument `storage.assocStableUnits` mutations, to confirm whether `trigger.unit` can be absent from the map at the point `handleTrigger()`'s bounce-fee check executes for a genuine (non-dry-run, non-air) primary trigger).

### Citations

**File:** aa_composer.js (L102-109)
```javascript
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
```

**File:** aa_composer.js (L1850-1862)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
```

**File:** main_chain.js (L1587-1592)
```javascript
								function addDataFeeds(payload){
									if (!storage.assocStableUnits[unit])
										throw Error("no stable unit "+unit);
									var arrAuthorAddresses = storage.assocStableUnits[unit].author_addresses;
									if (!arrAuthorAddresses)
										throw Error("no author addresses in "+unit);
```
