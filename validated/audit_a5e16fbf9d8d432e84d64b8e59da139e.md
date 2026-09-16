### Title
Unhandled NULL pointer dereference in AA trigger processing crashes full node - (File: aa_composer.js)

### Summary
In `handleTrigger()`, when a primary AA trigger unit is processed, the code accesses `storage.assocStableUnits[trigger.unit].count_aa_responses` without checking whether the cache entry exists, unlike the sibling code path in `handlePrimaryAATrigger()` that explicitly validates the same lookup and throws a controlled error if missing.

### Finding Description
`handlePrimaryAATrigger()` reads a stable unit's cache entry and defensively checks it: [1](#0-0) 

But `handleTrigger()`, which runs for every primary trigger (real execution, not just estimation), performs the same style of lookup with no null check at all: [2](#0-1) 

```js
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```

If `storage.assocStableUnits[trigger.unit]` is `undefined` at this point (e.g., because the unit's cache entry was already pruned/evicted from `assocStableUnits`, or because `handleTrigger` is invoked through a code path where the trigger unit hasn't been added to the cache before this check runs), accessing `.count_aa_responses` on `undefined` throws an uncaught `TypeError`. This is directly analogous to the KubeVirt NULL pointer dereference (CWE-476): an attacker-triggerable condition (posting a payment to an AA address, i.e., an ordinary unit an unprivileged unit poster can create) reaches code that dereferences a property on a value that is not guaranteed to be non-null, causing a crash.

Unlike normal validation errors that are gracefully handled via `callbacks.ifUnitError`, this exception occurs deep inside AA trigger execution (`handlePrimaryAATrigger` → `handleTrigger`), which is wrapped only by database transaction logic and mutex locks, not a try/catch that converts it into a soft failure. An uncaught exception here propagates up through the `mutex.lock(['aa_triggers'], ...)` callback chain in `handleAATriggers()`, which has no error handling, crashing the Node.js process (unhandled exception terminates the process by default).

### Impact Explanation
A crash of the full node process while processing accepted, stable AA triggers constitutes a denial of service: the node stops confirming new units and processing further AA triggers until manually restarted, i.e., "a network unable to confirm new units" if enough witness/full nodes are affected simultaneously by the same crafted trigger unit. Because AA triggers are processed for every stable unit paying to an AA address, this is reachable by any unprivileged unit poster who can pay an existing AA and craft input so this cache-miss condition occurs.

### Likelihood Explanation
Exploitability depends on being able to reliably force `storage.assocStableUnits[trigger.unit]` to be absent at the moment `handleTrigger` runs for that same `trigger.unit` as a primary trigger — this requires understanding of the exact caching/pruning lifecycle of `assocStableUnits` (populated/evicted in `storage.js`, `main_chain.js`, `writer.js`), which I could not fully confirm from the available index (population/eviction call sites exist in `storage.js`/`main_chain.js`/`writer.js` but the precise timing guarantee relative to `handleAATriggers()` was not verifiable with the tools available). The existence of the defensive `throw Error(...)` check for the identical lookup elsewhere in the same file (line 104-106) indicates the developers were aware this lookup can, under some circumstance, be missing — supporting that the unguarded access at line 1861 is a genuine gap rather than a provably-unreachable line.

### Recommendation
Add a null-check before accessing `.count_aa_responses`, mirroring the existing defensive pattern used in `handlePrimaryAATrigger`:
```js
const objUnitProps = storage.assocStableUnits[trigger.unit];
if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && objUnitProps && objUnitProps.count_aa_responses && mci >= constants.pemCurvesFixMci)
    return bounce('a second primary trigger from the same unit is not allowed');
```
If the entry is genuinely expected to always exist by design, that invariant should be enforced with a controlled check (throwing a descriptive `Error`, as done at line 106) rather than an implicit crash from accessing a property of `undefined`, and unit tests should assert `handleTrigger` cannot crash the process regardless of `assocStableUnits` cache state.

### Proof of Concept
Could not construct a concrete, index-verifiable sequence of unit postings that forces `storage.assocStableUnits[trigger.unit]` to be evicted/absent exactly when `handleTrigger` re-checks it for the same `trigger.unit`, because the full eviction/population lifecycle of `assocStableUnits` across `storage.js`, `main_chain.js`, and `writer.js` was not fully traceable with the available search tools in the remaining iterations. This should be verified with a full-repository session (e.g., a Devin run with file access) to trace `assocStableUnits` population order versus `handleAATriggers`/`handlePrimaryAATrigger` execution order, and to write a reproducing test analogous to the existing tests in `test/aa_composer.test.js` that manipulate `storage.assocStableUnits` directly.

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

**File:** aa_composer.js (L1861-1862)
```javascript
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
```
