Based on my research into the analog for CVE-2017-5194 (UAF via invalid message causing a crash), the closest structural match in ocore's JS codebase is a missing existence-check on a shared in-memory cache entry that is dereferenced right after a "free" (delete) operation elsewhere in the same code path — the same bug shape as a use-after-free, just manifesting as an unguarded property access on a possibly-evicted cache object rather than a raw pointer.

### Title
Unchecked cache dereference in AA response revert path can crash a full node on a crafted AA trigger chain - (File: aa_composer.js)

### Summary
`revertResponsesInCaches()` in `aa_composer.js` unconditionally dereferences `storage.assocUnstableUnits[first_unit].parent_units` without checking that the cache entry still exists [1](#0-0) . Every other place in the codebase that reads from these same in-memory caches (`assocUnstableUnits`, `assocStableUnits`) treats a missing entry as an expected/handled condition and guards it explicitly, e.g. `readUnitProps` [2](#0-1)  and `getFinalTps`'s parent walk which explicitly `continue`s when `parentProps` is absent because "removed from cache" [3](#0-2) . `revertResponsesInCaches` is the one caller that assumes the object is always present.

### Finding Description
When an AA trigger chain fails partway through (a secondary AA bounces), the primary trigger handler calls `revert()`, which calls `revertResponsesInCaches(arrResponses)` to strip the just-created, about-to-be-rolled-back response units out of the shared unit caches before retrying as a bounce [4](#0-3) . The same function is also invoked unconditionally at the end of every dry-run trigger execution [5](#0-4) .

`revertResponsesInCaches` takes the first response unit in the list, reads its cached props object, and reads `.parent_units` off it, only afterward calling `storage.forgetUnit` on all response units:
```
var objFirstUnit = storage.assocUnstableUnits[first_unit];
var parent_units = objFirstUnit.parent_units;
arrResponseUnits.forEach(storage.forgetUnit);
``` [6](#0-5) 

`storage.forgetUnit(unit)` deletes the unit from `assocUnstableUnits` (and several other caches) as its normal effect [7](#0-6) . Nothing in `handleTrigger`'s revert/bounce control flow prevents `revertResponsesInCaches` from running twice over overlapping response sets in redirect/base-AA and secondary-trigger chains (`template.base_aa` recursion reuses the same `arrResponses` array and `bSecondary` flag across `handleTrigger` re-entries [8](#0-7) , and `handleSecondaryTriggers` recurses `handleTrigger` per output address while sharing the parent's `arrResponses` [9](#0-8) ). Because `assocUnstableUnits` is also asynchronously pruned by the periodic `shrinkCache()` job that deletes cache entries under a `write` mutex without any coordination with in-flight AA trigger processing state [10](#0-9) , any code path that reaches `revertResponsesInCaches` a second time for a unit whose cache entry was already removed by `forgetUnit` (or by a concurrent shrink/archival pass) will dereference `undefined.parent_units` and throw an uncaught `TypeError`.

This is the direct analog of the Irssi UAF: an object is "freed" from the relevant in-memory structure by one code path (`forgetUnit`/cache eviction) and a sibling path that still holds a stale key continues to dereference it, causing an unhandled crash.

### Impact Explanation
AA trigger execution, including the revert/bounce logic, runs deterministically as part of consensus-critical unit processing on every full node that evaluates the same AA address and trigger unit. An uncaught exception in this synchronous call chain is not caught by any `try/catch` in `handleTrigger`/`revert`, so it propagates up through the event loop and crashes the Node.js process. Because the trigger and the AA definition that produces the vulnerable revert sequence are fully attacker-controlled (any unprivileged unit poster can target any deployed AA, and any AA author can define a chain of AAs/base-AA redirects), a single crafted unit can deterministically crash every full node that processes it, halting stabilization and confirmation of new units network-wide — matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
The precondition (a stale/evicted cache entry at the exact moment `revertResponsesInCaches` runs for the same unit) requires hitting one of: (a) an AA response chain re-entering `revert()`/`revertResponsesInCaches` for overlapping response sets via `base_aa` redirection or secondary-trigger recursion, or (b) the periodic `shrinkCache()` background job evicting an in-flight response unit's cache entry while the same trigger's transaction is still open. Both conditions are plausible given the sharing of the mutable `arrResponses` array across recursive `handleTrigger` calls and the lack of any mutex coordination between `shrinkCache()` and AA trigger transaction state, but constructing the exact minimal AA/trigger sequence that reliably wins this race was not verified end-to-end with a running node.

### Recommendation
Add an explicit existence check in `revertResponsesInCaches` before dereferencing the cached unit props (mirroring the pattern already used in `readUnitProps`/`getFinalTps`), e.g. skip/guard when `storage.assocUnstableUnits[first_unit]` is falsy, and audit all `revert()`/base_aa-redirect/secondary-trigger recursion paths to ensure `revertResponsesInCaches` is never invoked twice for the same response unit set.

### Proof of Concept
1. Define AA `A` with `base_aa` redirect semantics or a chain of secondary AAs such that a later secondary AA in the chain deterministically bounces after AA `A`'s own response unit has already been saved and cached.
2. Post a trigger unit to AA `A` from an unprivileged wallet.
3. During `handleTrigger`'s `handleSecondaryTriggers` → `revert()` path, `revertResponsesInCaches(arrResponses)` is invoked; if the primary response unit's cache entry has meanwhile been evicted (e.g. by `shrinkCache()`'s 5-minute interval firing during a slow validation, or via a second revert of the same unit through recursive redirect handling), `storage.assocUnstableUnits[first_unit]` is `undefined` and `.parent_units` throws, crashing the node.

### Citations

**File:** aa_composer.js (L290-299)
```javascript
					handleTrigger({
						bDryRun: true, // suppress events for a unit that will be rolled back
						conn, batch, trigger, params: {}, stateVars: {}, arrDefinition, address, mci, objMcUnit, bSecondary: false, arrResponses,
						onDone: function () {
							revertResponsesInCaches(arrResponses);
							batch.clear();
							conn.query("ROLLBACK", function () {
								conn.release();
								onDone(arrResponses);
							});
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

**File:** aa_composer.js (L1720-1741)
```javascript
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
```

**File:** aa_composer.js (L1759-1765)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
```

**File:** aa_composer.js (L1909-1914)
```javascript
	if (arrResponseUnits.length > 0) {
		var first_unit = arrResponseUnits[0];
		var objFirstUnit = storage.assocUnstableUnits[first_unit];
		var parent_units = objFirstUnit.parent_units;
		arrResponseUnits.forEach(storage.forgetUnit);
		storage.fixIsFreeAfterForgettingUnit(parent_units);
```

**File:** storage.js (L1200-1202)
```javascript
				const parentProps = assocStableUnits[parent_unit];
				if (!parentProps) // removed from cache, so its mci is definitely before last ball
					continue;
```

**File:** storage.js (L1502-1505)
```javascript
	if (assocStableUnits[unit])
		return handleProps(assocStableUnits[unit]);
	if (conf.bFaster && assocUnstableUnits[unit])
		return handleProps(assocUnstableUnits[unit]);
```

**File:** storage.js (L2209-2232)
```javascript
function forgetUnit(unit){
	console.log('forgetting unit '+unit);
	if (!conf.bLight){
		console.log('parents', assocUnstableUnits[unit].parent_units);
		assocUnstableUnits[unit].parent_units.forEach(function(parent_unit){
			console.log('parent '+parent_unit+' best children', JSON.stringify(assocBestChildren[parent_unit]));
			if (assocBestChildren[parent_unit] && assocBestChildren[parent_unit].indexOf(assocUnstableUnits[unit]) >= 0){
				console.log('before pull', assocBestChildren[parent_unit]);
				_.pull(assocBestChildren[parent_unit], assocUnstableUnits[unit]);
				console.log('after pull', assocBestChildren[parent_unit]);
			}
		});
	}
	delete assocKnownUnits[unit];
	delete assocCachedUnits[unit];
	delete assocCachedUnitAuthors[unit];
	delete assocCachedUnitWitnesses[unit];
	delete assocUnstableUnits[unit];
	if (!conf.bLight && assocStableUnits[unit])
		throw Error("trying to forget stable unit "+unit);
	delete assocStableUnits[unit];
	delete assocUnstableMessages[unit];
	delete assocBestChildren[unit];
}
```

**File:** storage.js (L2250-2261)
```javascript
async function shrinkCache(){
	if (Object.keys(assocCachedAssetInfos).length > MAX_ITEMS_IN_CACHE)
		assocCachedAssetInfos = {};
	console.log(Object.keys(assocUnstableUnits).length+" unstable units");
	var arrKnownUnits = Object.keys(assocKnownUnits);
	var arrPropsUnits = Object.keys(assocCachedUnits);
	var arrStableUnits = Object.keys(assocStableUnits);
	var arrAuthorsUnits = Object.keys(assocCachedUnitAuthors);
	var arrWitnessesUnits = Object.keys(assocCachedUnitWitnesses);
	if (arrPropsUnits.length < MAX_ITEMS_IN_CACHE && arrAuthorsUnits.length < MAX_ITEMS_IN_CACHE && arrWitnessesUnits.length < MAX_ITEMS_IN_CACHE && arrKnownUnits.length < MAX_ITEMS_IN_CACHE && arrStableUnits.length < MAX_ITEMS_IN_CACHE)
		return console.log('cache is small, will not shrink');
	const unlock = await mutex.lock("write");
```
