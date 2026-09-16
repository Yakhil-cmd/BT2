### Title
Race condition in `readUnitProps` cache/DB consistency check crashes the node - (File: storage.js)

### Summary
`storage.readUnitProps()` performs a "check-then-fetch" pattern: it first checks the in-memory unstable/stable-unit caches, and if the unit isn't cached it issues an async DB query to fetch its properties. Because unit-stability transitions (moving a unit from `assocUnstableUnits` to `assocStableUnits`) can happen concurrently while the async DB query is in flight, the function can observe a state where the freshly-queried DB row no longer matches the in-memory cache snapshot it expects, and it unconditionally `throw`s, crashing the node process — the same bug class as CVE-2018-19489 (a race between a state-changing operation and a stale-state consumer that leads to a crash).

### Finding Description [1](#0-0) 

`readUnitProps(conn, unit, handleProps)` is implemented as:
1. If `assocStableUnits[unit]` or (in faster mode) `assocUnstableUnits[unit]` is already cached, return immediately.
2. Otherwise, issue `conn.query(...)` to read the unit row from the DB (an async operation).
3. When the query callback fires, re-check `assocStableUnits[unit]`/`assocUnstableUnits[unit]` **again**, and compare it deep-equal to the just-fetched DB row.
4. If the two views disagree, the code calls `throw Error(...)` (lines 1533 and 1549), which is an uncaught exception inside an async DB callback and brings the whole node process down.

The code comment itself acknowledges the race:
```
// the unit could become stable after the check above and be added to assocStableUnits
```
but the mitigation is incomplete: it only tolerates the transition to `assocStableUnits` when the two snapshots are exactly `_.isEqual`. Any legitimate concurrent mutation of `assocUnstableUnits[unit]` (e.g., changes to `main_chain_index`, `is_on_main_chain`, `witnessed_level`, `count_aa_responses`, or removal via `storage.forgetUnit()`/`revertResponsesInCaches()` in `aa_composer.js`) that occurs between step 1 and step 3 causes the deep-equal check to fail, or the `!assocUnstableUnits[unit]` guard at line 1541-1542 to trip (`throw Error("no unstable props of "+unit)`), producing an unconditional crash.

This is directly analogous to the QEMU 9p race: in QEMU, a `wstat`/rename can mutate file/fid state concurrently with another in-flight operation referencing the old name/state, and the mismatch crashes the process. Here, unit "renaming" of state (unstable → stable, or cache eviction/forgetting) races with an in-flight `readUnitProps` DB round trip that still expects the old cached view, and the mismatch crashes the node the same way.

`readUnitProps` is invoked pervasively from validation and AA-trigger execution paths (`validation.js`, `main_chain.js`, `aa_composer.js`) while processing units submitted by ordinary peers/wallets, so an attacker only needs to cause enough concurrent unit/AA-trigger processing (which any unprivileged unit poster or AA trigger sender can influence by posting units/triggers) to widen the race window and reliably hit the mismatch.

### Impact Explanation
Hitting the race causes an unhandled `throw Error` inside an asynchronous DB callback. In Node.js this is an uncaught exception that is not caught by any `try/catch` up the async call stack, causing the process to terminate (crash). Since this code path runs on every full node processing units (including witnesses/hubs), a reliably triggerable crash amounts to a network-wide denial of service: nodes hit by the race stop validating/stabilizing units, and the network becomes unable to confirm new units until the affected nodes are restarted — matching the "network unable to confirm new units" impact criterion.

### Likelihood Explanation
The race window is opened by ordinary, permissionless operations: any unit poster can submit units, and AA responses/trigger processing (`aa_composer.js`, `handlePrimaryAATrigger`, `revertResponsesInCaches`) mutate `assocUnstableUnits`/`assocStableUnits` while other validations are concurrently calling `readUnitProps` for the same units via async DB queries. Under any realistic level of concurrent traffic (multiple units/AA triggers processed close together, which is normal network operation and can be amplified by an attacker flooding units/triggers), the window between the initial cache check and the DB callback firing can be crossed by a stability transition or cache eviction, making the crash a matter of timing/load rather than a rare edge case.

### Recommendation
- Remove the `throw Error` assertions in `readUnitProps` for the case where the cache was populated/changed concurrently with the in-flight query; instead, re-return the authoritative current cache value (`assocStableUnits[unit]` or `assocUnstableUnits[unit]`) without requiring exact equality, since the cache is the source of truth once populated.
- Alternatively, serialize access with a mutex/lock around the check-then-fetch sequence for a given unit (similar to the per-author-address locking already used in `validation.js`) so that no concurrent cache mutation can occur while the DB round trip for that unit is outstanding.
- Wrap the DB-callback logic in a way that failures translate into a normal error callback rather than an uncaught `throw`, so a mismatch degrades gracefully instead of crashing the process.

### Proof of Concept
1. Have a full node process two units concurrently such that:
   - Unit `A` is not yet cached (`assocUnstableUnits[A]` absent, `assocStableUnits[A]` absent), causing `readUnitProps(conn, A, cb)` to skip the cache and issue the DB query at storage.js:1507.
   - While that DB query is in flight, drive a concurrent operation that mutates the unstable-unit cache for `A` — e.g., trigger `main_chain.advanceMcStability` to make `A` stable (moving it into `assocStableUnits`) or trigger `aa_composer.revertResponsesInCaches`/`storage.forgetUnit(A)` to remove it from `assocUnstableUnits`.
2. When the original DB query's callback fires, the re-check at storage.js:1526-1550 finds a cache state that either doesn't `_.isEqual` the DB snapshot or is missing entirely, triggering `throw Error("different props of ...")` or `throw Error("no unstable props of ...")`.
3. The uncaught exception inside the async callback terminates the node process, demonstrating the DoS.

### Citations

**File:** storage.js (L1497-1554)
```javascript
function readUnitProps(conn, unit, handleProps){
	if (!unit)
		throw Error(`readUnitProps bad unit ` + unit);
	if (!handleProps)
		return new Promise(resolve => readUnitProps(conn, unit, resolve));
	if (assocStableUnits[unit])
		return handleProps(assocStableUnits[unit]);
	if (conf.bFaster && assocUnstableUnits[unit])
		return handleProps(assocUnstableUnits[unit]);
	var stack = new Error().stack;
	conn.query(
		"SELECT unit, level, latest_included_mc_index, main_chain_index, is_on_main_chain, is_free, is_stable, witnessed_level, headers_commission, payload_commission, sequence, timestamp, GROUP_CONCAT(address) AS author_addresses, COALESCE(witness_list_unit, unit) AS witness_list_unit, best_parent_unit, last_ball_unit, tps_fee, max_aa_responses, count_aa_responses, count_primary_aa_triggers, is_aa_response, version\n\
			FROM units \n\
			JOIN unit_authors USING(unit) \n\
			WHERE unit=? \n\
			GROUP BY +unit", 
		[unit], 
		function(rows){
			if (rows.length !== 1)
				throw Error("not 1 row, unit "+unit);
			var props = rows[0];
			props.author_addresses = props.author_addresses.split(',');
			props.count_primary_aa_triggers = props.count_primary_aa_triggers || 0;
			props.bAA = !!props.is_aa_response;
			delete props.is_aa_response;
			props.tps_fee = props.tps_fee || 0;
			if (parseFloat(props.version) >= constants.fVersion4)
				delete props.witness_list_unit;
			delete props.version;
			if (props.is_stable) {
				console.log('caching stable unit', unit, 'already cached =', !!assocStableUnits[unit]);
				// the unit could become stable after the check above and be added to assocStableUnits
				if (assocStableUnits[unit]) {
					let props2 = _.cloneDeep(assocStableUnits[unit]);
					delete props2.parent_units;
					if (!_.isEqual(props2, props))
						throw Error(`different props: assocStableUnits[unit]=${JSON.stringify(props2)}, props=${JSON.stringify(props)}`);
					return handleProps(assocStableUnits[unit]);
				}
				if (props.sequence === 'good') // we don't cache final-bads as they can be voided later
					assocStableUnits[unit] = props;
				// we don't add it to assocStableUnitsByMci as all we need there is already there
			}
			else{
				if (!assocUnstableUnits[unit])
					throw Error("no unstable props of "+unit);
				var props2 = _.cloneDeep(assocUnstableUnits[unit]);
				delete props2.parent_units;
				delete props2.assocEarnedHeadersCommissionRecipients;
			//	delete props2.bAA;
				if (!_.isEqual(props, props2)) {
					debugger;
					throw Error("different props of "+unit+", mem: "+JSON.stringify(props2)+", db: "+JSON.stringify(props)+", stack "+stack);
				}
			}
			handleProps(props);
		}
	);
```
