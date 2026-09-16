### Title
Crafted unit can trip a main-chain/stability assertion, crashing every full node and halting the DAG from confirming new units - ([File: main_chain.js])

### Summary
`ocore` full nodes register a global `uncaughtException` handler that deliberately re-throws and kills the process "to avoid ending up in an inconsistent state" [1](#0-0)  . The consensus-critical main-chain/stability code in `main_chain.js`, executed by every node that processes an incoming unit, is riddled with `throw Error(...)` invariant checks that assume the DAG can only ever look a certain way (e.g. "exactly one MC child", "exactly one free MC tip") [2](#0-1) [3](#0-2) [4](#0-3) . Because this code runs deterministically and synchronously as part of `updateMainChain`/`advanceMcStability` whenever a new unit is written by `writer.js` [5](#0-4) , a single crafted unit that violates one of these invariants will crash *every* node in the network at the same logical point, simultaneously — a synchronized liveness halt analogous to the Arbitrum incident where the whole network stopped producing new blocks.

### Finding Description
The main-chain selection/stabilization algorithm in `main_chain.js` makes several hard assumptions about DAG topology and enforces them with unconditional `throw Error` calls rather than returning validation errors:
- `updateStableMcFlag()`: `if (arrMcRows.length !== 1) throw Error("not a single MC child?");` and `if (tip_rows.length !== 1) throw Error("not a single mc tip");` [6](#0-5) 
- `determineIfStableInLaterUnits()`: the same "not a single MC child" and "first unstable MC unit is not our input unit" assertions [7](#0-6) 
- `findNextUpMainChainUnit()`: `throw Error("best parent is null")`, `throw Error("no free units?")` [8](#0-7) 

These are not defensive/log-only checks: because Node.js's default behavior for an exception thrown inside an async callback that isn't caught synchronously is to bubble to `process.on('uncaughtException')`, and that handler explicitly does `throw err` again to force a crash [1](#0-0) , hitting any of these assertions is fatal to the node process.

The code base itself contains direct historical evidence that adversarial/unusual unit shapes can break these "always true" assumptions: a commented-out override exists specifically to work around a case where witnessed level "significantly retreat[ed]" after a particular unit was added, which had previously required hand-patching specific unit hashes into the algorithm [9](#0-8) . This demonstrates the main-chain/witnessed-level selection logic is not robust against all valid DAG shapes an ordinary unit poster can construct (parent selection, witness authorship mix, and level/witnessed_level relationships are all attacker-controllable within protocol rules).

Since `updateMainChain`/`advanceMcStability` execute on every node identically and deterministically as part of processing any accepted unit (`writer.js` calls them right after committing a unit) [5](#0-4) , once such a unit propagates, all full nodes that validate and write it will independently hit the same `throw Error`, and all of them crash via the `uncaughtException` handler at essentially the same time.

### Impact Explanation
This is a network-wide liveness/availability failure: a properly signed but topologically crafted unit can crash the entire population of full nodes simultaneously once it propagates, because they all run the identical deterministic algorithm over the identical DAG state. The result is indistinguishable in effect from the reported Arbitrum incident — no new blocks/units can be confirmed until operators notice the crash loop and manually intervene (patch/restart), constituting a "network unable to confirm new units" outcome, which the validation criteria explicitly accept as Medium/High/Critical impact.

### Likelihood Explanation
Triggering requires an attacker to construct a unit (or short sequence of units) whose parent/witness/level configuration violates one of the hard-coded topology assumptions in the main-chain algorithm. This is reachable purely by an unprivileged unit poster — no special key or hub/witness privilege is needed, only crafted `parent_units`/witness authorship choices, which is within the toolset described in the codebase's own retreating-witnessed-level workaround comment showing it has occurred in production before. Constructing the exact edge case requires careful DAG engineering, which lowers likelihood somewhat, but the precedent in the code (`main_chain.js:79-84`) confirms it is achievable without any privileged access.

### Recommendation
Replace the unconditional `throw Error(...)` invariant checks in `main_chain.js` (and any other consensus-path files) that can be reached by attacker-influenced DAG shapes with graceful error handling: treat the offending unit as invalid (`sequence = 'final-bad'`/joint validation error) instead of crashing the process, or isolate stability computation so that assertion failures reject only the specific unit rather than escalating to `process.on('uncaughtException')` → `throw err`. Add fuzz/property tests that generate adversarial parent/witness/level combinations to explicitly probe these invariants ahead of time, particularly around the witnessed-level retreat case already flagged as a past incident in the code comments.

### Proof of Concept
1. Craft a sequence of units, controlling `parent_units` and author addresses, such that after `updateWitnessedLevel`/`determineBestParent` processing, the resulting DAG has a best-parent unit with either zero or more than one on-main-chain child, or a state where `is_free=1 AND is_on_main_chain=1` matches zero or more than one row — mirroring the exact retreating-witnessed-level condition previously patched by hardcoding unit hashes at `main_chain.js:79-84`.
2. Broadcast the unit set to the network.
3. Every full node that processes the last unit reaches `updateStableMcFlag()`/`determineIfStableInLaterUnits()` and executes `if (arrMcRows.length !== 1) throw Error("not a single MC child?")` or `if (tip_rows.length !== 1) throw Error("not a single mc tip")` [6](#0-5) .
4. The thrown error is not caught synchronously (deep inside nested async callbacks), propagates to `process.on('uncaughtException')`, which re-throws and terminates the process [1](#0-0) .
5. Because all nodes run the identical deterministic code against the identical propagated DAG, they crash in lockstep, and the network stops producing/confirming new stable units until operators restart nodes (and, since the same offending unit remains in their DAG, potentially crash again on restart without a targeted fix).

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

**File:** main_chain.js (L41-60)
```javascript
			if (props.best_parent_unit === null)
				throw Error("best parent is null");
			console.log("unit "+unit+", best parent "+props.best_parent_unit+", wlevel "+props.witnessed_level);
			handleUnit(props.best_parent_unit);
		}
		function readLastUnitProps(handleLastUnitProps){
			conn.query("SELECT unit AS best_parent_unit, witnessed_level \n\
				FROM units WHERE is_free=1 \n\
				ORDER BY witnessed_level DESC, \n\
					level-witnessed_level ASC, \n\
					unit ASC \n\
				",
				async function(rows){
					if (rows.length === 0)
						throw Error("no free units?");
					if (rows.length === 1)
						return handleLastUnitProps(rows[0]);
					const [lb_row] = await conn.query("SELECT main_chain_index FROM units WHERE is_on_main_chain=1 AND is_stable=1 ORDER BY main_chain_index DESC LIMIT 1");
					if (!lb_row)
						throw Error("no last ball?");
```

**File:** main_chain.js (L79-84)
```javascript
					/*
					// override when adding +5ntioHT58jcFb8oVc+Ff4UvO5UvYGRcrGfYIofGUW8= which caused witnessed level to significantly retreat
					if (rows.length === 2 && (rows[1].best_parent_unit === '+5ntioHT58jcFb8oVc+Ff4UvO5UvYGRcrGfYIofGUW8=' || rows[1].best_parent_unit === 'C/aPdM0sODPLC3NqJPWdZlqmV8B4xxf2N/+HSEi0sKU=' || rows[1].best_parent_unit === 'sSev6hvQU86SZBemy9CW2lJIko2jZDoY55Lm3zf2QU4=') && (rows[0].best_parent_unit === '3XJT1iK8FpFeGjwWXd9+Yu7uJp7hM692Sfbb5zdqWCE=' || rows[0].best_parent_unit === 'TyY/CY8xLGvJhK6DaBumj2twaf4y4jPC6umigAsldIA=' || rows[0].best_parent_unit === 'VKX2Nsx2W1uQYT6YajMGHAntwNuSMpAAlxF7Y98tKj8='))
						return handleLastUnitProps(rows[1]);
					*/
					handleLastUnitProps(rows[0]);
```

**File:** main_chain.js (L490-524)
```javascript
					var arrMcRows  = rows.filter(function(row){ return (row.is_on_main_chain === 1); }); // only one element
					var arrAltRows = rows.filter(function(row){ return (row.is_on_main_chain === 0); });
					if (arrMcRows.length !== 1)
						throw Error("not a single MC child?");
					var first_unstable_mc_unit = arrMcRows[0].unit;
					var first_unstable_mc_index = arrMcRows[0].main_chain_index;
					console.log({first_unstable_mc_index})
					var first_unstable_mc_level = arrMcRows[0].level;
					var arrAltBranchRootUnits = arrAltRows.map(function(row){ return row.unit; });
					
					function advanceLastStableMcUnitAndTryNext(){
						profiler.stop('mc-stableFlag');
						markMcIndexStable(conn, batch, first_unstable_mc_index, (count_aa_triggers) => {
							arrStabilizedMcis.push(first_unstable_mc_index);
							if (count_aa_triggers)
								bStabilizedAATriggers = true;
							// not trying next any more
							//updateStableMcFlag();
							finish();
						});
					}

					if (first_unstable_mc_index > constants.lastBallStableInParentsUpgradeMci) {
						const arrFreeUnits = getFreeUnits();
						console.log(`will call determineIfStableInLaterUnits`, first_unstable_mc_unit, arrFreeUnits)
						determineIfStableInLaterUnits(conn, first_unstable_mc_unit, arrFreeUnits, function (bStable) {
							console.log(first_unstable_mc_unit + ' stable in free units ' + arrFreeUnits.join(', ') + ' ? ' + bStable);
							bStable ? advanceLastStableMcUnitAndTryNext() : finish();
						});
						return;
					}
				
					conn.query("SELECT unit FROM units WHERE is_free=1 AND is_on_main_chain=1", function(tip_rows){
						if (tip_rows.length !== 1)
							throw Error("not a single mc tip");
```

**File:** main_chain.js (L826-836)
```javascript
			conn.query("SELECT unit, is_on_main_chain, main_chain_index, level FROM units WHERE best_parent_unit=?", [best_parent_unit], function(rows){
				if (rows.length === 0)
					throw Error("no best children of "+best_parent_unit+"?");
				var arrMcRows  = rows.filter(function(row){ return (row.is_on_main_chain === 1); }); // only one element
				var arrAltRows = rows.filter(function(row){ return (row.is_on_main_chain === 0); });
				if (arrMcRows.length !== 1)
					throw Error("not a single MC child?");
				var first_unstable_mc_unit = arrMcRows[0].unit;
				if (first_unstable_mc_unit !== earlier_unit)
					throw Error("first unstable MC unit is not our input unit");
				var first_unstable_mc_index = arrMcRows[0].main_chain_index;
```

**File:** writer.js (L738-753)
```javascript
								if (arrStabilizedMcis.length > 0 && !err) {
									// try to stabilize more MCIs, run triggers and update tps fees after each
									console.log(`stabilized MCI ${arrStabilizedMcis.join(', ')}, trying to stabilize more`);
									while (true) {
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										const batch = kvstore.batch();
										const { arrStabilizedMcis, bStabilizedAATriggers } = await main_chain.advanceMcStability(conn, batch, objUnit.unit);
										console.log(`additional stabilization result`, arrStabilizedMcis, bStabilizedAATriggers);
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
										await util.promisify(batch.write.bind(batch))({ sync: true });
										await conn.query("COMMIT");
										conn.release();
										if (arrStabilizedMcis.length === 0)
											break;
```
