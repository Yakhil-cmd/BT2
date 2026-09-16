### Title
Signature verification deferred after expensive DAG/stability-chain validation allows cheap invalid units to trigger disk/CPU-costly processing - (File: validation.js)

### Summary
CVE-2018-19155 (Navcoin "Fake Stake") describes a class of bug where a chain-based PoS node accepts and processes cheaply-forged invalid headers/blocks that pass structural checks but fail final authentication (stake proof), and the expensive validation work done *before* that authentication check can be used to exhaust disk and RAM. In ocore's DAG-based unit model, the analogous authentication step is per-author signature/authentifier verification, which is performed in `validateAuthors` — but only *after* the unit has already gone through several DB-heavy, potentially graph-walking checks in `validate()`.

### Finding Description
`validate()` in `validation.js` runs its checks in a fixed pipeline via `async.series`: [1](#0-0) . Notably `validateParents` — which can invoke `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag`, itself walking best-children/witness chains across the DAG and potentially advancing the main-chain stability point — runs at line 416, and `validateWitnesses`/`validateAATrigger`/`validateTpsFee` follow, all *before* `validateAuthors` (line 437) where authentifiers/signatures are actually checked [2](#0-1) .

Crucially, an attacker only needs to satisfy `hasValidHashes` (a trivial self-consistent hash of arbitrary content) to pass the cheap early checks in `validate()` [3](#0-2) ; correct `parent_units`/`last_ball_unit` references (pointing at real, already-known units) are easy to obtain by any node without any stake or fee cost, and the authors/authentifiers can be garbage — that failure is only detected later in `validateAuthors`. Between those two points, the DAG-walk in `main_chain.determineIfStableInLaterUnitsAndUpdateStableMcFlag`/`determineIfStableInLaterUnits` (main_chain.js) can perform multi-round DB queries, `readBestParentAndItsWitnesses`, `createListOfBestChildrenIncludedByLaterUnits`, and recursive graph traversal [4](#0-3) [5](#0-4) .

Additionally, `validate()`'s error handler explicitly acknowledges that stability-point advancement performed during this pre-authentication phase must be **committed even when the unit is subsequently rejected**: "We might have advanced the stability point and have to commit the changes as the caches are already updated" [6](#0-5) . This means a unit that ultimately fails signature verification can still leave permanent database/cache side effects from the expensive stability computation it triggered.

### Impact Explanation
An unprivileged peer can craft a stream of syntactically valid but unsigned/garbage-signed units, each referencing legitimate current parent tips and a legitimate stable `last_ball_unit`, at essentially zero cost (no funds, no valid keys required). Every such unit forces every receiving full node to execute the DB-bound `validateParents`/main-chain stability walk before the cheap signature check in `validateAuthors` can reject it. Because many of these operations involve DB transactions (`BEGIN`/rollback), connection-pool usage, and recursive graph queries, sustained submission can consume CPU, DB I/O, and memory (`storage.assocUnstableUnits`/`assocCachedUnits` caches), degrading node throughput and potentially delaying stabilization of legitimate units network-wide — the kind of "network unable to confirm new units" condition called out in the report's validation criteria.

### Likelihood Explanation
Moderate-to-high: constructing a well-formed unit with valid parent references and a valid hash does not require any signature, coin ownership, or fee payment — only knowledge of currently free/tip units and structural field rules, all of which are public. The attack requires no privileged network position (any poster can submit units, e.g., via `network.js` `handleJoint` or direct submission paths that call `validation.validate`) [7](#0-6) .

### Recommendation
Reorder the `validate()` pipeline in `validation.js` so `validateAuthors` (signature/authentifier verification) is performed as early as possible — ideally immediately after minimal structural/hash checks and before any DAG traversal or stability computation in `validateParents`. At minimum, perform a cheap syntactic/format check of authentifiers before running `validateParents`, and avoid committing any stability-point side effects (`objValidationState.bAdvancedLastStableMci`) for units that ultimately fail author/signature validation, or gate the expensive stability walk behind a lightweight proof-of-authenticity check.

### Proof of Concept
1. An attacker observes the current free/tip units and the last stable ball unit via public unit data (no special access needed).
2. The attacker constructs a unit object with: a single bogus author address, a garbage/short-circuited authentifier, valid `parent_units` pointing at real free units, and a valid `last_ball`/`last_ball_unit` pointing at a real stable unit, then computes `objectHash.getUnitHash` over this content so `hasValidHashes` passes.
3. The attacker submits many such units (varying content, e.g., different `unit` hashes) rapidly to a victim node.
4. Each submission traverses `checkDuplicate` → `validateHashTreeBall` → `validateParentsExistAndOrdered` → `validateHashTreeParentsAndSkiplist` → `validateParents` (including possible `determineIfStableInLaterUnitsAndUpdateStableMcFlag` graph walk) → `validateWitnesses`/`validateAATrigger`/`validateTpsFee` before finally failing at `validateAuthors`, consuming DB/CPU resources on every attempt [8](#0-7) .

Note: I was unable to directly inspect the full body of `checkDuplicate`, `validateAuthors`, and `validateWitnesses` (only line numbers were found via search, not full content) due to indexing limits, so exact per-step DB cost could not be fully quantified from the index alone; a full review of these functions (and confirmation of whether `checkDuplicate` does any early cheap rejection) would strengthen this analysis. If the user wants full file contents for `validation.js`'s `checkDuplicate`/`validateAuthors`/`validateWitnesses` bodies, a Devin session with full repo access can retrieve them for deeper confirmation.

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

**File:** validation.js (L363-444)
```javascript
		async.series(
			[
				function(cb){
					if (external_conn) {
						conn = external_conn;
						start_time = Date.now();
						commit_fn = function (cb2) { cb2(); };
						return cb();
					}
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
					});
				},
				function(cb){
					profiler.start();
					checkDuplicate(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-checkDuplicate');
					profiler.start();
					objUnit.content_hash ? cb() : validateHeadersCommissionRecipients(objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-hc-recipients');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeBall(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-ball');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateParentsExistAndOrdered(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-parents-exist');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeParentsAndSkiplist(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-parents');
				//	profiler.start(); // conflicting with profiling in determineIfStableInLaterUnitsAndUpdateStableMcFlag
					!objUnit.parent_units
						? cb()
						: validateParents(conn, objJoint, objValidationState, cb);
				},
				function(cb){
				//	profiler.stop('validation-parents');
					profiler.start();
					!objJoint.skiplist_units
						? cb()
						: validateSkiplist(conn, objJoint.skiplist_units, cb);
				},
				function(cb){
					profiler.stop('validation-skiplist');
					validateWitnesses(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
				function(cb){
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
				}
			], 
```

**File:** validation.js (L445-472)
```javascript
			function(err){
				if(err){
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('failed validation', consumed_time);
						console.log(objUnit.unit+" validation "+JSON.stringify(err)+" took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						unlock();
						if (typeof err === "object"){
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.bRequestPrunedContent);
							else if (err.error_code === "need_hash_tree") // need to download hash tree to catch up
								callbacks.ifNeedHashTree();
							else if (err.error_code === "invalid_joint") // ball found in hash tree but with another unit
								callbacks.ifJointError(err.message);
							else if (err.error_code === "transient")
								callbacks.ifTransientError(err.message);
							else
								throw Error("unknown error code");
						}
						else
							callbacks.ifUnitError(err);
					});
```

**File:** main_chain.js (L797-828)
```javascript
function determineIfStableInLaterUnits(conn, earlier_unit, arrLaterUnits, handleResult){
	if (!handleResult)
		return new Promise(resolve => determineIfStableInLaterUnits(conn, earlier_unit, arrLaterUnits, resolve));
	if (storage.isGenesisUnit(earlier_unit))
		return handleResult(true);
	// hack to workaround past validation error
	if (earlier_unit === 'LGFzduLJNQNzEqJqUXdkXr58wDYx77V8WurDF3+GIws=' && arrLaterUnits.join(',') === '6O4t3j8kW0/Lo7n2nuS8ITDv2UbOhlL9fF1M6j/PrJ4='
		|| earlier_unit === 'VLdMzBDVpwqu+3OcZrBrmkT0aUb/mZ0O1IveDmGqIP0=' && arrLaterUnits.join(',') === 'pAfErVAA5CSPeh1KoLidDTgdt5Blu7k2rINtxVTMq4k='
		|| earlier_unit === 'P2gqiei+7dur/gS1KOFHg0tiEq2+7l321AJxM3o0f5Q=' && arrLaterUnits.join(',') === '9G8kctAVAiiLf4/cyU2f4gdtD+XvKd1qRp0+k3qzR8o='
		|| constants.bTestnet && earlier_unit === 'zAytsscSjo+N9dQ/VLio4ZDgZS91wfUk0IOnzzrXcYU=' && arrLaterUnits.join(',') === 'ZSQgpR326LEU4jW+1hQ5ZwnHAVnGLV16Kyf/foVeFOc='
		|| constants.bTestnet && ['XbS1+l33sIlcBQ//2/ZyPsRV7uhnwOPvvuQ5IzB+vC0=', 'TMTkvkXOL8CxnuDzw36xDWI6bO5PrhicGLBR3mwrAxE=', '7s8y/32r+3ew1jmunq1ZVyH+MQX9HUADZDHu3otia9U='].indexOf(earlier_unit) >= 0 && arrLaterUnits.indexOf('39SDVpHJuzdDChPRerH0bFQOE5sudJCndQTaD4H8bms=') >= 0
		|| constants.bTestnet && earlier_unit === 'N6Va5P0GgJorezFzwHiZ5HuF6p6HhZ29rx+eebAu0J0=' && arrLaterUnits.indexOf('mKwL1PTcWY783sHiCuDRcb6nojQAkwbeSL/z2a7uE6g=') >= 0
	)
		return handleResult(true);
	var start_time = Date.now();
	storage.readPropsOfUnits(conn, earlier_unit, arrLaterUnits, function(objEarlierUnitProps, arrLaterUnitProps){
		if (constants.bTestnet && objEarlierUnitProps.main_chain_index <= 1220148 && objEarlierUnitProps.is_on_main_chain && arrLaterUnits.indexOf('qwKGj0w8P/jscAyQxSOSx2sUZCRFq22hsE6bSiqgUyk=') >= 0)
			return handleResult(true);
		if (objEarlierUnitProps.is_free === 1 || objEarlierUnitProps.main_chain_index === null)
			return handleResult(false);
		var max_later_limci = Math.max.apply(
			null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.latest_included_mc_index; }));
		if (max_later_limci < objEarlierUnitProps.main_chain_index) // the earlier unit is actually later
			return handleResult(false);
		var max_later_level = Math.max.apply(
			null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.level; }));
		var max_later_witnessed_level = Math.max.apply(
			null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.witnessed_level; }));
		readBestParentAndItsWitnesses(conn, earlier_unit, function(best_parent_unit, arrWitnesses){
			conn.query("SELECT unit, is_on_main_chain, main_chain_index, level FROM units WHERE best_parent_unit=?", [best_parent_unit], function(rows){
				if (rows.length === 0)
					throw Error("no best children of "+best_parent_unit+"?");
```

**File:** main_chain.js (L1142-1188)
```javascript
					determineIfHasAltBranches(function(bHasAltBranches){
						if (!bHasAltBranches){
							console.log("determineIfStableInLaterUnits no alt took "+(Date.now()-start_time)+"ms");
							if (min_mc_wl >= first_unstable_mc_level) 
								return handleResult(true);
							return handleResult(false);
							/*
							// Wrong. See the comment above
							// if there are 12 witnesses on the MC, the next unit is stable
							conn.query(
								"SELECT COUNT(DISTINCT address) AS count_witnesses FROM units JOIN unit_authors USING(unit) \n\
								WHERE is_on_main_chain=1 AND main_chain_index>=? AND address IN(?)",
								[first_unstable_mc_index, arrWitnesses],
								function(count_witnesses_rows){
									console.log(count_witnesses_rows[0]);
									handleResult(count_witnesses_rows[0].count_witnesses === constants.COUNT_WITNESSES);
								}
							);
							return;
							*/
						}
						// has alt branches
						if (first_unstable_mc_index >= constants.altBranchByBestParentUpgradeMci && min_mc_wl < first_unstable_mc_level){
							console.log("determineIfStableInLaterUnits min_mc_wl < first_unstable_mc_level with branches: not stable took "+(Date.now()-start_time)+"ms");
							return handleResult(false);
						}
						createListOfBestChildrenIncludedByLaterUnits(arrAltBranchRootUnits, function(arrAltBestChildren){
							determineMaxAltLevel(
								conn, first_unstable_mc_index, first_unstable_mc_level, arrAltBestChildren, arrWitnesses,
								function(max_alt_level){
									console.log("determineIfStableInLaterUnits with branches took "+(Date.now()-start_time)+"ms");
									// allow '=' since alt WL will *never* reach max_alt_level.
									// The comparison when moving the stability point above is still strict for compatibility
									handleResult(min_mc_wl >= max_alt_level);
								}
							);
						});
						
					});
				});
		
			});
		});
	
	});

}
```

**File:** network.js (L1258-1295)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
					if (objJoint.unsigned)
						throw Error("ifOk() unsigned");
					if (bPosted && objValidationState.sequence !== 'good') {
						validation_unlock();
						callbacks.ifUnitError("The transaction would be non-serial (a double spend)");
						delete assocUnitsInWork[unit];
						unlock();
						if (ws)
							writeEvent('nonserial', ws.host);
						return;
					}
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
						}
					}
					writer.saveJoint(objJoint, objValidationState, null, function(){
						validation_unlock();
						callbacks.ifOk();
						unlock();
						if (ws)
							writeEvent((objValidationState.sequence !== 'good') ? 'nonserial' : 'new_good', ws.host);
						notifyWatchers(objJoint, objValidationState.sequence === 'good', ws);
						if (objValidationState.arrUnitsGettingBadSequence)
							notifyWatchersAboutUnitsGettingBadSequence(objValidationState.arrUnitsGettingBadSequence);
						if (!bCatchingUp)
							eventBus.emit('new_joint', objJoint);
					});
				},
```
