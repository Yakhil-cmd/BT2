I have sufficient context to produce the final analysis.

### Title
`checkSerialAddressUse`/`findConflictingUnits` unbounded conflicting-unit set enables unit-validation DoS ([File: validation.js])

### Summary
The Sherlock report describes `accruePremiumAndExpireProtections` becoming un-callable because an unbounded `EnumerableSet` grows via cheap, unprivileged user actions and is then fully iterated in a loop, each iteration doing non-trivial work. The analogous root cause exists in ocore's per-unit author validation path: `findConflictingUnits` (called from `checkSerialAddressUse`) reads *every* non-final-bad unit ever authored by an address that is not yet included behind `last_ball_mci`, and then iterates that whole set with `async.eachSeries`, calling the expensive DAG-traversal function `graph.determineIfIncludedOrEqual` for each one.

### Finding Description
Every time a unit from address `objAuthor.address` is validated, `validateAuthor` → `checkSerialAddressUse` → `findConflictingUnits` runs this query: [1](#0-0) 
which selects all units authored by that address that are unstable (`_mci IS NULL`) or with `_mci` beyond the current `max_parent_limci`, excluding only `final-bad` units. It then does, for each row, a call to `graph.determineIfIncludedOrEqual`: [2](#0-1) 

`determineIfIncludedOrEqual`/`determineIfIncluded` is itself a graph walk that can issue multiple DB queries or in-memory traversals per call: [3](#0-2) 

An unprivileged unit poster can trivially grow this per-address working set: repeatedly post double-spending (non-serial, `temp-bad`) units from the same address without letting any of them stabilize (e.g., keep spending from unconfirmed outputs, or simply keep posting cheap zero-payload units that conflict). Because `sequence!='final-bad'` is the only exclusion filter, and `temp-bad`/pending units remain in the set until they become stable or `final-bad`, the attacker only needs to keep the address "in conflict" (which itself does not require large fees — trivial value-1 double-spends or repeated definition/other unit posts referencing the same unconfirmed inputs are sufficient) to keep accumulating rows returned by `findConflictingUnits`. Each subsequent unit from (or referencing double-spends against) that address then pays the full O(n) graph-traversal cost of `findConflictingUnits`, and this happens synchronously inside the hot `validateAuthor` path that every full node must execute for every incoming unit.

This mirrors the reported bug class exactly: a set that (a) is populated purely by unprivileged, low-cost user actions, (b) has no upper bound / pruning tied to those actions, and (c) is fully iterated with non-trivial per-item cost inside a function that is a required, frequently-invoked part of core protocol logic (unit validation), rather than an optional maintenance job.

### Impact Explanation
As the conflicting-unit set for a targeted/attacker-controlled address grows, `checkSerialAddressUse` becomes increasingly expensive for every node validating any new unit involving that address (as an author, or as a conflicting party being checked by other units' `findConflictingUnits`/`checkForDoublespends` calls, which use the identical `graph.determineIfIncludedOrEqual` pattern). This degrades validation throughput and, if scaled sufficiently, can stall a node's ability to validate/confirm units touching the poisoned address — matching the accepted impact class "node ... unable to confirm new units" for the affected address's activity, since validation of units from/about that address becomes computationally impractical.

### Likelihood Explanation
Likelihood is moderate-to-high: creating non-serial/conflicting units from a single address is cheap and requires no special privileges — any unit poster can author many small double-spending units. The set is not pruned as it grows (only excluded once a unit is `final-bad`, which requires further validation work by the network to resolve), so a sustained low-cost campaign can accumulate a large backlog before finalization catches up, and `graph.determineIfIncludedOrEqual`'s cost is not O(1), amplifying total effect from `O(n)` items into effectively `O(n·traversal_cost)`.

### Recommendation
- Cap the number of tracked unstable/non-final-bad conflicting units per address that `findConflictingUnits` will process, or short-circuit once a bounded threshold is exceeded (analogous to the report's suggestion of bounding `activeProtectionIndexes`).
- Consider more aggressive/faster resolution (or fee-based deterrence) of the `temp-bad` → `final-bad`/`good` state to keep this set small in practice.
- Optimize `graph.determineIfIncludedOrEqual` calls in this loop, e.g., batch/short-circuit checks (the `bAllSerial` early-exit already helps for the all-serial case, but provides no protection when many mutually conflicting non-serial units exist).

### Proof of Concept
1. From address `A`, spend a small unconfirmed output twice, in units `U1` and `U2`, to create a genuine double-spend before either stabilizes.
2. Repeat similar double-spend patterns from `A` many times (each cheap, using minimal value/fee), so that many units from `A` remain `temp-bad`/unstable simultaneously rather than resolving to `final-bad` quickly.
3. Post another unit `U_n` authored by (or referencing an output that conflicts with) `A`.
4. Observe that `checkSerialAddressUse`/`findConflictingUnits` for `U_n` must query and then `graph.determineIfIncludedOrEqual`-traverse every accumulated conflicting unit for `A`, with cost growing linearly (times traversal cost) in the number of accumulated conflicting units, degrading validation time for any node processing units touching address `A`.

### Citations

**File:** validation.js (L1257-1301)
```javascript
	function findConflictingUnits(handleConflictingUnits){
	//	var cross = (objValidationState.max_known_mci - objValidationState.max_parent_limci < 1000) ? 'CROSS' : '';
		var indexMySQL = conf.storage == "mysql" ? "USE INDEX(unitAuthorsIndexByAddressMci)" : "";
		conn.query( // _left_ join forces use of indexes in units
		/*	"SELECT unit, is_stable \n\
			FROM units \n\
			"+cross+" JOIN unit_authors USING(unit) \n\
			WHERE address=? AND (main_chain_index>? OR main_chain_index IS NULL) AND unit != ?",
			[objAuthor.address, objValidationState.max_parent_limci, objUnit.unit],*/
			// final-bad units are permanently voided and never come back to 'good', so they are not real competitors:
			// exclude them here rather than only when deciding bConflictsWithStableUnits below
			"SELECT unit, is_stable, sequence, level \n\
			FROM unit_authors "+indexMySQL+"\n\
			CROSS JOIN units USING(unit)\n\
			WHERE address=? AND _mci>? AND unit != ? AND sequence!='final-bad' \n\
			UNION \n\
			SELECT unit, is_stable, sequence, level \n\
			FROM unit_authors "+indexMySQL+"\n\
			CROSS JOIN units USING(unit)\n\
			WHERE address=? AND _mci IS NULL AND unit != ? AND sequence!='final-bad' \n\
			ORDER BY level DESC",
			[objAuthor.address, objValidationState.max_parent_limci, objUnit.unit, objAuthor.address, objUnit.unit],
			function(rows){
				if (rows.length === 0)
					return handleConflictingUnits([]);
				var bAllSerial = rows.every(function(row){ return (row.sequence === 'good'); });
				var arrConflictingUnitProps = [];
				async.eachSeries(
					rows,
					function(row, cb){
						graph.determineIfIncludedOrEqual(conn, row.unit, objUnit.parent_units, function(bIncluded){
							if (!bIncluded)
								arrConflictingUnitProps.push(row);
							else if (bAllSerial)
								return cb('done'); // all are serial and this one is included, therefore the earlier ones are included too
							cb();
						});
					},
					function(){
						handleConflictingUnits(arrConflictingUnitProps);
					}
				);
			}
		);
	}
```

**File:** graph.js (L131-249)
```javascript
function determineIfIncluded(conn, earlier_unit, arrLaterUnits, handleResult){
//	console.log('determineIfIncluded', earlier_unit, arrLaterUnits, new Error().stack);
	if (!earlier_unit)
		throw Error("no earlier_unit");
	if (!arrLaterUnits || arrLaterUnits.length === 0)
		throw Error("no later units");
	if (!handleResult)
		return new Promise(resolve => determineIfIncluded(conn, earlier_unit, arrLaterUnits, resolve));
	if (storage.isGenesisUnit(earlier_unit))
		return handleResult(true);
	storage.readPropsOfUnits(conn, earlier_unit, arrLaterUnits, function(objEarlierUnitProps, arrLaterUnitProps){
		if (objEarlierUnitProps.is_free === 1)
			return handleResult(false);
		
		var max_later_limci = Math.max.apply(
			null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.latest_included_mc_index; }));
		//console.log("max limci "+max_later_limci+", earlier mci "+objEarlierUnitProps.main_chain_index);
		if (objEarlierUnitProps.main_chain_index !== null && max_later_limci >= objEarlierUnitProps.main_chain_index)
			return handleResult(true);
		if (max_later_limci < objEarlierUnitProps.latest_included_mc_index)
			return handleResult(false);
		
		var max_later_level = Math.max.apply(
			null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.level; }));
		if (max_later_level < objEarlierUnitProps.level)
			return handleResult(false);
		
		var max_later_wl = Math.max.apply(
			null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.witnessed_level; }));
		if (max_later_wl < objEarlierUnitProps.witnessed_level && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
			return handleResult(false);
		
		var bAllLaterUnitsAreWithMci = !arrLaterUnitProps.find(function(objLaterUnitProps){ return (objLaterUnitProps.main_chain_index === null); });
		if (bAllLaterUnitsAreWithMci){
			if (objEarlierUnitProps.main_chain_index === null){
				console.log('all later are with mci, earlier is null mci', objEarlierUnitProps, arrLaterUnitProps);
				return handleResult(false);
			}
			var max_later_mci = Math.max.apply(
				null, arrLaterUnitProps.map(function(objLaterUnitProps){ return objLaterUnitProps.main_chain_index; }));
			if (max_later_mci < objEarlierUnitProps.main_chain_index)
				return handleResult(false);
		}
		
		var arrKnownUnits = [];
		
		function goUp(arrStartUnits){
		//	console.log('determine goUp', earlier_unit, arrLaterUnits/*, arrStartUnits*/);
			arrKnownUnits = arrKnownUnits.concat(arrStartUnits);
			var arrDbStartUnits = [];
			var arrParents = [];
			arrStartUnits.forEach(function(unit){
				var props = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
				if (!props || !props.parent_units){
					arrDbStartUnits.push(unit);
					return;
				}
				props.parent_units.forEach(function(parent_unit){
					var objParent = storage.assocUnstableUnits[parent_unit] || storage.assocStableUnits[parent_unit];
					if (!objParent){
						if (arrDbStartUnits.indexOf(unit) === -1)
							arrDbStartUnits.push(unit);
						return;
					}
					/*objParent = _.cloneDeep(objParent);
					for (var key in objParent)
						if (['unit', 'level', 'latest_included_mc_index', 'main_chain_index', 'is_on_main_chain'].indexOf(key) === -1)
							delete objParent[key];*/
					arrParents.push(objParent);
				});
			});
			if (arrDbStartUnits.length > 0){
				console.log('failed to find all parents in memory, will query the db, earlier '+earlier_unit+', later '+arrLaterUnits+', not found '+arrDbStartUnits);
				arrParents = [];
			}
			
			function handleParents(rows){
			//	var sort_fun = function(row){ return row.unit; };
			//	if (arrParents.length > 0 && !_.isEqual(_.sortBy(rows, sort_fun), _.sortBy(arrParents, sort_fun)))
			//		throw Error("different parents");
				var arrNewStartUnits = [];
				for (var i=0; i<rows.length; i++){
					var objUnitProps = rows[i];
					if (objUnitProps.unit === earlier_unit)
						return handleResult(true);
					if (objUnitProps.main_chain_index !== null && objUnitProps.main_chain_index <= objEarlierUnitProps.latest_included_mc_index)
						continue;
					if (objUnitProps.main_chain_index !== null && objEarlierUnitProps.main_chain_index !== null && objUnitProps.main_chain_index < objEarlierUnitProps.main_chain_index)
						continue;
					if (objUnitProps.main_chain_index !== null && objEarlierUnitProps.main_chain_index === null)
						continue;
					if (objUnitProps.latest_included_mc_index < objEarlierUnitProps.latest_included_mc_index)
						continue;
					if (objUnitProps.witnessed_level < objEarlierUnitProps.witnessed_level && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
						continue;
					if (objUnitProps.is_on_main_chain === 0 && objUnitProps.level > objEarlierUnitProps.level)
						arrNewStartUnits.push(objUnitProps.unit);
				}
				arrNewStartUnits = _.uniq(arrNewStartUnits);
				arrNewStartUnits = _.difference(arrNewStartUnits, arrKnownUnits);
				(arrNewStartUnits.length > 0) ? goUp(arrNewStartUnits) : handleResult(false);
			}
			
			if (arrParents.length)
				return setImmediate(handleParents, arrParents);
			
			conn.query(
				"SELECT unit, level, witnessed_level, latest_included_mc_index, main_chain_index, is_on_main_chain \n\
				FROM parenthoods JOIN units ON parent_unit=unit \n\
				WHERE child_unit IN(?)",
				[arrStartUnits],
				handleParents
			);
		}
		
		goUp(arrLaterUnits);
	
	});
}
```
