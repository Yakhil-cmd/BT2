### Title
Reachable node crash via `throw Error` assertions in double-spend validation - (File: validation.js)

### Summary
CVE-2019-6473 shows a class of bug where a value in unprivileged, attacker-controlled input reaches a hard assertion inside the server's core processing path, causing the process to exit. `ocore`'s unit-validation path contains several unconditional `throw Error(...)` assertions inside `checkForDoublespends()` in [1](#0-0)  that fire while validating payment inputs for a unit that any unprivileged peer can post (`validatePaymentInputsAndOutputs` → `checkInputDoubleSpend` → `checkForDoublespends`, see [2](#0-1) ). If a code path can be found where a "conflicting" double-spend record's stored address does not match the current unit's author addresses, or is not covered by `arrAddressesWithForkedPath`, the throw is unconditional and uncaught inside the async DB callback, which ultimately propagates to the top-level `process.on('uncaughtException')` handler in [3](#0-2)  that deliberately re-throws to crash the node.

### Finding Description
`validation.js` performs an assertion-style `throw Error` for cases the developers believed were logically impossible:
- `throw Error("conflicting "+type+" spent from another address?")` at [4](#0-3) 
- `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` at [5](#0-4) 
- `throw Error("double spending "+type+" without double spending address?")` at [6](#0-5) 

These are reached from `checkInputDoubleSpend`, called for every `issue`/`transfer`/`headers_commission`/`witnessing` input while validating a unit's payment message ( [7](#0-6) ). For the `issue` input type on assets with `issued_by_definer_only`, the double-spend `WHERE` clause deliberately omits the `address=?` filter ( [8](#0-7) ), unlike the `transfer` and `headers_commission`/`witnessing` branches, which always constrain by an address known to be one of the current unit's authors ( [9](#0-8)  and [10](#0-9) ). This asymmetry means the `issue` branch's double-spend query can return matching rows keyed only by `(type='issue', denomination, serial_number)`, without pinning to a specific address, whenever `objAsset.issued_by_definer_only` is true.

This is directly analogous to CVE-2019-6473: an attacker who controls one field of a message (here, the issue input's `serial_number`/`denomination`/asset selection, analogous to the DHCPv4 hostname option) can drive the validator into a state the code treats as "impossible", triggering the hard assertion (`throw Error`) instead of returning a normal validation error via callback.

### Impact Explanation
Any of these `throw` statements executing inside the async DB-query callback is not caught by the surrounding `try/catch` of `validate()` (there is none around this async chain), so it escalates to an uncaught exception. `network.js`'s `process.on('uncaughtException')` handler explicitly re-throws to crash the process ( [3](#0-2) ), taking down the full node — matching the "server process exit" impact of the CVE. Because unit validation is on the hot path for every unit relayed to a full node (from wallets, AAs, or peers), and it also affects `writer`/`saveJoint` flows used for issued assets and AA-composed payments, this could be used to remotely crash arbitrary full nodes, halting new-unit confirmation for the network reachable through that node (denial of service to a core validation function, not merely a peer-only path).

### Likelihood Explanation
Exploitability is **not confirmed**: the exact preconditions require constructing two units — one prior "conflicting" issuance and a new candidate issuance of the same `issued_by_definer_only` asset, same `denomination`/`serial_number`, from addresses arranged so that `findConflictingUnits`/`arrAddressesWithForkedPath` bookkeeping (set only per-author in `validateAuthor`, [11](#0-10) ) does not include the conflicting record's address. Whether `issued_by_definer_only` issuance is otherwise constrained elsewhere (e.g., forcing `address === objAsset.definer_address`) could not be fully verified within the available context/tool budget — I found many references to `issued_by_definer_only` across `validation.js`, `indivisible_asset.js`, `storage.js`, and `writer.js` but did not have remaining iterations to trace all enforcement points. This uncertainty means the likelihood of a fully unprivileged, single-poster trigger is **unconfirmed** rather than proven.

### Recommendation
- Replace the `throw Error(...)` assertions in `checkForDoublespends` (lines 1673, 1688, 1692) with calls to `cb2(err)`/`cb(err)` that route through the normal `ifUnitError`/`ifJointError` callback path, so any unexpected data results in unit rejection instead of a process crash.
- Audit the `issue`-branch double-spend `WHERE` clause construction ( [12](#0-11) ) to always include an `address` constraint consistent with the `transfer`/`witnessing` branches, removing the asymmetry that allows address-independent matches for `issued_by_definer_only` assets.
- Add defensive checks (returning validation errors, not throwing) in front of every "should never happen" assertion inside async DB-callback chains reachable from `validate()`, since these all crash the node when triggered by unexpected but attacker-influenced data.

### Proof of Concept
Not fully constructible with confidence from static analysis alone. The suspected trigger requires two sequential units:
1. Unit A: author X issues an `issued_by_definer_only`, non-fixed-denomination asset input with `denomination=D`, `serial_number=1`.
2. Unit B: author Y (a different address, but somehow satisfying the earlier per-author owner/author checks for the same asset) issues another `issue` input with the same `denomination=D` and `serial_number=1`, positioned so that `findConflictingUnits`/`arrAddressesWithForkedPath` for Y does not contain X's address.

Because full verification of the `issued_by_definer_only` address-binding checks elsewhere in the codebase could not be completed, this PoC sketch should be validated by a maintainer/tester against the actual `issued_by_definer_only` issuance rules before treating this as a confirmed exploitable path.

### Citations

**File:** validation.js (L1304-1343)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
			}
			var arrConflictingUnits = arrConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			breadcrumbs.add("========== found conflicting units "+arrConflictingUnits+" =========");
			breadcrumbs.add("========== will accept a conflicting unit "+objUnit.unit+" =========");
			objValidationState.arrAddressesWithForkedPath.push(objAuthor.address);
			objValidationState.arrConflictingUnits = (objValidationState.arrConflictingUnits || []).concat(arrConflictingUnits);
			bNonserial = true;
			var arrUnstableConflictingUnitProps = arrConflictingUnitProps.filter(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 0);
			});
			// findConflictingUnits() already excludes final-bad rows, so any stable row left here is a real, good competitor
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			// if we are (or already became, due to another author) final-bad, we are not a living competitor for this address either,
			// so there is no need to punish other pending units - they'll correctly resolve to 'good' on their own once stable
			if (objValidationState.sequence === 'final-bad')
				return next();
			if (arrUnstableConflictingUnits.length === 0)
				return next();
			conn.query("SELECT unit FROM units WHERE unit IN(?) AND +sequence='good'",[arrUnstableConflictingUnits],function(rows){
				if (rows.length > 0)
					objValidationState.arrUnitsGettingBadSequence = (objValidationState.arrUnitsGettingBadSequence || []).concat(rows.map(function(row){return row.unit}));
				// we don't modify the db during validation, schedule the update for the write
				objValidationState.arrAdditionalQueries.push(
				{sql: "UPDATE units SET sequence='temp-bad' WHERE unit IN(?) AND +sequence='good'", params: [arrUnstableConflictingUnits]});
				next();
				});
		});
	}
```

**File:** validation.js (L1661-1705)
```javascript
function checkForDoublespends(conn, type, sql, arrSqlArgs, objUnit, objValidationState, onAcceptedDoublespends, cb){
	conn.query(
		sql, 
		arrSqlArgs,
		function(rows){
			if (rows.length === 0)
				return cb();
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			async.eachSeries(
				rows,
				function(objConflictingRecord, cb2){
					if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
						throw Error("conflicting "+type+" spent from another address?");
					if (conf.bLight) // we can't use graph in light wallet, the private payment can be resent and revalidated when stable
						return cb2(objUnit.unit+": conflicting "+type);
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state); final-bad is excluded by the query and treated as non-existent
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
							cb2();
						}
					});
				},
				function(err){
					if (err)
						return cb(err);
					onAcceptedDoublespends(cb);
				}
			);
		}
	);
}
```

**File:** validation.js (L2239-2305)
```javascript
	async.forEachOfSeries(
		payload.inputs,
		function(input, input_index, cb){
			if (!isNonemptyObject(input))
				return cb("input must be a non-empty object");
			if (objAsset){
				if ("type" in input && input.type !== "issue")
					return cb("non-base input can have only type=issue");
			}
			else{
				if ("type" in input && !["issue", "headers_commission", "witnessing"].includes(input.type))
					return cb("bad input type");
			}
			var type = input.type || "transfer";

			var doubleSpendFields = "unit, address, message_index, input_index, main_chain_index, sequence, is_stable";
			var doubleSpendWhere;
			var doubleSpendVars = [];
			var doubleSpendIndexMySQL = "";
			function checkInputDoubleSpend(cb2){
			//	if (objAsset)
			//		profiler2.start();
				doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
				if (objAsset){
					doubleSpendWhere += " AND asset=?";
					doubleSpendVars.push(payload.asset);
				}
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
				checkForDoublespends(
					conn, "divisible input", 
					doubleSpendQuery, doubleSpendVars, 
					objUnit, objValidationState, 
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
					}, 
					function onDone(err){
						if (err && objAsset && objAsset.is_private && !conf.bLight)
							throw Error("spend proof didn't help: "+err);
					//	if (objAsset)
					//		profiler2.stop('checkInputDoubleSpend');
						cb2(err);
					}
				);
			}
```

**File:** validation.js (L2360-2373)
```javascript
					doubleSpendWhere = "type='issue'";
					doubleSpendVars = [];
				//	if (objAsset && objAsset.fixed_denominations){
						doubleSpendWhere += " AND denomination=?";
						doubleSpendVars.push(denomination);
				//	}
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
					}
					if (objAsset && !objAsset.issued_by_definer_only){
						doubleSpendWhere += " AND address=?";
						doubleSpendVars.push(address);
					}
```

**File:** validation.js (L2407-2408)
```javascript
					doubleSpendWhere = "type=? AND src_unit=? AND src_message_index=? AND src_output_index=?";
					doubleSpendVars = [type, input.unit, input.message_index, input.output_index];
```

**File:** validation.js (L2569-2577)
```javascript
					var input_key = type + "-" + address;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
					
					doubleSpendWhere = "type=? AND from_main_chain_index=? AND address=? AND asset IS NULL";
					doubleSpendVars = [type, input.from_main_chain_index, address];
					if (conf.storage == "mysql")
						doubleSpendIndexMySQL = " USE INDEX (byIndexAddress) ";
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
