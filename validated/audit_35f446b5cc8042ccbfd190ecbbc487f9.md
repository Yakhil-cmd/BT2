### Title
Unhandled exception in AA response‑unit validation causes full node crash (DoS) triggerable by any unprivileged unit poster — ([File: aa_composer.js])

### Summary
CVE‑2022‑21454 describes a low‑privileged, network‑reachable actor causing a MySQL Server crash/hang via the Group Replication plugin. The closest reachable analog in ocore is not in MySQL itself but in the AA (Autonomous Agent) trigger‑execution pipeline: an unprivileged user can post an ordinary unit that pays an AA, and the resulting **internally generated AA response unit** is validated with a callback set that throws unhandled `Error`s instead of returning a normal error to the caller. Since these callbacks fire deep inside async database/kvstore callback chains that are outside the mutex/try‑catch scope used for externally received units, an uncaught exception here crashes the whole Node.js process on any full node that executes the trigger — i.e. every node in the network that has caught up to the relevant MCI.

### Finding Description
When a unit pays to an AA address, `validateAATrigger` and `handleAATriggers`/`handlePrimaryAATrigger` run the AA and compose a response unit via `handleTrigger` → `sendUnit` → `validateAndSaveUnit`: [1](#0-0) 

Inside `validateAndSaveUnit`, most of the `validation.validate()` callback branches — `ifJointError`, `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`, and the `sequence !== 'good'` branch of `ifOk` — all execute `throw Error(...)` rather than propagating an error through `cb()`: [2](#0-1) 

Likewise, a failure returned by `writer.saveJoint` in this path also throws instead of being handled gracefully: [3](#0-2) 

These throws happen while executing the AA in `handlePrimaryAATrigger`, which is invoked automatically for *every stabilized unit that pays an AA*, from the writer/stabilization pipeline: [4](#0-3) [5](#0-4) [6](#0-5) 

Because the AA's response unit is composed from author‑controlled input (`trigger.data`, `trigger.outputs`, formulas referencing `trigger.*`, secondary AA chains, state‑var interactions, balance edge cases, etc.), an attacker who crafts a specific payment/data payload to an AA can drive the composed response unit into one of these "impossible" branches (e.g. transiently unresolved dependency, a definition not yet available at this MCI, or a race that makes the freshly composed response nonserial). Since `validation.validate` is designed for network‑received joints where such states are expected and are handled softly (see the parallel, non‑throwing handling in `network.js`'s `handleJoint`): [7](#0-6) 

but the AA composer path assumes these states are "impossible" and throws instead, an attacker-influenced trigger that hits one of these edge conditions raises an uncaught exception inside an async callback chain (database query callback / kvstore write callback), which Node.js cannot recover from unless a global `uncaughtException` handler is present and chooses to keep running. This is the same bug class as CVE‑2022‑21454: a low‑privileged, network‑reachable input causes the server process to crash or hang.

### Impact Explanation
If an unprivileged unit poster can construct a trigger unit that forces `validateAndSaveUnit`'s AA‑generated response unit into an "unexpected" validation branch, every full node (and hub) that processes the stabilized MCI containing that trigger executes the same AA logic and hits the same throw, since AA execution is deterministic and mandatory across all full nodes. This can crash all full nodes in the network simultaneously, producing "a network unable to confirm new units" — nodes able to restart will re-execute the same trigger during recovery and crash again, causing a repeatable, network‑wide denial of service, matching the "hang or frequently repeatable crash" impact class in the CVE.

### Likelihood Explanation
Exploitability requires finding a concrete formula/state/balance/asset combination that pushes AA execution into one of the throwing branches (e.g., unexpected `ifNeedParentUnits`, `ifTransientError`, or `sequence !== 'good'` for the just‑composed response unit). The code comments ("nonserial AA", "unexpected dependencies") indicate the developers believed these states unreachable for internally generated units, but the AA system is complex (secondary triggers, base AAs, asset issuance/transfer conditions, storage_size adjustments, oversize fee calculation) and has had multiple related upgrade forks (`pemCurvesFixMci`, `aa3UpgradeMci`, etc.) to patch edge cases — evidence that "impossible" states have occurred in practice. Confirming a concrete trigger PoC requires deeper live/dynamic analysis of the exact edge condition (e.g., a race where the AA response unit's `last_ball_unit` briefly lacks the definition of an asset/AA referenced in the message, forcing an unresolved‑dependency response), which could not be fully proven statically from the indexed code alone.

### Recommendation
- Replace all `throw Error(...)` statements in `aa_composer.js`'s `validateAndSaveUnit` (`ifJointError`, `ifTransientError`, `ifNeedHashTree`, `ifNeedParentUnits`, `ifOkUnsigned`, the `sequence !== 'good'` check, and the `writer.saveJoint` error callback) with graceful failure handling (e.g. `return cb(err)`/bounce the AA trigger) instead of crashing the process.
- Add defensive validation/fallback so that any AA‑composed response unit that would fail full network validation is bounced rather than propagated to a throw.
- Wrap high‑risk internal‑unit composition/validation code paths in `try/catch` at the top level and log+bounce on any unexpected internal error, rather than allowing an uncaught exception to terminate the process.

### Proof of Concept
Not concretely reproducible from static analysis alone. A full PoC would require constructing an AA definition and a triggering unit whose composed response — computed by `handleTrigger`/`sendUnit` in `aa_composer.js` — hits one of the "impossible" validation branches (e.g., a response unit that momentarily is nonserial due to a double‑spend against another still‑unstable AA response, or one whose `last_ball_unit`/dependency state triggers `ifNeedParentUnits`/`ifTransientError` in `validation.js`), which then throws inside `validateAndSaveUnit` (aa_composer.js:1802-1838) and crashes the executing node.

### Citations

**File:** aa_composer.js (L91-150)
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
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
										// copy updatedStateVars to all responses
										if (arrResponses[0].updatedStateVars)
											for (var i = 1; i < arrResponses.length; i++)
												arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
										// merge all changes of balances if the same AA was called more than once
										let assocBalances = {};
										for (let { aa_address, balances } of arrResponses)
											assocBalances[aa_address] = balances; // overwrite if repeated
										for (let r of arrResponses) {
											r.balances = assocBalances[r.aa_address];
											r.allBalances = assocBalances;
										}
									}
									else
										arrResponses[0].allBalances = { [address]: arrResponses[0].balances };
									arrResponses.forEach(function (objAAResponse) {
										if (objAAResponse.objResponseUnit)
											arrPostedUnits.push(objAAResponse.objResponseUnit);
										eventBus.emit('aa_response', objAAResponse);
										eventBus.emit('aa_response_to_unit-'+objAAResponse.trigger_unit, objAAResponse);
										eventBus.emit('aa_response_to_address-'+objAAResponse.trigger_address, objAAResponse);
										eventBus.emit('aa_response_from_aa-'+objAAResponse.aa_address, objAAResponse);
									});
									onDone();
								});
							});
						});
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L1800-1838)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
		}, conn);
	}
```

**File:** main_chain.js (L1691-1723)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
	}
```

**File:** writer.js (L720-759)
```javascript
								if (arrStabilizedMcis.length > 0 && (bInLargerTx || objValidationState.bUnderWriteLock))
									throw Error(`saveJoint stabilized an MCI while in larger tx or under write lock`);
								if (arrStabilizedMcis.length > 1)
									throw Error(`saveJoint stabilized more than one MCI: ${arrStabilizedMcis.join(', ')}`);
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();

									if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
										// get a new connection to write tps fees
										const conn = await db.takeConnectionFromPool();
										await conn.query("BEGIN");
										await storage.updateTpsFees(conn, arrStabilizedMcis);
										await conn.query("COMMIT");
										conn.release();
									}
								}
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
										if (bStabilizedAATriggers) {
											console.log(`executing AA triggers after additional stabilization`, arrStabilizedMcis);
											// every trigger takes its own db connection
											const aa_composer = require("./aa_composer.js");
											await aa_composer.handleAATriggers();
										}
```

**File:** network.js (L1174-1218)
```javascript
			validation.validate(objJoint, {
				ifUnitError: function(error){
					console.log(objJoint.unit.unit+" validation failed: "+error);
					clearHost();
					callbacks.ifUnitError(error);
					if (constants.bDevnet)
						throw Error(error);
					purgeJointAndDependenciesAndNotifyPeers(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws && error !== 'authentifier verification failed' && !error.match(/bad merkle proof at path/) && !bPosted)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
				ifJointError: function(error){
					clearHost();
					callbacks.ifJointError(error);
				//	throw Error(error);
					joint_storage.saveKnownBadJoint(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
				ifTransientError: function(error){
				//	throw Error(error);
					console.log("############################## transient error "+error);
					clearHost();
					callbacks.ifTransientError ? callbacks.ifTransientError(error) : callbacks.ifUnitError(error);
					process.nextTick(unlock);
					joint_storage.removeUnhandledJointAndDependencies(unit, function(){
					//	if (objJoint.ball)
					//		db.query("DELETE FROM hash_tree_balls WHERE ball=? AND unit=?", [objJoint.ball, objJoint.unit.unit]);
						delete assocUnitsInWork[unit];
					});
					if (error.includes("last ball just advanced"))
						setTimeout(rerequestLostJoints, 10 * 1000, true);
					if (error === "possible AA" && bCatchingUp)
						tryToAdvanceStabilityPointForCatchupAATrigger(objJoint);
				},
```
