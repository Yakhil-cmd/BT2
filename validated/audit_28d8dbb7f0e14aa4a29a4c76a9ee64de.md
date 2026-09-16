### Title
Time-of-check/time-of-use gap between unit validation commit and unit write allows a stale double-spend decision to be persisted - (File: `validation.js`, `writer.js`, `network.js`)

### Summary
`validation.validate()` performs all double-spend/sequence checks inside its own DB transaction (`BEGIN` ... `commit_fn` does `COMMIT`/`ROLLBACK`), releases the connection, and only afterwards hands control to the caller's `ifOk(objValidationState, unlock)` callback [1](#0-0) . The actual persistence of the unit (`writer.saveJoint`) happens later, in a brand-new transaction opened independently from the validation transaction [2](#0-1) . The `objValidationState` object computed during the "check" phase (sequence, `arrDoubleSpendInputs`, `is_unique` decisions) is reused unchanged as the "use" phase input to `writer.saveJoint`, e.g. via `network.js`'s `ifOk` handler which calls `writer.saveJoint(objJoint, objValidationState, ...)` [3](#0-2) .

### Finding Description
The classic TOCTOU pattern requires that between the "check" and the "use" some state the check relied on can change without the use noticing. Here:

1. `checkForDoublespends`/`checkInputDoubleSpend` in `validation.js` decides, per input, whether a conflicting spend exists and whether the unit under validation should have `is_unique=1` or `null`, and stages the "un-uniquify" SQL for the *competing* record into `objValidationState.arrAdditionalQueries` for public assets [4](#0-3) .
2. For private, divisible assets, the same function instead executes that "un-uniquify" UPDATE **immediately**, inside the validation connection, protected only by a separate `mutex.lock(["private_write"])` [5](#0-4) . This lock is unrelated to, and narrower than, the per-author-address lock (`mutex.lock(arrAuthorAddresses, ...)`) that wraps the whole `validate()` call [6](#0-5) .
3. `validation.validate()` commits/rolls back and **releases the connection** before invoking `callbacks.ifOk(objValidationState, unlock)` [7](#0-6) . The address-level `unlock` (a.k.a. `validation_unlock`) is only released by the caller — but the caller is trusted code, not a DB-transaction boundary; there is a real window between the validation-transaction commit and the write-transaction begin.
4. `writer.saveJoint` opens a **new** connection/transaction and blindly trusts the previously computed `objValidationState.arrDoubleSpendInputs` / `sequence` / `is_unique` values to write `inputs`/`outputs` rows [8](#0-7) , without re-verifying that the double-spend landscape is unchanged.
5. Meanwhile, `validateAndSaveDivisiblePrivatePayment` for private-chain elements writes its own `inputs`/`outputs` rows directly with `is_unique = bStable ? 1 : null` using only the input `conn` supplied by the recipient-side flow, with **no author-address mutex at all** around it — the address lock that guards the "public" path in `validation.validate()` is not held here [9](#0-8) .

Because the private-payment "check" (`validateDivisiblePrivatePayment` → `initPrivatePaymentValidationState`) and "use" (`validateAndSaveDivisiblePrivatePayment`'s INSERT/UPDATE) are two separate calls with no continuous lock over both, and because the concurrently-running public unit path can independently reach `checkInputDoubleSpend`'s `private_write`-guarded UPDATE for the *same* asset/output at essentially the same moment (guarded by a different mutex key than the address lock used elsewhere), two competing spends of the same private output can each observe the pre-update `is_unique=1` state and each proceed to persist their own input row with `is_unique=1`, because the DB-level UNIQUE constraint that would normally reject a genuine duplicate (`src_unit, src_message_index, src_output_index, is_unique`) is satisfied for each transaction separately (they commit in different transactions, at different times, not serialized by a common lock across the whole check-then-use sequence for private assets).

### Impact Explanation
If two conflicting spends of the same private-asset output can both persist with `is_unique=1` in `inputs`, this constitutes a double-spend of a private output that the sequence/uniqueness machinery was specifically designed to prevent — i.e., unauthorized/duplicate spending of asset balance, a critical concern for a payment DAG (the analog to NVIDIA's TOCTOU: a check performed against one snapshot of state, while the privileged "use" operation acts on a since-changed resource).

### Likelihood Explanation
Exploitation requires an attacker (as an asset holder / private-payment counterparty) to race two conflicting private-payment chains referencing the same private output through two different code paths (`network.js`'s public-joint `ifOk` path for a mixed base+private message vs. the private-chain-only `validateAndSaveDivisiblePrivatePayment` path used by wallet-to-wallet private transfers) so that their check/use windows overlap. This requires precise timing but is achievable by a local attacker controlling both counterparties or by an unprivileged private-payment counterparty racing against the node's own concurrent processing of an unrelated unit touching the same address. I was not able to fully confirm from the indexed code whether an additional, wider mutex elsewhere (outside the searched files) closes this window across both call paths; this is the primary source of uncertainty in this finding.

### Recommendation
- Ensure the entire check-then-use sequence for double-spend resolution (both public `arrAdditionalQueries` staged updates and the private-asset immediate `private_write` update) is performed under one lock that spans from the start of validation through the final commit of `writer.saveJoint`, keyed consistently (e.g., always by asset+output or by author address) rather than mixing `arrAuthorAddresses` and `["private_write"]` lock keys.
- In `writer.saveJoint`, re-check double-spend status against current DB state within the same transaction that performs the INSERT, instead of trusting `objValidationState` computed in a prior, already-committed transaction.
- For `validateAndSaveDivisiblePrivatePayment` (`divisible_asset.js`), acquire the same address/asset-output lock used by `validation.validate()` before performing the INSERT/UPDATE sequence, and hold it until the transaction commits.

### Proof of Concept
Conceptual (cannot be fully constructed without live race timing control):
1. Attacker owns a private-asset output `O` and constructs two private payment chains, `Unit A` and `Unit B`, each spending `O` to a different address.
2. Attacker submits `Unit A` via the standard network path (`network.js` `handleJoint` → `validation.validate` → `writer.saveJoint`) and, at nearly the same wall-clock instant, submits `Unit B` via the private-chain wallet path (`divisible_asset.validateAndSaveDivisiblePrivatePayment`) to a colluding or separate node process/connection so that its `initPrivatePaymentValidationState` check for `O` runs before `Unit A`'s validation transaction commits its `private_write`-protected uniqueness update.
3. If both checks observe `O` as not-yet-conflicted, both `Unit A` and `Unit B` persist input rows referencing `O` with `is_unique=1`, resulting in a double-spend of the private output. [4](#0-3) [9](#0-8) [2](#0-1)

### Citations

**File:** validation.js (L357-358)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
		
```

**File:** validation.js (L474-490)
```javascript
				else{
					profiler.stop('validation-messages');
					profiler.start();
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('validation', consumed_time);
						console.log(objUnit.unit+" validation ok took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						profiler.stop('validation-commit');
						if (objJoint.unsigned){
							unlock();
							callbacks.ifOkUnsigned(objValidationState.sequence === 'good');
						}
						else
							callbacks.ifOk(objValidationState, unlock);
					});
```

**File:** validation.js (L2258-2296)
```javascript
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
```

**File:** writer.js (L24-53)
```javascript
async function saveJoint(objJoint, objValidationState, preCommitCallback, onDone) {
	var objUnit = objJoint.unit;
	console.log("\nsaving unit "+objUnit.unit);
	var arrQueries = [];
	var commit_fn;
	if (objValidationState.conn && !objValidationState.batch)
		throw Error("conn but not batch");
	var bInLargerTx = (objValidationState.conn && objValidationState.batch);
	const bCommonOpList = objValidationState.last_ball_mci >= constants.v4UpgradeMci;

	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);

	function initConnection(handleConnection) {
		if (bInLargerTx) {
			profiler.start();
			commit_fn = function (sql, cb) { cb(); };
			return handleConnection(objValidationState.conn);
		}
		db.takeConnectionFromPool(function (conn) {
			profiler.start();
			conn.addQuery(arrQueries, "BEGIN");
			commit_fn = function (sql, cb) {
				conn.query(sql, function () {
					cb();
				});
			};
			handleConnection(conn);
		});
	}
```

**File:** writer.js (L355-393)
```javascript
								determineInputAddressFromSrcOutput(payload.asset, denomination, input, handleAddress);
							};
							
							determineInputAddress(function(address){
								// final-bad units are treated as non-existent competitors, their claims are never unique
								var is_unique = 
									(
										objValidationState.sequence === 'final-bad' ||
										objValidationState.arrDoubleSpendInputs.some(function (ds) { return (ds.message_index === i && ds.input_index === j); }) ||
										conf.bLight
									)
									? null : 1;
								conn.addQuery(arrQueries, "INSERT INTO inputs \n\
										(unit, message_index, input_index, type, \n\
										src_unit, src_message_index, src_output_index, \
										from_main_chain_index, to_main_chain_index, \n\
										denomination, amount, serial_number, \n\
										asset, is_unique, address) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
									[objUnit.unit, i, j, type, 
									 src_unit, src_message_index, src_output_index, 
									 from_main_chain_index, to_main_chain_index, 
									 denomination, input.amount, input.serial_number, 
									 payload.asset, is_unique, address]);
								switch (type){
									case "transfer":
										conn.addQuery(arrQueries, 
											"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
											[src_unit, src_message_index, src_output_index]);
										break;
									case "headers_commission":
									case "witnessing":
										var table = type + "_outputs";
										conn.addQuery(arrQueries, "UPDATE "+table+" SET is_spent=1 \n\
											WHERE main_chain_index>=? AND main_chain_index<=? AND +address=?", 
											[from_main_chain_index, to_main_chain_index, address]);
										break;
								}
								cb3();
							});
```

**File:** network.js (L1258-1294)
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
```

**File:** divisible_asset.js (L17-75)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	// we always have only one element
	validateAndSaveDivisiblePrivatePayment(conn, arrPrivateElements[0], callbacks);
}


function validateAndSaveDivisiblePrivatePayment(conn, objPrivateElement, callbacks){
	validateDivisiblePrivatePayment(conn, objPrivateElement, {
		ifError: callbacks.ifError,
		ifOk: function(bStable, arrAuthorAddresses){
			console.log("private validation OK "+bStable);
			var unit = objPrivateElement.unit;
			var message_index = objPrivateElement.message_index;
			var payload = objPrivateElement.payload;
			var arrQueries = [];
			for (var j=0; j<payload.outputs.length; j++){
				var output = payload.outputs[j];
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
			}
			for (var j=0; j<payload.inputs.length; j++){
				var input = payload.inputs[j];
				var type = input.type || "transfer";
				var src_unit = input.unit;
				var src_message_index = input.message_index;
				var src_output_index = input.output_index;
				var address = null, address_sql = null;
				if (type === "issue")
					address = input.address || arrAuthorAddresses[0];
				else{ // transfer
					if (arrAuthorAddresses.length === 1)
						address = arrAuthorAddresses[0];
					else
						address_sql = "(SELECT address FROM outputs \
						WHERE unit="+conn.escape(src_unit)+" AND message_index="+conn.escape(src_message_index)+" \
							AND output_index="+conn.escape(src_output_index)+" AND address IN("+conn.escape(arrAuthorAddresses)+"))";
				}
				var is_unique = bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				conn.addQuery(arrQueries, "INSERT INTO inputs \n\
						(unit, message_index, input_index, type, \n\
						src_unit, src_message_index, src_output_index, \
						serial_number, amount, \n\
						asset, is_unique, address) VALUES(?,?,?,?,?,?,?,?,?,?,?,"+(address_sql || conn.escape(address))+")",
					[unit, message_index, j, type, 
					 src_unit, src_message_index, src_output_index, 
					 input.serial_number, input.amount, 
					 payload.asset, is_unique]);
				if (type === "transfer"){
					conn.addQuery(arrQueries, 
						"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
						[src_unit, src_message_index, src_output_index]);
				}
			}
			async.series(arrQueries, callbacks.ifOk);
		}
	});
}
```
