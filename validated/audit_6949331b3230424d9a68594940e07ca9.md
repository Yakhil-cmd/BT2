## Analysis

The FISCO‑BCOS CVE describes a class of bug where a transaction's effects can be recorded/served as "processed" while the durable state that prevents its re-spend is not actually committed, letting an attacker double-spend. The closest reachable analog in `ocore` is in the unit-persistence path, `writer.js`'s `saveJoint`, where the joint is durably written to the KV store **before** the SQL transaction that records double-spend protection is committed, with no atomicity between the two stores.

### Title
Non-atomic two-phase persistence in `saveJoint` (KV-store write before SQL `COMMIT`) enables double-spend on interrupted writes - (File: writer.js)

### Summary
`saveJoint` first performs a synced `batch.write` to the LevelDB-backed KV store (making the joint JSON permanently retrievable under key `'j\n'+unit`), and only afterward runs `commit_fn(... "COMMIT" ...)` against the SQL connection that actually persists the `inputs`/`outputs` rows used for double-spend detection. [1](#0-0) 

### Finding Description
Double-spend prevention in `ocore` is enforced entirely by the SQL layer: `checkForDoublespends`/`checkInputDoubleSpend` query the `inputs` table (and its `UNIQUE(src_unit, src_message_index, src_output_index, is_unique)` constraint) to detect whether an output was already claimed by another unit. [2](#0-1) [3](#0-2) 

`saveJoint` writes the winning joint bytes to the KV store first (`batch.write({sync:true}, ...)`), and only in the next step commits (or rolls back) the SQL transaction that inserts the corresponding `inputs` row and flips `outputs.is_spent=1`: [4](#0-3) [5](#0-4) 

If the process is interrupted (crash, OOM-kill, forced restart) after the KV-store batch write succeeds but before the SQL `COMMIT` completes, on restart the SQL transaction is lost (uncommitted transactions are not durable), so the `inputs` row that would mark the spent output as claimed never exists. However, the joint content is already permanently stored in the KV store and can be served to peers/light clients that look it up by unit hash, and the underlying output is still absent from `inputs`, so a second, conflicting unit spending the same source output will pass `checkInputDoubleSpend` as "good" because no competing `inputs` record is found in SQL.

### Impact Explanation
This breaks the fundamental double-spend guarantee for a payment output: after a restart racing the two-phase write, an attacker (or the same node re-processing) can get two units that spend the same source output both treated as validly serial by different points in time/different nodes, since the SQL side, which is the sole enforcement point, never recorded the first spend. This can lead to unauthorized double-spending of a stable output and to disagreement between nodes about which spend is valid, undermining consensus finality — matching the "High" DoS/double-spend impact class of the reference CVE.

### Likelihood Explanation
The unsafe ordering (KV write, then SQL commit) executes on every single unit write in `saveJoint`, so the vulnerable window exists continuously; only an interruption between the two steps is needed to trigger the inconsistency (process kill, host crash/reboot, container restart, or any unhandled exception path that skips `commit_fn`). No privileged network position or peer collusion is required — the condition is purely about the persistence-layer ordering triggered by ordinary unit processing.

### Recommendation
Make joint persistence atomic with respect to the SQL transaction that enforces double-spend protection: either (a) write to the KV store only after the SQL `COMMIT` has fully succeeded, or (b) add a startup/recovery reconciliation step that verifies every joint present in the KV store also has matching committed rows in `inputs`/`outputs`/`units`, purging or re-validating orphaned KV entries that lack a corresponding SQL commit.

### Proof of Concept
1. Node processes a unit `U1` with a payment input spending output `O`.
2. `saveJoint` executes `batch.write({sync:true}, ...)` successfully, persisting `U1`'s joint in the KV store.
3. Before `commit_fn("COMMIT", ...)` finishes, the process is killed (crash/OOM/forced restart).
4. On restart, the SQL transaction for `U1` is not committed, so `inputs` has no row for `U1`'s spend of `O`, and `outputs.is_spent` for `O` is still `0`.
5. `U1`'s joint remains servable from the KV store (e.g., via joint lookup/catchup).
6. Attacker submits `U2`, spending the same output `O`; `checkInputDoubleSpend` finds no conflicting `inputs` row, so `U2` validates as `sequence='good'` and is committed normally, completing a double-spend of `O`.

### Citations

**File:** writer.js (L365-414)
```javascript
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
						},
						function(){
							for (var j=0; j<payload.outputs.length; j++){
								var output = payload.outputs[j];
								// we set is_serial=1 for public payments as we check that their inputs are stable and serial before spending, 
								// therefore it is impossible to have a nonserial in the middle of the chain (but possible for private payments)
								conn.addQuery(arrQueries, 
									"INSERT INTO outputs \n\
									(unit, message_index, output_index, address, amount, asset, denomination, is_serial) VALUES(?,?,?,?,?,?,?,1)",
									[objUnit.unit, i, j, output.address, parseInt(output.amount), payload.asset, denomination]
								);
							}
							cb2();
						}
					);
				},
				cb
			);
		}
				
		function updateBestParent(cb){
```

**File:** writer.js (L687-715)
```javascript
							var batch_start_time = Date.now();
							batch.put('j\n'+objUnit.unit, JSON.stringify(objJoint));
							if (bInLargerTx)
								return cb();
							batch.write({ sync: true }, function(err){
								console.log("batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("writer: batch write failed: "+err);
								cb();
							});
						}
						
						saveToKvStore(function(){
							profiler.stop('write-batch-write');
							profiler.start();
							commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
								var consumed_time = Date.now()-start_time;
								profiler.add_result('write', consumed_time);
								console.log((err ? (err+", therefore rolled back unit ") : "committed unit ")+objUnit.unit+", write took "+consumed_time+"ms");
								profiler.stop('write-sql-commit');
								profiler.increment();
								if (err) {
									var headers_commission = require("./headers_commission.js");
									headers_commission.resetMaxSpendableMci();
									delete storage.assocUnstableMessages[objUnit.unit];
									await storage.resetMemory(conn);
								}
								if (!bInLargerTx)
									conn.release();
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

**File:** initial-db/byteball-sqlite.sql (L288-315)
```sql
CREATE TABLE inputs (
	unit CHAR(44) NOT NULL,
	message_index TINYINT NOT NULL,
	input_index TINYINT NOT NULL,
	asset CHAR(44) NULL,
	denomination INT NOT NULL DEFAULT 1,
	is_unique TINYINT NULL DEFAULT 1,
	type TEXT CHECK (type IN('transfer','headers_commission','witnessing','issue')) NOT NULL,
	src_unit CHAR(44) NULL, -- transfer
	src_message_index TINYINT NULL, -- transfer
	src_output_index TINYINT NULL, -- transfer
	from_main_chain_index INT NULL, -- witnessing/hc
	to_main_chain_index INT NULL, -- witnessing/hc
	serial_number BIGINT NULL, -- issue
	amount BIGINT NULL, -- issue
	address CHAR(32) NOT NULL,
	PRIMARY KEY (unit, message_index, input_index),
	UNIQUE  (src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
	UNIQUE  (type, from_main_chain_index, address, is_unique), -- UNIQUE guarantees there'll be no double spend for type=hc/witnessing
	UNIQUE  (asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
	FOREIGN KEY (unit) REFERENCES units(unit),
	CONSTRAINT inputsBySrcUnit FOREIGN KEY (src_unit) REFERENCES units(unit),
	CONSTRAINT inputsByAddress FOREIGN KEY (address) REFERENCES addresses(address),
	CONSTRAINT inputsByAsset FOREIGN KEY (asset) REFERENCES assets(unit)
);
CREATE INDEX inputsIndexByAddress ON inputs(address);
CREATE INDEX inputsIndexByAddressTypeToMci ON inputs(address, type, to_main_chain_index);
CREATE INDEX inputsIndexByAssetType ON inputs(asset, type);
```
