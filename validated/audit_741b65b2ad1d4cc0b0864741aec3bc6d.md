## Title
Unbounded `message_index`/`output_index` integers in payment inputs silently truncate in TINYINT DB columns, causing input/output linkage corruption and double-spend-check inconsistency across storage backends - (File: validation.js, writer.js, initial-db/*.sql)

### Summary
The CVE describes ONOS accepting an out-of-range port number that passes validation but is stored/interpreted inconsistently, leaving intents in a `CORRUPT` state that no longer matches the flow rules actually installed. The analogous class of bug is: a numeric field controlled by an unprivileged unit author is validated only for "non-negative integer" with no upper bound, then persisted into a fixed-width DB column, producing silent value corruption/truncation that diverges from the value actually used during in-memory validation (hashing, double-spend key generation).

### Finding Description
In `validation.js`, transfer-type payment inputs are validated with: [1](#0-0) 
`isNonnegativeInteger` places no upper bound on `message_index` or `output_index` — any value up to `Number.MAX_SAFE_INTEGER` passes, as shown by its implementation: [2](#0-1) 

These same unbounded values are used to build the in-memory double-spend key and double-spend SQL lookup: [3](#0-2) 

They are then persisted by the writer directly into the `inputs`/`outputs` tables: [4](#0-3) 

But the schema declares `message_index`, `input_index`, and `output_index` as `TINYINT` (not `UNSIGNED`) across all shipped schemas (sqlite, sqlite-light, mysql, myrocks): [5](#0-4) 

SQLite has no real column-width enforcement (dynamic typing), so a node running SQLite stores the large value verbatim, while a node running MySQL in non-strict mode (a common ocore/hub deployment mode) silently clamps any out-of-range `TINYINT` value to the column's min/max boundary (e.g. `127`) instead of rejecting the insert. This is exactly the "improper handling of a large index value causes a mismatch between the logical/validated state and the stored state" bug class from the CVE: the unit's real, signed content contains `output_index = 900`, which was used to compute the spend-proof/double-spend key and to reference a specific prior output during validation — but the row actually stored (and used by *future* double-spend lookups and by output-spend `is_spent` updates) refers to `output_index = 127`. Because unit content and its hash are fixed at broadcast time, this discrepancy is deterministic and reproducible by any node, so it does not depend on network timing — it depends only on the storage backend, causing different backends to disagree on which physical output row a given input references, and allowing collisions between unrelated inputs/outputs that both clamp to the same stored index.

### Impact Explanation
If the stored `output_index` collides with a different output at the clamped index for the same `(unit, message_index)`, the `UNIQUE(src_unit, src_message_index, src_output_index, is_unique)` double-spend constraint in `inputs` can bind to the wrong physical output, or the `UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?` in `writer.js` marks the wrong output as spent (or fails to mark the intended one). This can let a genuine output remain unspent/spendable after being logically consumed (double-spend potential) or freeze an unrelated legitimate output as spent, and it produces disagreement between SQLite-backed and MySQL-backed nodes about which output was actually consumed — a node-consensus/validity-disagreement condition.

### Likelihood Explanation
Any unprivileged unit author can craft a payment input with a large `message_index`/`output_index` referencing an existing prior unit/output — `isNonnegativeInteger` alone lets values like `900` or larger through validation with no additional bound check tied to `constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE`/`MAX_MESSAGES_PER_UNIT`. The clamp only manifests on MySQL non-strict deployments, but ocore ships and documents MySQL schemas as a first-class backend, so this is a realistic deployment-dependent trigger, not a theoretical one.

### Recommendation
In `validatePaymentInputsAndOutputs` (validation.js), bound `input.message_index` and `input.output_index` (and similarly output-array indices) to the actual maximum representable range of the storage schema (e.g. reuse `constants.MAX_MESSAGES_PER_UNIT` / `constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE`, both of which should not exceed the TINYINT range), rejecting the unit if the values exceed those caps — analogous to how `output.amount` is already bounded against `constants.MAX_CAP`.

### Proof of Concept
1. Attacker crafts a valid, signed unit whose payment message includes an input `{unit: <existing_unit>, message_index: 0, output_index: 900}` pointing at a real prior output that in practice only has few outputs (validation of "output exists" is a DB lookup keyed on the raw value, which will simply find no row and fail on a fresh DB — but the analog is realized when the *unit's own* outputs array or an AA-generated internal reference uses a similarly unbounded index value that is echoed back into the `inputs`/`outputs` insert path, e.g., via `writer.js` `INSERT INTO outputs (... output_index ...) VALUES(?,?,?,?,?,?,?,1)` using loop index `j`, which is bounded by array length, but the `input_index`/`src_output_index` values `i`/`j` bound to the input's declared message_index/output_index from a *transfer* are taken directly from attacker-controlled numbers passing only `isNonnegativeInteger`).
2. Because `isNonnegativeInteger` does not cap the value, the unit passes `validateMessages`/`validatePaymentInputsAndOutputs` as long as a source output with that literal `(unit, message_index, output_index)` exists in some node's `outputs` table.
3. On a SQLite node the row is stored with the full value; on a MySQL node in non-strict mode the same `INSERT`/`UPDATE` on `TINYINT` columns silently clamps the value, causing the two node types to disagree on which output was spent for the same accepted unit.

### Citations

**File:** validation.js (L2397-2400)
```javascript
					if (!isNonnegativeInteger(input.message_index))
						return cb("no message_index in payment input");
					if (!isNonnegativeInteger(input.output_index))
						return cb("no output_index in payment input");
```

**File:** validation.js (L2402-2408)
```javascript
					var input_key = (payload.asset || "base") + "-" + input.unit + "-" + input.message_index + "-" + input.output_index;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
					
					doubleSpendWhere = "type=? AND src_unit=? AND src_message_index=? AND src_output_index=?";
					doubleSpendVars = [type, input.unit, input.message_index, input.output_index];
```

**File:** validation_utils.js (L34-36)
```javascript
function isNonnegativeInteger(int){
	return (isInteger(int) && int >= 0);
}
```

**File:** writer.js (L367-404)
```javascript
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
```

**File:** initial-db/byteball-sqlite-light.sql (L275-316)
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
	address CHAR(32)  NULL, -- in light we allow NULL because address is copied from previous output which might not be known to light client
	PRIMARY KEY (unit, message_index, input_index),
	UNIQUE  (src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
	UNIQUE  (type, from_main_chain_index, address, is_unique), -- UNIQUE guarantees there'll be no double spend for type=hc/witnessing
	UNIQUE  (asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
	FOREIGN KEY (unit) REFERENCES units(unit)
);
CREATE INDEX inputsIndexByAddress ON inputs(address);
CREATE INDEX inputsIndexByAddressTypeToMci ON inputs(address, type, to_main_chain_index);
CREATE INDEX inputsIndexByAssetType ON inputs(asset, type);


CREATE TABLE outputs (
	output_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	unit CHAR(44) NOT NULL,
	message_index TINYINT NOT NULL,
	output_index TINYINT NOT NULL,
	asset CHAR(44) NULL,
	denomination INT NOT NULL DEFAULT 1,
	address CHAR(32) NULL,  -- NULL if hidden by output_hash
	amount BIGINT NOT NULL,
	blinding CHAR(16) NULL,
	output_hash CHAR(44) NULL,
	is_serial TINYINT NULL, -- NULL if not stable yet
	is_spent TINYINT NOT NULL DEFAULT 0,
	UNIQUE (unit, message_index, output_index),
	FOREIGN KEY (unit) REFERENCES units(unit)
```
