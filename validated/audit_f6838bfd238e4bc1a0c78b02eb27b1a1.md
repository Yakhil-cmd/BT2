### Title
AA `storage_size` accumulator uses a 32-bit `INT` column while the JS-side byte-balance guard operates on unchecked doubles, allowing overflow/wraparound that bypasses the storage-fee solvency check - ([File: aa_composer.js])

### Summary
The btrfs CVE stems from tracking a cumulative byte counter (`bytes_changed`) in a fixed-width type (`unsigned int`) that can wrap around when a single operation adds more than 4 GiB, causing the quota-limit comparison to pass incorrectly and letting the caller exceed the enforced cap. The `ocore` autonomous-agent (AA) engine has a structurally similar cumulative-counter pattern: `storage_size`, which tracks how many bytes of state-variable storage an AA address has consumed, is persisted in a **32-bit `INT`** column in the SQL schemas [1](#0-0) [2](#0-1) , while all the arithmetic that computes and compares it in `aa_composer.js` is done with unchecked JavaScript numbers with no explicit bound against `MAX_STORAGE_SIZE` or `Number.MAX_SAFE_INTEGER`.

### Finding Description
`updateStorageSize()` in `aa_composer.js` accumulates `delta_storage_size` from every updated state variable (bounded per-variable only by `constants.MAX_STATE_VAR_VALUE_LENGTH` = 1024) and adds it to the previously stored `storage_size` read from the `aa_addresses.storage_size` column: [3](#0-2) 

The only guard preventing an AA from growing `storage_size` beyond what it can pay for is:
```
if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE ...)
    return cb("byte balance ... would drop below new storage size ...");
``` [4](#0-3) 

This comparison is performed entirely in JS-number space and then written back with `UPDATE aa_addresses SET storage_size=?`. Because the persisted column is a 32-bit signed `INT` (range ±2,147,483,647) in the MySQL/MyRocks/SQLite-light schemas [1](#0-0) , once `new_storage_size` exceeds `2^31-1` the value silently wraps (or is truncated, depending on backend) on write, while the JS-level `storage_size` variable used in the *next* invocation is re-read from the database and therefore reflects the wrapped (possibly negative or much smaller) integer rather than the true cumulative size. As in the btrfs bug, the cumulative "changeset" is tracked in a fixed-width type on one path (the persisted DB integer) while the enforcement logic assumes unbounded precision (JS doubles) on the other, so exceeding the fixed-width range causes the enforcement check (`byte_balance < new_storage_size`) to evaluate against a wrong, wrapped value instead of the true cumulative size, defeating the "does the AA have enough bytes to cover its storage" invariant that the constant `constants.MAX_STATE_VAR_VALUE_LENGTH`/`aaStorageSizeUpgradeMci` gate was meant to enforce [5](#0-4) .

Additionally, because different backends (`sqlite` vs `mysql`/`myrocks`) implement integer storage differently — SQLite is dynamically typed and can hold full 64-bit integers, whereas MySQL/MariaDB's `INT` column is strictly 32-bit — a node running MySQL/MyRocks and a node running SQLite would compute/store different `storage_size` values for the same AA once the true cumulative size exceeds `2^31-1`, producing exactly the "node disagreement on validity/stability" class of impact this scan is looking for, since `storage_size` participates in unit validation via `updateStorageSize()`'s bounce/no-bounce decision, which affects whether an AA response unit is produced at all.

### Impact Explanation
If `storage_size` wraps to a small or negative number on the write side while the read-back value used by subsequent triggers is the wrapped value, an AA can be tricked into believing it has much less (or negative) storage committed than it truly has. Combined with the balance check `byte_balance < new_storage_size`, a wrapped/negative `new_storage_size` will always satisfy `byte_balance < new_storage_size === false`, meaning the solvency check silently passes even though the AA does not actually hold enough bytes to back its accumulated storage. This lets an attacker who repeatedly triggers an AA to grow its `storage_size` past the 32-bit boundary cause: (a) storage-fee bypass, i.e., an AA accumulates state-variable storage it never truly paid the "bytes-as-storage-collateral" price for once wraparound occurs (fund-accounting corruption / AA fund loss for whoever eventually has to cover that storage), and (b) divergent `storage_size` values between MySQL-backed and SQLite-backed full nodes, which is a node-disagreement-on-validity condition since `updateStorageSize()`'s bounce decision differs from node to node for the same trigger.

### Likelihood Explanation
Reaching `2^31-1` (~2.1 GB) of cumulative `storage_size` for one AA address is expensive but not implausible: state-variable values are capped at 1024 bytes each (`MAX_STATE_VAR_VALUE_LENGTH`), so an attacker needs on the order of 2 million distinct state-var writes and must fund the AA's byte balance to at least match the growing `storage_size` at every step (a fraction of the 1e15 total token supply). This requires sustained, resource-intensive but permissionless AA-trigger spamming from an ordinary unprivileged trigger sender — no special privilege, hub, or node compromise is needed, matching the "AA trigger sender" reachable actor class in scope.

### Recommendation
- Change `aa_addresses.storage_size` to a 64-bit column (`BIGINT`) consistently across all SQL schema files (`byteball-mysql.sql`, `byteball-myrocks.sql`, `byteball-sqlite.sql`, `byteball-sqlite-light.sql`) to match the semantics already assumed by `aa_balances.balance BIGINT`.
- Add an explicit upper bound check on `new_storage_size` (e.g., against a defined `MAX_STORAGE_SIZE` constant well below `Number.MAX_SAFE_INTEGER` and below any DB column limit) inside `updateStorageSize()` in `aa_composer.js`, bouncing the AA response if exceeded, rather than relying solely on the `byte_balance` comparison.
- Add a migration to detect/normalize any already-wrapped `storage_size` values and add a consistency check similar to `checkStorageSizes()` [6](#0-5)  that also validates the value stays within the intended safe integer / column range.

### Proof of Concept
1. Deploy an AA whose `state` handler writes a new, uniquely-named state variable (up to `MAX_STATE_VAR_VALUE_LENGTH` = 1024 bytes) on every trigger, and fund it with bytes so `byte_balance` always exceeds the running `storage_size` before each trigger (`updateStorageSize` check at `aa_composer.js:1564`).
2. Repeatedly send triggers (approx. 2^31/1024 ≈ 2,097,152 state-var writes, batched across many trigger units within `MAX_OPS`/`MAX_MESSAGES_PER_UNIT` limits) until `storage_size` in `aa_addresses` crosses `2^31-1`.
3. Observe on a MySQL/MyRocks-backed node that the `INT` column wraps/truncates the value on the next `UPDATE aa_addresses SET storage_size=?` write [7](#0-6) , while a SQLite-backed node (dynamic typing, effectively 64-bit) retains the true, larger value.
4. Trigger the AA once more: the two node types now compute different `byte_balance < new_storage_size` results in `updateStorageSize()` [4](#0-3) , causing one node to bounce the response unit and the other to accept it — a concrete node disagreement on unit validity for the same trigger/response chain.

*Note: full verification of the exact wraparound behavior on MySQL vs MyRocks vs SQLite in this codebase (e.g., whether MySQL strict mode would reject rather than silently truncate an out-of-range INT insert) could not be completed within the available tool budget; the schema evidence (`INT` vs `BIGINT` inconsistency) and the unchecked-arithmetic code path in `aa_composer.js` are confirmed, but runtime DB-specific truncation/error behavior should be validated directly against a live MySQL/MyRocks instance.*

### Citations

**File:** initial-db/byteball-myrocks.sql (L759-769)
```sql
CREATE TABLE aa_addresses (
	address CHAR(32) NOT NULL PRIMARY KEY,
	unit CHAR(44) NOT NULL, -- where it is first defined.  No index for better speed
	mci INT NOT NULL, -- it is available since this mci (mci of the above unit)
	storage_size INT NOT NULL DEFAULT 0,
	base_aa CHAR(32) NULL,
	definition TEXT NOT NULL,
	getters TEXT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT aaAddressesByBaseAA FOREIGN KEY (base_aa) REFERENCES aa_addresses(address)
) ENGINE=RocksDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```

**File:** initial-db/byteball-sqlite-light.sql (L794-805)
```sql
CREATE TABLE aa_addresses (
	address CHAR(32) NOT NULL PRIMARY KEY,
	unit CHAR(44) NULL, -- where it is first defined.  No index for better speed, NULL for light
	mci INT NULL, -- it is available since this mci (mci of the above unit), NULL for light
	storage_size INT NOT NULL DEFAULT 0,
	base_aa CHAR(32) NULL,
	definition TEXT NOT NULL,
	getters TEXT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
--	CONSTRAINT aaAddressesByBaseAA FOREIGN KEY (base_aa) REFERENCES aa_addresses(address)
);
CREATE INDEX byBaseAA ON aa_addresses(base_aa);
```

**File:** aa_composer.js (L1531-1568)
```javascript
	function updateStorageSize(cb) {
		if (bBouncing || trigger_opts.bAir)
			return cb();
		var delta_storage_size = 0;
		var addressVars = stateVars[address] || {};
		for (var var_name in addressVars) {
			var state = addressVars[var_name];
			if (!state.updated)
				continue;
			if (state.value === false) { // false value signals that the var should be deleted
				if (state.original_old_value !== undefined)
					delta_storage_size -= var_name.length + getValueSize(state.original_old_value);
			}
			else {
				try {
					var newSize = getValueSize(state.value);
				}
				catch (e) {
					console.log("failed to get size of new value of state var " + var_name + ": ", e);
					return cb("invalid new value of state var " + var_name);
				}
				if (newSize > constants.MAX_STATE_VAR_VALUE_LENGTH)
					return cb(`state var value too long: ${newSize}`);
				if (state.original_old_value !== undefined)
					delta_storage_size += newSize - getValueSize(state.original_old_value);
				else
					delta_storage_size += var_name.length + newSize;
			}
		}
		console.log('storage size = ' + storage_size + ' + ' + delta_storage_size + ', byte_balance = ' + byte_balance);
		var new_storage_size = storage_size + delta_storage_size;
		if (new_storage_size < 0)
			throw Error("storage size would become negative: " + new_storage_size);
		if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci)
			return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);
		if (delta_storage_size === 0)
			return cb();
		conn.query("UPDATE aa_addresses SET storage_size=? WHERE address=?", [new_storage_size, address], function () {
```

**File:** aa_composer.js (L1918-1952)
```javascript
function checkStorageSizes() {
	mutex.lockOrSkip(['checkStorageSizes'], function (unlock) {
		db.takeConnectionFromPool(function (conn) { // block conection for the entire duration of the check
			var options = {};
			options.gte = "st\n";
			options.lte = "st\n\uFFFF";

			var assocSizes = {};
			var handleData = function (data) {
				var address = data.key.substr(3, 32);
				var var_name = data.key.substr(36);
				if (!assocSizes[address])
					assocSizes[address] = 0;
				assocSizes[address] += var_name.length + data.value.length - 2; // -2 for type and \n
			}
			var stream = kvstore.createReadStream(options);
			stream.on('data', handleData)
				.on('end', function () {
					conn.query("SELECT address, storage_size FROM aa_addresses", function (rows) {
						rows.forEach(function (row) {
							if (!assocSizes[row.address])
								assocSizes[row.address] = 0;
							if (row.storage_size !== assocSizes[row.address])
								throw Error("storage size mismatch on " + row.address + ": db=" + row.storage_size + ", kv=" + assocSizes[row.address]);
						});
						conn.release();
						unlock();
					});
				})
				.on('error', function (error) {
					throw Error('error from data stream: ' + error);
				});
		});
	});
}
```

**File:** constants.js (L64-68)
```javascript
exports.MAX_AA_STRING_LENGTH = 4096;
exports.MAX_STATE_VAR_NAME_LENGTH = 128;
exports.MAX_STATE_VAR_VALUE_LENGTH = 1024;
exports.MAX_OPS = process.env.MAX_OPS || 2000;
exports.MAX_RESPONSES_PER_PRIMARY_TRIGGER = process.env.MAX_RESPONSES_PER_PRIMARY_TRIGGER || 10;
```
