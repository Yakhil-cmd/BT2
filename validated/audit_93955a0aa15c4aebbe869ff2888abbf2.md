### Title
Attacker can DOS the MySQL/RocksDB `outputs` table (and thus new-unit confirmation) by exhausting the 32‑bit `output_id` AUTO_INCREMENT space - ([File: initial-db/byteball-mysql.sql])

### Summary
Every payment output written by `writer.js` gets a row in the `outputs` table whose primary key `output_id` is a signed 32-bit `INT AUTO_INCREMENT` (not `BIGINT`), shared globally across all assets and all units on the DAG. Any unprivileged unit poster can create outputs cheaply and repeatedly; once the counter reaches `2147483647`, every subsequent `INSERT INTO outputs` fails, which halts saving of any new unit containing a payment message — a network-wide inability to confirm new units, directly analogous to the Hats Protocol `mintTopHat()` DOS where a bounded 32-bit ID space is exhausted by a low-cost, unprivileged actor.

### Finding Description
The `outputs` table schema declares:
```sql
CREATE TABLE outputs (
	output_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	...
``` [1](#0-0) [2](#0-1) 

This column is a signed 32-bit integer, capped at `2,147,483,647`. It is incremented on every single payment output insertion performed by `writer.js` while saving any joint/unit, for both base-asset and custom-asset payments: [3](#0-2) 

Unlike the Hats protocol's `topHatId`, which is bound by an explicit domain concept, this counter has no cap check, no fee gate, and no per-user quota — it is a raw, implicit, network-wide resource consumed by ordinary payment activity. Any unprivileged unit author can create up to `MAX_OUTPUTS_PER_PAYMENT_MESSAGE` (128) outputs per payment message and up to `MAX_MESSAGES_PER_UNIT` (128) messages per unit: [4](#0-3) 

i.e., up to 16,384 output rows per single unit, at the cost of only the unit's byte-fee (there is no minimum monetary cost beyond ordinary network fees, which — as with the original report's "cheaper L2 chains" caveat — can be made economically negligible for a patient attacker, e.g. via minimal-value dust outputs or self-payments). By contrast, the `outputs` schema for SQLite (`INTEGER PRIMARY KEY AUTOINCREMENT`) is a 64-bit ROWID and is not subject to this overflow, so the vulnerability is specific to the MySQL/RocksDB backends used by hubs/witnesses/full nodes running those storage engines: [5](#0-4) 

Once the `output_id` counter is exhausted, `INSERT INTO outputs` in `writer.js` will fail for every future unit containing a payment message (i.e., essentially every economically meaningful unit), so `saveJoint()` can no longer commit new units — the node can no longer confirm new units at all, exactly the "network unable to confirm new units" impact class.

### Impact Explanation
This is a systemic denial of service: once triggered on a given node's database engine (MySQL/RocksDB), the node becomes unable to persist any new unit that includes a payment message, which is nearly every meaningful unit on the DAG. If witnesses/hubs run on the affected storage engines, this can stall network-wide confirmation of new units — matching the required "network unable to confirm new units" impact bar. There is no recovery path short of an operator manually altering the column type or truncating/renumbering the table (a redeploy/maintenance event), mirroring the Hats Protocol conclusion that recovery requires redeployment.

### Likelihood Explanation
Exploitation requires sending roughly 2.1 billion output rows, achievable via ~131,000 maximally-sized units (128 messages × 128 outputs each). This is far more expensive than the original 4-billion top-hat mint loop in gas terms, but it is entirely permissionless, requires no special privileges, no double-spend, and no exotic conditions — only sustained, low-value payment traffic (e.g., 1-byte outputs to self or many small change outputs) paid for at ordinary network fee rates over an extended campaign, consistent with the source report's premise that the attack is impractical on expensive chains but feasible where per-operation cost is low. Given ocore's byte-fee model can be made arbitrarily cheap by an attacker optimizing for minimal fee per output, sustained/patient spam over time is plausible, though the sheer volume required (billions of rows, terabytes of table growth) does impose a practical throughput/storage cost that a defender/operator would likely notice long before exhaustion — this is the main mitigating factor.

### Recommendation
Change `output_id` (and other similarly-typed global AUTO_INCREMENT identifiers, e.g. `aa_response_id`) from `INT` to `BIGINT` in `byteball-mysql.sql` and `byteball-myrocks.sql`, matching the effectively unbounded 64-bit space already used by the SQLite/ROWID backend. This closes the gap between backends and removes the reachable 32-bit exhaustion ceiling without requiring any fee/authorization redesign.

### Proof of Concept
1. Configure a node against MySQL/RocksDB storage (per `initial-db/byteball-mysql.sql` / `byteball-myrocks.sql`).
2. Repeatedly post payment units, each using the maximum allowed messages (128) and maximum outputs per message (128), i.e. up to 16,384 new `outputs` rows per unit, paying only the standard byte-fee.
3. Continue for ~131,000 such units (or more, accounting for smaller ordinary transactions in between) until the `outputs.output_id` AUTO_INCREMENT counter approaches `2,147,483,647`.
4. Observe that the next `INSERT INTO outputs` performed by `writer.js` during `saveJoint()` fails (primary-key/range violation), preventing that node from persisting any further unit containing a payment message.

### Citations

**File:** initial-db/byteball-mysql.sql (L306-309)
```sql
CREATE TABLE outputs (
	output_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	message_index TINYINT NOT NULL,
```

**File:** initial-db/byteball-myrocks.sql (L283-286)
```sql
CREATE TABLE outputs (
	output_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	message_index TINYINT NOT NULL,
```

**File:** writer.js (L145-167)
```javascript
			if (definition){
				// IGNORE for messages out of sequence
				definition_chash = objectHash.getChash160(definition);
				conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO definitions (definition_chash, definition, has_references) VALUES (?,?,?)", 
					[definition_chash, JSON.stringify(definition), Definition.hasReferences(definition) ? 1 : 0]);
				// actually inserts only when the address is first used.
				// if we change keys and later send a unit signed by new keys, the address is not inserted. 
				// Its definition_chash was updated before when we posted change-definition message.
				if (definition_chash === author.address)
					conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO addresses (address) VALUES(?)", [author.address]);
			}
			else if (objUnit.content_hash)
				conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO addresses (address) VALUES(?)", [author.address]);
			conn.addQuery(arrQueries, "INSERT INTO unit_authors (unit, address, definition_chash) VALUES(?,?,?)", 
				[objUnit.unit, author.address, definition_chash]);
			if (bGenesis)
				conn.addQuery(arrQueries, "UPDATE unit_authors SET _mci=0 WHERE unit=?", [objUnit.unit]);
		/*	if (!objUnit.content_hash){
				for (var path in author.authentifiers)
					conn.addQuery(arrQueries, "INSERT INTO authentifiers (unit, address, path, authentifier) VALUES(?,?,?,?)", 
						[objUnit.unit, author.address, path, author.authentifiers[path]]);
			}*/
		}
```

**File:** constants.js (L45-48)
```javascript
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
```

**File:** initial-db/byteball-sqlite.sql (L318-330)
```sql
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
```
