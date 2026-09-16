### Title
Archiving/removal of an uncovered unit does not delete its `aa_addresses` entry, leaving a phantom AA registration - (File: archiving.js)

### Summary
`generateQueriesToRemoveJoint()` and `generateQueriesToVoidJoint()` in `archiving.js` implement the ocore equivalent of the reported bug class: they perform a "shallow" deletion of a unit's dependent rows across dozens of tables, but never touch the `aa_addresses` table, exactly mirroring `removeCategoryGroup()` removing the top-level record while leaving dependent records (`groupToCategories`, `categorization`) behind.

### Finding Description
When a unit is archived because it turned out to be uncovered (never confirmed/stabilized) or voided (found non-serial/final-bad), `archiving.generateQueriesToArchiveJoint()` dispatches to either `generateQueriesToRemoveJoint()` or `generateQueriesToVoidJoint()`: [1](#0-0) [2](#0-1) 

Both functions carefully delete rows from `unit_authors`, `parenthoods`, `address_definition_changes`, `assets`, `asset_attestors`, `attestations`, `messages`, `polls`, etc. — an extensive, deliberate list analogous to TRSRY's `categoryGroups` bookkeeping. However, neither function issues a `DELETE FROM aa_addresses WHERE unit=?`. `aa_addresses` is populated during unit writing via `storage.insertAADefinitions()`, called from `writer.js` whenever an author's address definition is `['autonomous agent', ...]`, independent of whether the unit will ultimately become serial/stable: [3](#0-2) 

Because `aa_addresses` rows are looked up directly by address (not by joining back to a live `units`/`unit_authors` row), once the row is inserted it persists forever unless explicitly deleted — but the archiving code path that is supposed to fully undo a unit's effects never removes it. This is the same "shallow removal" pattern as the reported bug: the parent record (the unit/joint) is removed, but a dependent record (`aa_addresses`) that was created as a side effect of that unit is not removed, leaving stale/incorrect state that downstream code (AA triggering, `light/get_definition`, balance/response computation) still treats as valid.

### Impact Explanation
An address is only ever an AA address for one specific, chash-derived definition, so this cannot let two different definitions collide on the same address. But the lingering `aa_addresses` row means an AA definition that was only ever contained in a unit that got completely purged from the DAG (no longer present in `units`, `unit_authors`, `messages`, etc., and rejected/never accepted by honest peers because it was non-serial or uncovered) remains permanently "known" and triggerable on the node that had briefly accepted it. This produces node disagreement: nodes that received and then purged the bad/uncovered unit retain a functioning AA address and can execute triggers against it (composing responses, moving balances sent to that address) that other honest nodes — which never accepted that unit — do not recognize at all. That is a concrete divergence in what is considered a valid AA/response across the network, matching the required impact class of "node disagreement on validity/stability" and potential fund-handling inconsistency for anyone who sends payments to that address afterward.

### Likelihood Explanation
Medium. It requires an attacker (or naturally occurring race) to get a unit whose author definition is an AA written locally (which happens during normal `writer.saveJoint` processing before finality is known) and later have that specific unit end up archived as `uncovered` or `voided` (final-bad/non-serial) rather than becoming stable. This is a realistic, reachable path for any ordinary unit poster defining/triggering with an AA-definition author, without needing a malicious peer, node operator, or network-level attack — it only requires normal validation/archiving code paths that already exist for handling conflicting/non-serial units.

### Recommendation
Add `DELETE FROM aa_addresses WHERE unit=?` (and any dependent `aa_triggers`/`aa_responses`/AA state rows keyed by that unit or address) to both `generateQueriesToRemoveJoint()` and `generateQueriesToVoidJoint()` in `archiving.js`, mirroring the cleanup already done for `assets`, `attestations`, etc., so that purging/voiding a unit fully reverses all of its side effects, including AA address registration.

### Proof of Concept
1. Post/receive a unit `U` whose author address definition is `['autonomous agent', {...}]`. During `writer.saveJoint`, `storage.insertAADefinitions()` inserts a row into `aa_addresses` for that address (as shown in `storage.js:798-811`, AA definitions are read straight from this table).
2. `U` subsequently fails to stabilize (e.g., it is a losing unit in a non-serial battle, or it never gets enough confirmations and is purged as `uncovered`, or is voided as `final-bad`). `joint_storage`/`storage` calls into `archiving.generateQueriesToRemoveJoint()` or `generateQueriesToVoidJoint()`, which purge every table listed in `archiving.js:58-111` but never `aa_addresses`.
3. The local node still has the `aa_addresses` row for that address, even though `units`, `unit_authors`, and `messages` for `U` are gone. Any later trigger unit sent to this address will still be composed/executed by this node's `aa_composer`, while other honest nodes that never accepted `U` do not know this address as an AA at all — producing divergent handling of the same address across the network.

### Citations

**File:** archiving.js (L58-87)
```javascript
function generateQueriesToRemoveJoint(conn, unit, arrQueries, cb){
	generateQueriesToUnspendOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
		conn.addQuery(arrQueries, "DELETE FROM aa_responses WHERE trigger_unit=? OR response_unit=?", [unit, unit]);
		conn.addQuery(arrQueries, "DELETE FROM original_addresses WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM sent_mnemonics WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM witness_list_hashes WHERE witness_list_unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM earned_headers_commission_recipients WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM unit_witnesses WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM unit_authors WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM parenthoods WHERE child_unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM address_definition_changes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM inputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM outputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM spend_proofs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM poll_choices WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM polls WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM votes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attested_fields WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attestations WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_metadata WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_denominations WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_attestors WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM assets WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM messages WHERE unit=?", [unit]);
	//	conn.addQuery(arrQueries, "DELETE FROM balls WHERE unit=?", [unit]); // if it has a ball, it can't be uncovered
		conn.addQuery(arrQueries, "DELETE FROM units WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM joints WHERE unit=?", [unit]);
		cb();
	});
}
```

**File:** archiving.js (L89-111)
```javascript
function generateQueriesToVoidJoint(conn, unit, arrQueries, cb){
	generateQueriesToUnspendOutputsSpentInArchivedUnit(conn, unit, arrQueries, function(){
		// we keep witnesses, author addresses, and the unit itself
		conn.addQuery(arrQueries, "DELETE FROM witness_list_hashes WHERE witness_list_unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM earned_headers_commission_recipients WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "UPDATE unit_authors SET definition_chash=NULL WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM address_definition_changes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM inputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM outputs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM spend_proofs WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM poll_choices WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM polls WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM votes WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attested_fields WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM attestations WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_metadata WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_denominations WHERE asset=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM asset_attestors WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM assets WHERE unit=?", [unit]);
		conn.addQuery(arrQueries, "DELETE FROM messages WHERE unit=?", [unit]);
		cb();
	});
}
```

**File:** storage.js (L798-811)
```javascript
function readAADefinition(conn, address, to_mci, handleDefinition) {
	if (!handleDefinition)
		return new Promise(resolve => readAADefinition(conn, address, to_mci, (arrDefinition, unit, storage_size) => resolve({ arrDefinition, unit, storage_size })));
	if (to_mci === null || to_mci === Infinity)
		to_mci = MAX_INT32;
	conn.query("SELECT definition, unit, storage_size, mci FROM aa_addresses WHERE address=? AND mci<=?", [address, to_mci], function (rows) {
		if (rows.length !== 1)
			return handleDefinition(null);
		var arrDefinition = JSON.parse(rows[0].definition);
		if (arrDefinition[0] !== 'autonomous agent')
			throw Error("non-AA definition in AA unit");
		handleDefinition(arrDefinition, rows[0].unit, rows[0].storage_size);
	});
}
```
