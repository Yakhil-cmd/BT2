### Title
Address case-equivalence bypass via mixed-collation string comparison across storage backends - (File: `validation_utils.js`, `validation.js`, `initial-db/byteball-mysql.sql`)

### Summary
The CVE describes libgit2 accepting a filename that is textually different from, but filesystem-equivalent to, an already-checked-out path (NTFS 8.3 short names), so checkout logic treats two different strings as the same on-disk object with no validation applied to the alias. ocore has an analogous equivalence gap between **address string identity** as enforced by validation code and **address string identity** as enforced by the underlying SQL storage engine's collation, combined with a legacy case-insensitive address-validation code path that is still reachable.

### Finding Description
Ocore normally requires addresses to match the strict canonical form `/^[A-Z2-7]{32}$/` [1](#0-0) , but a legacy, purely-checksum-based validator `isValidAddressAnyCase` (only checks base32 decode + checksum, no case restriction) is still selected by `validatePaymentInputsAndOutputs` whenever the unit's `last_ball_mci` is below `constants.timestampUpgradeMci`: [2](#0-1) [3](#0-2) .

The checksum check itself in `chash.js` (`isChashValid`) only validates that the decoded checksum bytes match, and base32 decoding of a string is case-dependent in the `thirty-two` library, so a differently-cased permutation of a 32-character chash can independently decode to bytes whose checksum still validates, producing two textually distinct but chash-"equivalent" address strings [4](#0-3) .

Separately, the MySQL schema sets an explicit case-sensitive binary collation (`latin1_bin`) only for unit-hash columns (`unit`, `witness_list_unit`, `last_ball_unit`, `best_parent_unit`), while the table (and by inheritance, columns without an explicit COLLATE override, including `address` columns used throughout `addresses`, `outputs`, `inputs`, `unit_authors`, etc.) default to `utf8mb4_unicode_520_ci`, a case-insensitive collation [5](#0-4) . The SQLite schema, by contrast, compares `CHAR(32)` address columns byte-for-byte (case-sensitive) by default [6](#0-5) .

This is precisely the "equivalent name, different identity handling" bug class from the CVE: a MySQL-backed full node can match rows (unique constraints, `WHERE address=?`, `JOIN ... USING(address)`, double-spend `inputsBySrcUnit`/UNIQUE checks) for two case-different address strings that a SQLite-backed node treats as entirely distinct rows. Any consensus-critical logic that depends on address identity (definition lookup in `validateDefinition`/`handleDuplicateAddressDefinition`, double-spend uniqueness in the `inputs` table, balance aggregation, `outputsByAddressSpent`) can therefore diverge between MySQL and SQLite deployments for units validated under the legacy `isValidAddressAnyCase` path [7](#0-6) .

### Impact Explanation
If a unit author supplies a case-permuted (but checksum-valid) variant of an existing address as an output address, issuer address, or author address in a unit whose `last_ball_mci` predates `timestampUpgradeMci`, MySQL nodes may silently coalesce it with the canonical address (via case-insensitive collation) in balance/UNIQUE/definition lookups, while SQLite nodes keep it as a separate, brand-new address with no known definition. This produces node disagreement on unit validity (one engine accepts a duplicate-definition or double-spend that the other rejects, or vice versa), which is one of the accepted high-impact outcomes (network unable to reach consensus on validity/stability).

### Likelihood Explanation
Exploitation requires only posting a unit that references the historical `timestampUpgradeMci` window and includes a case-altered address string that still passes chash checksum validation — no privileged access, hub cooperation, or protocol-level trust is required, matching the "unprivileged unit poster" threat model. The practical likelihood is reduced by the fact that the legacy code path is gated to units validated against an old `last_ball_mci`, which limits it mostly to catch-up/historical-sync scenarios rather than fresh unit posting on the live tip, but heterogeneous-database networks performing initial sync or replay remain exposed.

### Recommendation
- Enforce a single canonical address string representation everywhere by rejecting any address that does not match the strict `/^[A-Z2-7]{32}$/` pattern, regardless of `last_ball_mci`, i.e., retire `isValidAddressAnyCase` from all live validation paths.
- Explicitly set a case-sensitive binary collation (e.g., `utf8mb4_bin` or `latin1_bin`) on every address-bearing column (`addresses.address`, `outputs.address`, `inputs.address`, `unit_authors.address`, etc.) in the MySQL/MyRocks schemas, matching SQLite's byte-exact comparison semantics, so that no two nodes with different storage engines can disagree on address identity.
- Add a migration to audit and normalize any historically stored non-canonical-case addresses.

### Proof of Concept
1. Identify/construct a base32 string `X` (32 chars) that decodes (case-sensitive base32) to bytes whose embedded checksum still validates under `chash.isChashValid`, and which differs only in letter case from an existing, funded address `ADDR` (e.g., lower-cased or mixed-case variant of `ADDR`).
2. Craft a unit whose `last_ball_mci` is below `constants.timestampUpgradeMci`, referencing `X` as an output address or issuer address in a payment/definition message. `validatePaymentInputsAndOutputs` will accept it via `isValidAddressAnyCase` since strict uppercase is not enforced pre-upgrade [2](#0-1) .
3. Post this unit to a network with mixed MySQL/SQLite nodes (or a mixed-storage catch-up scenario). On MySQL nodes, DB operations against `address=?` and UNIQUE indexes for `X` collide with the canonical `ADDR` row due to case-insensitive collation; SQLite nodes treat `X` as a fresh, unrelated address.
4. Observe divergent validation results (duplicate-definition rejection, double-spend detection, or balance computation) between the two node types, demonstrating node disagreement on unit validity.

### Citations

**File:** validation_utils.js (L56-58)
```javascript
function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
```

**File:** validation_utils.js (L60-62)
```javascript
function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```

**File:** validation.js (L1469-1499)
```javascript
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){ // first use of the definition_chash (in particular, of the address, when definition_chash=address)
				try {
					if (objectHash.getChash160(arrAddressDefinition) !== definition_chash)
						return callback("wrong definition: " + objectHash.getChash160(arrAddressDefinition) + "!==" + definition_chash);
				}
				catch (e) {
					return callback("definition hash failed: " + e.toString());
				}
				callback();
			},
			ifFound: function(arrAddressDefinition2){ // arrAddressDefinition2 can be different
				handleDuplicateAddressDefinition(arrAddressDefinition2);
			}
		});
	}
	
	function handleDuplicateAddressDefinition(arrAddressDefinition){
	//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
			return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
		// todo: investigate if this can split the nodes
		// in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet
		try {
			if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
				return callback("unit definition doesn't match the stored definition");
		}
		catch (e) {
			return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
		}
		callback(); // let it be for now. Eventually, at most one of the balls will be declared good
	}
```

**File:** validation.js (L2145-2145)
```javascript
	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
```

**File:** chash.js (L152-171)
```javascript
function isChashValid(encoded){
	var encoded_len = encoded.length;
	if (encoded_len !== 32 && encoded_len !== 48) // 160/5 = 32, 288/6 = 48
		throw Error("wrong encoded length: "+encoded_len);
	try{
		var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
	}
	catch(e){
		console.log(e);
		return false;
	}
	var binChash = buffer2bin(chash);
	var separated = separateIntoCleanDataAndChecksum(binChash);
	var clean_data = bin2buffer(separated.clean_data);
	//console.log("clean data", clean_data);
	var checksum = bin2buffer(separated.checksum);
	//console.log(checksum);
	//console.log(getChecksum(clean_data));
	return checksum.equals(getChecksum(clean_data));
}
```

**File:** initial-db/byteball-mysql.sql (L1-39)
```sql
CREATE TABLE units (
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL PRIMARY KEY, -- sha256 in base64
	creation_date timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	version VARCHAR(10) NOT NULL DEFAULT '1.0',
	alt VARCHAR(3) NOT NULL DEFAULT '1',
	witness_list_unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NULL,
	last_ball_unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NULL,
	timestamp INT NOT NULL DEFAULT 0,
	content_hash CHAR(44) NULL,
	headers_commission INT NOT NULL,
	payload_commission INT NOT NULL,
	oversize_fee BIGINT NULL,
	tps_fee BIGINT NULL,
	actual_tps_fee BIGINT NULL,
	burn_fee BIGINT NULL,
	max_aa_responses INT NULL,
	count_aa_responses INT NULL, -- includes responses without a response unit
	is_aa_response TINYINT NULL,
	count_primary_aa_triggers INT NULL,
	is_free TINYINT NOT NULL DEFAULT 1,
	is_on_main_chain TINYINT NOT NULL DEFAULT 0,
	main_chain_index INT NULL, -- when it first appears
	latest_included_mc_index INT NULL, -- latest MC ball that is included in this ball (excluding itself)
	level INT NULL,
	witnessed_level INT NULL,
	is_stable TINYINT NOT NULL DEFAULT 0,
	sequence ENUM('good','temp-bad','final-bad') NOT NULL DEFAULT 'good',
	best_parent_unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NULL,
	KEY byMainChain(is_on_main_chain),
	KEY byMcIndex(main_chain_index),
	KEY byLimci(latest_included_mc_index),
	KEY byLevel(level),
	KEY byFree(is_free),
	KEY byStableMci(is_stable, main_chain_index),
	KEY byDate(creation_date),
	CONSTRAINT unitsByLastBallUnit FOREIGN KEY (last_ball_unit) REFERENCES units(unit),
	FOREIGN KEY (best_parent_unit) REFERENCES units(unit),
	CONSTRAINT unitsByWitnessListUnit FOREIGN KEY (witness_list_unit) REFERENCES units(unit)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```

**File:** initial-db/byteball-sqlite.sql (L301-336)
```sql
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
	FOREIGN KEY (unit) REFERENCES units(unit),
	CONSTRAINT outputsByAsset FOREIGN KEY (asset) REFERENCES assets(unit)
);
CREATE INDEX outputsByAddressSpent ON outputs(address, is_spent);
CREATE INDEX outputsIndexByAsset ON outputs(asset);
```
