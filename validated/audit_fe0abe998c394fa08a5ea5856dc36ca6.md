### Title
Case/accent-insensitive MySQL collation on `attested_fields.field` allows attestation-field confusion in oscript `attestation[[...]]` lookups - (File: formula/evaluation.js)

### Summary
The Directus advisory (GHSA-qw9g-7549-7wg5 / CVE-2024-27295) is a case study of a database-level accent/case-insensitive comparison being relied upon where the application logic assumes an exact, byte-for-byte identity match. In ocore, the `attested_fields` table's `field` and `value` columns are declared without any explicit `COLLATE`/`BINARY` qualifier in `initial-db/byteball-mysql.sql`, so they inherit the database's default collation `utf8mb4_unicode_520_ci`, which is applied via the mysql driver connection charset `UTF8MB4_UNICODE_520_CI` set in `db.js`. This collation is both case-insensitive and accent-insensitive.

### Finding Description
`attested_fields` is defined as: [1](#0-0) 
with no `COLLATE ... _bin` override, unlike other sensitive columns in the same schema (e.g. `data_feeds.feed_name`/`value` explicitly use `COLLATE utf8mb4_bin`): [2](#0-1) 

The connection-level charset that governs the default collation for unqualified columns is set globally: [3](#0-2) 

The oscript `attestation[[...]]` formula, reachable from any AA definition (and, if the field name is built from `trigger.data`, indirectly influenced by an unprivileged trigger sender), builds the SQL field filter with a simple `conn.escape(field)` equality comparison and no collation override: [4](#0-3) [5](#0-4) 

Because the comparison runs under `utf8mb4_unicode_520_ci`, a `field` value such as `"émail"`, `"EMAIL"`, or a value containing homoglyphs/accented characters can match a stored row whose `field` is `"email"` (or vice-versa), even though the two strings are not identical. The same weak collation applies to the `value` column that is then read back and used inside AA logic (`returnValue`), and to `attestations`/`attested_fields.address` where they are not qualified with `BINARY`/`_bin` collate in the MySQL schema, in contrast to the RocksDB (`byteball-myrocks.sql`) schema which explicitly marks these columns `BINARY`: [6](#0-5) 

This is exactly the bug class in the Directus advisory: SQL performs a "weak"/collation-driven equality check where the application (here, an AA's oscript logic) assumes strict identity between the queried string and the stored string.

### Impact Explanation
AAs commonly gate fund release, KYC-style authorization, or asset-transfer permissions on `attestation[[attestors=..., address=..., ]].<field>` lookups (see `test/formula.test.js:1235-1301` for typical usage patterns). If an attestor (or a party able to influence which field name is queried, e.g. via `trigger.data` used dynamically as the field selector) posts an attestation using a homoglyph/accented/differently-cased field name, the AA's fixed-string field lookup can be silently satisfied by an unintended row, or an unintended row can shadow/mask the intended one. Depending on how the AA is written, this can lead to unauthorized release of AA funds, bypass of `spender_attested` restrictions on private assets, or incorrect KYC-style gating - i.e., concrete AA fund loss/incorrect authorization, which meets the required High severity bar for this program.

### Likelihood Explanation
Exploitation requires: (1) an entity able to post attestation messages with attacker-chosen `field` strings (any unit author can post an `attestation` message for their own address, and any attestor referenced by an AA condition can pick arbitrary field names), and (2) an AA design that performs a field-name-gated authorization check via `attestation[[...]].field`. This is a narrower, design-dependent condition (medium-likelihood) rather than a universal, always-triggered bug, since it depends on the specific AA's use of attestation lookups and on whether field names are attacker-influenceable or attacker-known ahead of time. However, given how common attestation-gated AA patterns are (KYC/verification bots), the reachable surface is non-trivial.

### Recommendation
Explicitly declare `COLLATE utf8mb4_bin` (or `BINARY`) for `attested_fields.field`, `attested_fields.value`, and `attestations`/`attested_fields.address` in `initial-db/byteball-mysql.sql`, mirroring the treatment already given to `data_feeds.feed_name`/`value` and to the RocksDB schema's `BINARY` address columns. Alternatively/additionally, force a binary-safe comparison at the query level in `formula/evaluation.js` (e.g. `AND field = CONVERT(? USING utf8mb4) COLLATE utf8mb4_bin`) so that oscript-level string equality for attestation lookups is not silently weakened by the connection's default collation, regardless of future schema changes.

### Proof of Concept
1. Attestor `A` posts `attestation[[address: X, profile: {email: "victim@correct.value"}]]`.
2. A second (malicious or careless) attestation is posted for address `Y` using a visually/character-set-different field name that MySQL's `utf8mb4_unicode_520_ci` collation treats as equal to `"email"` (e.g., a field name containing a combining diacritic or a Unicode homoglyph that collates identically to `e`, `m`, `a`, `i`, `l`).
3. An AA whose logic is `attestation[[attestors=A, address=trigger.address]].email` is triggered for address `Y`; the SQL `WHERE ... AND field = <escaped attacker field>` matches the row intended for the distinct field name due to accent/case folding, returning the attacker-controlled `value` instead of failing the lookup.
4. If the AA conditions fund release or bypass of an attestation-based restriction on the returned value, the attacker obtains unauthorized behavior from the AA.

Note: full confirmation that MySQL's `utf8mb4_unicode_520_ci` collation folds the *specific* homoglyph/diacritic pair used in a real exploit, and identification of a concrete shipped AA template that uses attacker-influenceable field names, could not be verified further within the available tooling/time; this PoC describes the mechanism validated by the schema and code paths cited above.

### Citations

**File:** initial-db/byteball-mysql.sql (L185-196)
```sql
CREATE TABLE data_feeds (
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	message_index TINYINT NOT NULL,
	feed_name VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
	-- type ENUM('string', 'number') NOT NULL,
	`value` VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
	`int_value` BIGINT NULL,
	PRIMARY KEY (unit, feed_name),
	KEY byNameStringValue(feed_name, `value`),
	KEY byNameIntValue(feed_name, `int_value`),
	FOREIGN KEY (unit) REFERENCES units(unit)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```

**File:** initial-db/byteball-mysql.sql (L731-743)
```sql
CREATE TABLE attested_fields (
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	message_index TINYINT NOT NULL,
	attestor_address CHAR(32) NOT NULL,
	address CHAR(32) NOT NULL,
	`field` VARCHAR(50) NOT NULL,
	`value` VARCHAR(100) NOT NULL,
	PRIMARY KEY (unit, message_index, `field`),
	CONSTRAINT attestedFieldsByAttestorAddress FOREIGN KEY (attestor_address) REFERENCES addresses(address),
	FOREIGN KEY (unit) REFERENCES units(unit)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
CREATE INDEX attestedFieldsByAttestorFieldValue ON attested_fields(attestor_address, `field`, `value`);
CREATE INDEX attestedFieldsByAddressField ON attested_fields(address, `field`);
```

**File:** db.js (L8-17)
```javascript
	var pool  = mysql.createPool({
	//var pool  = mysql.createConnection({
		connectionLimit : conf.database.max_connections,
		timezone: 'Z',
		host     : conf.database.host,
		user     : conf.database.user,
		password : conf.database.password,
		charset  : 'UTF8MB4_UNICODE_520_CI', // https://github.com/mysqljs/mysql/blob/master/lib/protocol/constants/charsets.js
		database : conf.database.name
	});
```

**File:** formula/evaluation.js (L944-951)
```javascript
							else {
								field = evaluated_field;
								if (typeof field !== 'string' || field.length === 0)
									return setFatalError('bad evaluated field: ' + field, { arr }, false, cb);
								table = 'attested_fields';
								and_field = "AND field = " + conn.escape(field);
								selected_fields = 'value';
							}
```

**File:** formula/evaluation.js (L966-994)
```javascript
							// first look for attestations in the recent unstable AA units
							conn.query(
								"SELECT " + selected_fields + " \n\
								FROM "+ table +" \n\
								CROSS JOIN units USING(unit) \n\
								CROSS JOIN unit_authors USING(unit) \n\
								CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
								WHERE attestor_address IN(" + arrAttestorAddresses.map(conn.escape).join(', ') + ") \n\
									AND "+ table + ".address = ? " + and_field +" \n\
									AND (main_chain_index > ? OR main_chain_index IS NULL) \n\
								ORDER BY latest_included_mc_index DESC, level DESC, units.unit, message_index LIMIT ?",
								[params.address.value, mci, (ifseveral === 'abort') ? 2 : 1],
								function (rows) {
									if (!bAA)
										rows = []; // discard any results
									count_rows += rows.length;
									if (count_rows > 1 && ifseveral === 'abort')
										return setFatalError("several attestations found for " + params.address.value, { arr }, false, cb);
									if (rows.length > 0 && ifseveral !== 'abort') // if found but ifseveral=abort, we continue
										return returnValue(rows);
									// then check the stable units
									const or_null_mci = conf.bLight ? 'OR main_chain_index IS NULL' : '';
									conn.query(
										"SELECT "+selected_fields+" FROM "+table+" CROSS JOIN units USING(unit) \n\
										WHERE attestor_address IN(" + arrAttestorAddresses.map(conn.escape).join(', ') + ") \n\
											AND address = ? "+and_field+" AND (main_chain_index <= ? " + or_null_mci + ") AND +sequence='good' \n\
										ORDER BY main_chain_index DESC, latest_included_mc_index DESC, level DESC, unit, message_index LIMIT ?",
										[params.address.value, mci, (ifseveral === 'abort') ? 2 : 1],
										function (rows) {
```

**File:** initial-db/byteball-myrocks.sql (L208-217)
```sql
CREATE TABLE attestations (
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	message_index TINYINT NOT NULL,
	attestor_address CHAR(32) BINARY NOT NULL,
	address CHAR(32) BINARY NOT NULL,
	-- name VARCHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	PRIMARY KEY (unit, message_index),
	KEY byAddress(address),
	KEY (attestor_address)
) ENGINE=RocksDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```
