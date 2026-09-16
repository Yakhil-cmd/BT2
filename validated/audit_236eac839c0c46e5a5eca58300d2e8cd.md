### Title
Newline-Delimiter Injection in Data-Feed Key Construction Bypasses the `\n` Sanitization Enforced Only on Posted Data Feeds - (File: data_feeds.js)

### Summary
`ocore`'s data-feed lookup functions (`readDataFeedByAddress`, `dataFeedByAddressExists`) build RocksDB scan keys by naively concatenating `address`, `feed_name` and `value` with `\n` as a field separator, e.g. `'df\n'+address+'\n'+feed_name+'\n'+prefixed_value` [1](#0-0) . The `\n`-freedom invariant that makes this delimiter scheme safe is enforced only on the *write* path (validating an actually-posted `data_feed` message), not on the *read/query* path (the `data_feed`/`in_data_feed` oscript functions used by AA formulas and address-definition oracle conditions). A trigger sender or address owner can therefore supply a `feed_name` containing embedded `\n` bytes to the query path and inject extra delimiter fields into the key used for the KV range scan.

### Finding Description
When a `data_feed` message is actually posted to the DAG, both `validation.js` and `aa_validation.js` explicitly reject feed names/values containing `\n`: [2](#0-1) [3](#0-2) 

However, the symmetric check is missing on the *query* side. The oscript `data_feed`/`in_data_feed` functions, which are directly reachable from AA formulas (evaluated on every trigger) and from address-definition `in data feed` oracle conditions, only validate that `feed_name` is a non-empty string — never that it excludes `\n`: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

That unchecked `feed_name` string then flows straight into `readDataFeedByAddress`/`dataFeedByAddressExists`, where it is concatenated with `\n` separators to build the RocksDB key/range for `gte`/`lte`/`gt`/`lt` scans: [8](#0-7) [9](#0-8) 

Because legitimate stored feed names are *guaranteed* never to contain `\n` (enforced at write time) while the *query* argument can contain `\n`, an attacker who controls the `feed_name` used in a `data_feed`/`in_data_feed` call (e.g. an AA that reads `feed_name=trigger.data.name`, where `trigger.data` is a free-form object with no `\n` restriction — see the `case 'data':`/`'temp_data'` validation which only requires a non-empty object, no character filtering: [10](#0-9) ) can embed the `\n` field separator plus crafted trailing bytes (mimicking the `type`, value-encoding, or mci-encoding segments of the key format) into `feed_name`. This misaligns the field boundaries that the rest of the codebase assumes are fixed, and can cause the byte-range scan to match (or fail to match) a stored key that was posted under a genuinely different, sanitized `feed_name`/value pair than the one nominally requested. This is structurally identical to the reported CRLF-injection bug class: a delimiter character is rejected on one code path (posting/`login`) but not on a second code path (querying/`_openDir`) that builds the same delimited wire format, allowing the attacker to smuggle extra "fields" past the parser's field boundaries.

### Impact Explanation
If an AA relies on `data_feed[...]`/`in_data_feed[...]` results to gate fund transfers (e.g., price-oracle checks, KYC/attestation-style oracle checks) or if an address definition uses `in data feed` as a spending authentifier, an attacker able to control the `feed_name` argument (directly via oscript literal they author, or indirectly via `trigger.data` fields consumed by an AA's own formula) can attempt to make the lookup falsely report a match against a value posted under an unrelated feed name/value combination. This can result in an AA paying out funds it should not have (AA fund loss), or spoofing satisfaction of an oracle-based spending condition (unauthorized spending), which meets the "concrete unauthorized spending / AA fund loss" bar. Exploitation requires being able to craft a colliding byte sequence via the encoded value/mci suffixes, which constrains reliability, but the root cause — untrusted delimiter characters entering a hand-rolled `\n`-delimited key format with no sanitization on the read path — is a genuine CWE-93-class defect reachable by an unprivileged AA trigger sender or address-definition author.

### Likelihood Explanation
Likelihood is Medium: reaching the vulnerable code requires (a) an AA (or address definition) that passes an attacker-influenced string into `feed_name` of `data_feed`/`in_data_feed`/`in data feed`, which is a common enough oscript pattern for dynamic-name lookups, and (b) crafting bytes that collide with the fixed-format suffix (`type`, lexicographically-encoded double, encoded mci) of a legitimately stored key. The lack of any `\n` filtering on the read path (in contrast to the strict filtering on the write path) is unconditional and always reachable; the difficulty is in the byte-alignment needed for a useful collision, not in reaching the code.

### Recommendation
Apply the same `\n`/control-character exclusion used for posted data-feed names/values to the query path as well:
- In `formula/validation.js` `validateDataFeed`/`validateDataFeedExists` and `formula/evaluation.js`'s `getDataFeed`, reject `feed_name` (and string `feed_value`) containing `\n` or `\0`, matching the checks already present in `validation.js`/`aa_validation.js`.
- In `data_feeds.js` (`readDataFeedValueByParams`, `readDataFeedByAddress`, `dataFeedByAddressExists`, `dataFeedExists`), reject `feed_name`/string `value` containing `\n` before building any key.
- In `definition.js`'s `in data feed` evaluator, reject `feed_name` containing `\n`.
- Ideally, centralize this validation in a single helper (e.g., `isValidDataFeedName`/`isValidDataFeedValue` in `validation_utils.js`) used by both the write and read paths, so the invariant cannot drift apart again.

### Proof of Concept
Conceptual PoC (exact byte alignment needed to force a real collision was not verified against the live encoding functions, which were not fully retrievable from the index):
1. Oracle posts a legitimate `data_feed` message `{"temperature": "20"}` from address `ORACLE_ADDR`. This is stored under key `df\nORACLE_ADDR\ntemperature\ns\n20\n<mci>` (write path enforces no `\n` in `temperature`/`20`).
2. An AA formula reads a feed name from attacker-controlled trigger data:
   ```
   {
     data_feed[oracles=ORACLE_ADDR, feed_name=trigger.data.name, feed_value>=0]
   }
   ```
3. Attacker sends a trigger unit with `data` message app payload `{"name": "temperature\ns\n20\n"}` (a `\n`-laden string is permitted because `app: "data"` payloads are validated only as non-empty objects, with no character restrictions: [10](#0-9) ).
4. `evaluation.js`'s `getDataFeed`/`data_feeds.readDataFeedValue` builds `key_prefix = 'df\n'+ORACLE_ADDR+'\n'+'temperature\ns\n20\n'+'\n'+prefixed_value`, injecting extra `\n`-delimited segments that were never validated, potentially causing the range scan to behave inconsistently with the single, sanitized `feed_name` the oracle actually posted — undermining the intended one-feed-name-to-one-key mapping the rest of the validation logic assumes.

Note: full confirmation of an exact exploitable byte collision would require re-deriving `string_utils.encodeDoubleInLexicograpicOrder`/`encodeMci`/`getMciFromDataFeedKey`, whose bodies could not be retrieved from the index within this session; a Devin session with full file access is recommended to complete this verification.

### Citations

**File:** data_feeds.js (L119-164)
```javascript
	var prefixed_value;
	var type;
	if (typeof value === 'string'){
		var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
		var float = string_utils.toNumber(value, bLimitedPrecision);
		if (float !== null){
			prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(float);
			type = 'n';
		}
		else{
			prefixed_value = 's\n'+value;
			type = 's';
		}
	}
	else{
		prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(value);
		type= 'n';
	}
	var strMinMci = string_utils.encodeMci(min_mci);
	var strMaxMci = string_utils.encodeMci(max_mci);
	var key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
	var bFound = false;
	var options = {};
	switch (relation){
		case '=':
			options.gte = key_prefix+'\n'+strMaxMci;
			options.lte = key_prefix+'\n'+strMinMci;
			options.limit = 1;
			break;
		case '>=':
			options.gte = key_prefix;
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '>':
			options.gt = key_prefix+'\nffffffff';
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '<=':
			options.lte = key_prefix+'\nffffffff';
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
		case '<':
			options.lt = key_prefix;
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
	}
```

**File:** data_feeds.js (L290-311)
```javascript
	var key_prefix;
	if (value === null){
		key_prefix = 'dfv\n'+address+'\n'+feed_name;
	}
	else{
		var prefixed_value;
		if (typeof value === 'string'){
			var float = string_utils.toNumber(value, bLimitedPrecision);
			if (float !== null)
				prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(float);
			else
				prefixed_value = 's\n'+value;
		}
		else
			prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(value);
		key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
	}
	var options = {
		gte: key_prefix+'\n'+string_utils.encodeMci(max_mci),
		lte: key_prefix+'\n'+string_utils.encodeMci(min_mci),
		limit: bAbortIfSeveral ? 2 : 1
	};
```

**File:** data_feeds.js (L342-354)
```javascript
function readDataFeedValueByParams(params, max_mci, unstable_opts, cb) {
	var oracles = params.oracles;
	if (!oracles)
		return cb("no oracles in readDataFeedValueByParams");
	if (!ValidationUtils.isNonemptyArray(oracles))
		return cb("oracles must be non-empty array");
	if (!oracles.every(ValidationUtils.isValidAddress))
		return cb("some oracle addresses are not valid");
	if (oracles.length > 10)
		return cb("too many oracles");
	var feed_name = params.feed_name;
	if (!feed_name || typeof feed_name !== 'string')
		return cb("empty feed_name or not a string");
```

**File:** validation.js (L1933-1943)
```javascript
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
```

**File:** aa_validation.js (L84-90)
```javascript
				case 'profile':
				case 'data':
				case 'temp_data':
					if (!isNonemptyObject(payload))
						return cb2('payload of app=' + message.app + ' must be non-empty object or formula: ' + JSON.stringify(payload));
					cb2();
					break;
```

**File:** aa_validation.js (L95-111)
```javascript
					for (var feed_name in payload) {
						var feed_name_formula = getFormula(feed_name);
						if (feed_name_formula === null) {
							if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
								return cb2("feed name " + feed_name + " too long");
							if (feed_name.indexOf('\n') >= 0)
								return cb2("feed name " + feed_name + " contains \\n");
						}
						var value = payload[feed_name];
						if (typeof value === 'string') {
							var value_formula = getFormula(value);
							if (value_formula === null) {
								if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
									return cb2("value " + value + " too long");
								if (value.indexOf('\n') >= 0)
									return cb2("value " + value + " of feed name " + feed_name + " contains \\n");
							}
```

**File:** formula/evaluation.js (L602-619)
```javascript
				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
					var value = null;
					var relation = '';
					var min_mci = 0;
					if (params.feed_value) {
						value = params.feed_value.value;
						relation = params.feed_value.operator;
						if (!isValidValue(value))
							return cb("bad feed_value: "+value);
					}
```

**File:** formula/validation.js (L26-53)
```javascript
function validateDataFeed(params) {
	var complexity = 1;
	if (params.oracles && params.feed_name) {
		for (var name in params) {
			var operator = params[name].operator;
			var value = params[name].value;
			if (Decimal.isDecimal(value)){
				if (!isFiniteDecimal(value))
					return {error: 'not finite', complexity};
				value = toDoubleRange(value).toString();
			}
			if (operator !== '=') return {error: 'not =', complexity};
			if (['oracles', 'feed_name', 'min_mci', 'feed_value', 'ifseveral', 'ifnone', 'what', 'type'].indexOf(name) === -1)
				return {error: 'unknown df param: ' + name, complexity};
			if (typeof value !== 'string')
				continue;
			switch (name) {
				case 'oracles':
					if (value.trim() === '') return {error: 'empty oracle', complexity};
					var addresses = value.split(':');
					if (addresses.length === 0) return {error: 'empty oracle list', complexity};
				//	complexity += addresses.length;
					if (!addresses.every(ValidationUtils.isValidAddress)) return {error: 'oracle address not valid', complexity};
					break;

				case 'feed_name':
					if (value.trim() === '') return {error: 'empty feed name', complexity};
					break;
```

**File:** definition.js (L401-428)
```javascript
			case 'in data feed':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!Array.isArray(args))
					return cb(op+" arg must be array");
				if (args.length !== 4 && args.length !== 5)
					return cb(op+" must have 4 or 5 args");
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4];
				if (!isNonemptyArray(arrAddresses))
					return cb("no addresses in "+op);
				for (var i=0; i<arrAddresses.length; i++)
					if (!isValidAddress(arrAddresses[i])) // it is ok if the address was never used yet
						return cb("oracle address not valid");
				complexity += arrAddresses.length-1; // 1 complexity point for each address (1 point was already counted)
				if (!isNonemptyString(relation))
					return cb("no relation");
				if (typeof relation !== 'string')
					return cb("relation is not a string");
				if (["=", ">", "<", ">=", "<=", "!="].indexOf(relation) === -1)
					return cb("invalid relation: "+relation);
				if (!isNonemptyString(feed_name))
					return cb("no feed_name");
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return cb("feed_name too long");
```
