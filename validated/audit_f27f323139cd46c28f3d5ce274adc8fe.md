### Title
Data-feed key-injection via unescaped `\n` in AA formula `feed_name`/`value` parameters bypasses mci bounds and feed isolation - ([File: data_feeds.js])

### Summary
`dataFeedByAddressExists()` and `readDataFeedByAddress()` in `data_feeds.js` build raw LevelDB range-query keys by string-concatenating attacker-influenced `feed_name` and `value` (from an AA trigger's `data_feed[[...]]` / `in data feed` formula lookups) directly into the key with `\n` as the field delimiter, without ever validating that these values are free of `\n`. This mirrors the Roundcube LDAP bug class (unescaped substitution of user data into a structured filter/key), letting a trigger author "escape" the intended `address`/`feed_name`/`value` field boundaries of the key and manipulate the shape of the constructed range query.

### Finding Description
Data feeds are looked up via oscript formula constructs such as `data_feed[[oracles=..., feed_name=..., feed_value=...]]` and `in data feed` (definition.js `'in data feed'`, formula/evaluation.js `getDataFeed`). The `feed_name` and `feed_value` values passed to these constructs can be arbitrary formula expressions, including values taken from `trigger.data`, which is fully controlled by whoever posts the trigger unit to an AA (an unprivileged unit poster).

These values flow into `data_feeds.js`: [1](#0-0) 
and [2](#0-1) 

Here `key_prefix` (and the `gte`/`lte` range bounds derived from it) is built as `'df\n'+address+'\n'+feed_name+'\n'+prefixed_value` or `'dfv\n'+address+'\n'+feed_name`, purely by string concatenation with `\n` as the field separator — the exact same separator used elsewhere throughout the codebase as the canonical delimiter for this key schema (see the on-disk write side in `main_chain.js`, which uses the identical `'df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci` / `'dfv\n'+address+'\n'+feed_name+'\n'+strMci` format): [3](#0-2) 

Crucially, when a *unit's own* `data_feed` message is validated, the codebase explicitly rejects `\n` in `feed_name`/string `value` for exactly this reason (to preserve key-schema integrity): [4](#0-3) 
and the AA-definition-time validator for `data_feed` messages does the same: [5](#0-4) 

However, **no equivalent check exists on the read/query side** for `feed_name` (or the derived `s\n`-typed string `value`) used by `data_feed[[...]]`/`in data feed` formula lookups: [6](#0-5) [7](#0-6) [8](#0-7) 

Because `feed_name`/`value` here can originate from `trigger.data` (attacker-controlled) and is never checked for embedded `\n`, an AA trigger sender can inject `\n`-delimited fragments into the constructed LevelDB key/range boundaries. This is analogous to the CVE's unescaped `%u`/`%fu`/`%d` substitution into an LDAP filter: the attacker's string is supposed to occupy a single logical "field" of the query but instead can inject additional field boundaries, changing which underlying key range is actually matched (`\n` playing the role of the LDAP metacharacter). Concretely this can be leveraged to append a specific `type\nvalue\nreversed_mci` suffix inside what should be the isolated `feed_name` field, letting the query directly target — and thus be satisfied by, or fail against — a specific stored key regardless of the true `min_mci`/`max_mci` bounds normally enforced by the surrounding `gte`/`lte` options, or regardless of the real posted `feed_name`.

### Impact Explanation
Data feeds/oracles are commonly used inside AAs to gate fund releases, price-based settlements, and other consensus-critical decisions. If a trigger sender can craft `feed_name`/`value` strings that manipulate the LevelDB key-range boundaries used by `dataFeedByAddressExists`/`readDataFeedByAddress`, they can:
- Cause the “in data feed”/`data_feed[[...]]` construct to match (or fail to match) data that would not otherwise satisfy the mci window (`min_mci`/`max_mci`) that is supposed to keep AA evaluation deterministic and bounded to data stable as of the trigger's `last_ball_mci`.
- Cause different results depending on constructed key collisions with a real oracle-posted key, effectively spoofing oracle conditions from the AA's point of view.

Either outcome can drive an AA into releasing funds it should not (fund loss to the operator/other users) or into disagreeing with other nodes about whether a condition (and hence unit validity) holds — a node-disagreement/AA-fund-loss class impact, matching the rules' accepted impact categories.

### Likelihood Explanation
Any unprivileged user can post an AA trigger unit with arbitrary `data` payload; if the target AA’s oscript formula references `feed_name` or `feed_value` dynamically from `trigger.data` (a documented, supported oscript pattern), the attacker directly controls the string that is unescaped-concatenated into the key. No special privileges, race conditions, or node compromise are required — only crafting a `data` field containing embedded `\n` sequences, which is not filtered by the formula-side validators (`formula/validation.js`'s `validateDataFeed`/`validateDataFeedExists`) unlike the message-posting-side validators.

### Recommendation
Apply the same `\n`-rejection (and length limits) to `feed_name` and string `feed_value` used in the query path as is already enforced for `data_feed` message payloads: add checks in `formula/validation.js` (`validateDataFeed`, `validateDataFeedExists`) and in `data_feeds.js` (`dataFeedByAddressExists`, `readDataFeedByAddress`, `readDataFeedValueByParams`) that reject any `feed_name`/string `value` containing `\n` (or `\0`) before it is concatenated into a LevelDB key/range boundary, mirroring the existing checks in `validation.js` and `aa_validation.js`.

### Proof of Concept
Conceptual PoC (requires a running node/AA to fully confirm, not executed here):
1. Deploy (or find) an AA whose oscript formula performs a dynamic lookup, e.g.
   `data_feed[[oracles="ORACLE_ADDR", feed_name=trigger.data.name, feed_value=trigger.data.val]]`.
2. Post a trigger unit with `data.name` set to a string containing an embedded `\n` followed by attacker-chosen fragments designed to align with the internal key schema `df\n<address>\n<feed_name>\n<type>\n<value>\n<reversed_mci>` (or `dfv\n<address>\n<feed_name>\n<reversed_mci>`), aiming to force the `gte`/`lte` bounds constructed in `data_feeds.js` `readDataFeedByAddress`/`dataFeedByAddressExists` to reference a reversed-mci value outside the legitimate `[min_mci, max_mci]` window derived from `objValidationState.last_ball_mci`.
3. Observe that the AA formula's data-feed lookup returns a value/existence result inconsistent with what should be visible given the trigger's `last_ball_mci`, demonstrating the mci-bound bypass / key-boundary confusion.

Full confirmation of exploitability (exact byte-level crafting of the reversed-mci hex and confirming stream `gte`/`lte` semantics accept the injected boundary) requires running the code against a live `kvstore`, which was not verified interactively in this session.

### Citations

**File:** data_feeds.js (L119-139)
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
```

**File:** data_feeds.js (L291-309)
```javascript
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
```

**File:** main_chain.js (L1607-1615)
```javascript
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
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

**File:** formula/evaluation.js (L607-610)
```javascript
						return cb("bad oracles "+arrAddresses);
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
```

**File:** formula/evaluation.js (L731-733)
```javascript
						var feed_name = evaluated_params.feed_name.value;
						if (!feed_name || typeof feed_name !== 'string')
							return setFatalError('bad feed name', { arr }, false, cb);
```

**File:** formula/validation.js (L43-53)
```javascript
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
