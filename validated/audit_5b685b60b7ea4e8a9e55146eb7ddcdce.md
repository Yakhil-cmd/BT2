## Title
Delimiter injection in `data_feed`/`in data feed` oscript builtins allows spoofing oracle data across feed names - (File: [data_feeds.js](data_feeds.js), [formula/evaluation.js](formula/evaluation.js))

### Summary
The `data_feed` and `in_data_feed` oscript builtins let an AA look up an oracle's data feed by a `feed_name` string that can be fully attacker-controlled (e.g. derived from `trigger.data`). Unlike the equivalent static validation performed when an AA *posts* a `data_feed` message, the dynamic lookup path never rejects the internal delimiter character (`\n`) from `feed_name`. Because the KV-store key for stored data feeds is built by naively joining `address`, `feed_name`, `type`, `value`, and `mci` with `\n`, an attacker who controls `feed_name` at read time can inject `\n` sequences that make the constructed lookup key alias a record that was actually stored under a *different* feed name, spoofing the existence/value of an oracle feed that was never posted.

### Finding Description
When an AA posts a `data_feed` message, `aa_validation.js` explicitly rejects any feed name or value containing `\n`: [1](#0-0) 

However, when an AA *reads* a data feed dynamically via the `data_feed` or `in_data_feed` formula builtins, the `feed_name` parameter is taken directly from the evaluated expression (which is commonly `trigger.data.feed_name`, i.e. attacker-controlled input from an unprivileged unit poster) with only a "non-empty string" check — no length limit and no rejection of `\n` or other control characters: [2](#0-1) [3](#0-2) 

This unsanitized `feed_name` flows into `dataFeeds.readDataFeedValue` / `dataFeeds.dataFeedExists`, and ultimately into `readDataFeedByAddress` / `dataFeedByAddressExists`, which build the KV-store lookup key by string concatenation using `\n` as the field delimiter: [4](#0-3) [5](#0-4) 

Stored data feed records use exactly the same `\n`-joined format when they are written on stabilization: [6](#0-5) 

Because `readDataFeedByAddress`/`dataFeedByAddressExists` perform a **prefix/range match on the raw byte string** (`'df\n'+address+'\n'+feed_name+'\n'+prefixed_value` or `'dfv\n'+address+'\n'+feed_name`), an attacker who can embed literal `\n` bytes inside `feed_name` can craft a `feed_name` value such that:

`attacker_feed_name + '\n' + <rest of injected key material>`

byte-for-byte equals

`real_feed_name + '\n' + <type>\n<value>\n<mci>`

that some oracle actually posted for a completely different, legitimate feed name. This is a direct structural analogy to the CVE: a delimiter/control character that should have been rejected from a user-controlled field is instead permitted, letting the attacker forge additional "fields" into a structured message that other code parses by delimiter-splitting (`string_utils.getValueFromDataFeedKey` even asserts `m.length !== 6` when parsing back, confirming the strict positional format that can be manipulated): [7](#0-6) 

### Impact Explanation
An AA that uses an oracle-gated condition where the feed name is influenced by trigger data (a documented, encouraged oscript pattern — see the parameterized `definition_template`/`in data feed` example using `trigger.data.feed_name`) can be tricked into believing a value was posted for feed `X` when it was actually posted (by the same or a different oracle address) for an unrelated feed `Y`. This breaks the integrity guarantee of "in data feed"/"data_feed" conditions used to gate fund release, asset issuance/transfer conditions, or state transitions in AAs, enabling:
- Unauthorized release of AA-held funds (an attacker satisfies a condition intended to require a specific oracle attestation that was never made for that feed).
- AA fund loss/freezing due to state corrupted by spoofed oracle data.
- Divergent behavior between AAs relying on this feed if evaluated inconsistently is not expected (this is deterministic given fixed inputs, so it is a spoofing/authorization bypass rather than a network split, but it is a concrete unauthorized-fund-release vector).

### Likelihood Explanation
Reachable by any unprivileged unit poster who can trigger an AA whose author lets the trigger data flow into a `feed_name` argument of `data_feed`/`in data feed` — a pattern explicitly demonstrated in the codebase's own test AA definitions (`"{trigger.data.feed_name}"`), making it a realistic AA-authoring pattern rather than a contrived edge case. No special privileges, node compromise, or network position are required — only crafting a trigger unit with a `feed_name` string containing embedded `\n` bytes.

### Recommendation
Apply the same sanitization used in `aa_validation.js` for statically-posted data feed messages to the dynamic read paths:
- In `formula/evaluation.js` (`data_feed` and `in_data_feed` cases), reject `feed_name` (and string `feed_value`) containing `\n` (or any control character), and enforce `constants.MAX_DATA_FEED_NAME_LENGTH` / `MAX_DATA_FEED_VALUE_LENGTH`.
- Alternatively/defense-in-depth, harden `data_feeds.js` (`readDataFeedByAddress`, `dataFeedByAddressExists`, `readDataFeedValue`, `dataFeedExists`) to reject any `feed_name`/`value` containing the internal delimiter character before constructing KV-store keys, so the fix is centralized regardless of the call site.

### Proof of Concept
1. An oracle posts a legitimate data feed unit with `feed_name = "temp"`, `value = "hot"` at some mci; this is stored (once stable) as key `df\n<oracle_addr>\ntemp\ns\nhot\n<strMci>` (see `main_chain.js` `addDataFeeds`).
2. An AA definition contains a condition such as `["in data feed", ["{trigger.data.oracle}"], "{trigger.data.feed_name}", "=", "@expected"]` gating a payment (mirrors the pattern used in `test/aa.test.js`'s `definition_template` message).
3. An attacker sends a trigger unit whose `trigger.data.feed_name` is crafted as `"attack\ns\nhot\n" + <valid-looking hex mci suffix material>` (exact byte layout depends on the target's stored mci) so that when `readDataFeedByAddress`/`dataFeedByAddressExists` builds `'df\n'+oracle_addr+'\n'+feed_name+'\n'+prefixed_value+...`, the resulting byte string collides with (or falls within the range of) the real key stored for feed `"temp"`.
4. The condition evaluates to true even though the oracle never posted anything for feed `"attack"`, letting the attacker satisfy the oracle-gated condition and trigger fund release from the AA.

Note: exact byte-level crafting of a colliding key (accounting for the reversed-mci suffix encoding in `string_utils.encodeMci`) would need to be validated in a live test harness; this was not run against the code, so the PoC above describes the mechanism and reachable code paths rather than a confirmed working exploit string.

### Citations

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

**File:** formula/evaluation.js (L600-619)
```javascript
			case 'data_feed':

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

**File:** formula/evaluation.js (L726-746)
```javascript
						if (typeof evaluated_params.oracles.value !== 'string')
							return setFatalError('oracles is not a string', { arr }, false, cb);
						var arrAddresses = evaluated_params.oracles.value.split(':');
						if (!arrAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad oracles', { arr }, false, cb);
						var feed_name = evaluated_params.feed_name.value;
						if (!feed_name || typeof feed_name !== 'string')
							return setFatalError('bad feed name', { arr }, false, cb);
						var value = evaluated_params.feed_value.value;
						var relation = evaluated_params.feed_value.operator;
						if (!isValidValue(value))
							return setFatalError("bad feed_value: "+value, { arr }, false, cb);
						var min_mci = 0;
						if (evaluated_params.min_mci){
							min_mci = evaluated_params.min_mci.value.toString();
							if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
								return setFatalError('bad min_mci', { arr }, false, cb);
							min_mci = parseInt(min_mci);
						}
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
					}
```

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

**File:** data_feeds.js (L287-311)
```javascript
function readDataFeedByAddress(address, feed_name, value, min_mci, max_mci, ifseveral, objResult, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var bAbortIfSeveral = (ifseveral === 'abort');
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

**File:** main_chain.js (L1587-1616)
```javascript
								function addDataFeeds(payload){
									if (!storage.assocStableUnits[unit])
										throw Error("no stable unit "+unit);
									var arrAuthorAddresses = storage.assocStableUnits[unit].author_addresses;
									if (!arrAuthorAddresses)
										throw Error("no author addresses in "+unit);
									var strMci = string_utils.encodeMci(mci);
									for (var feed_name in payload){
										var value = payload[feed_name];
										var strValue = null;
										var numValue = null;
										if (typeof value === 'string'){
											strValue = value;
											var bLimitedPrecision = (mci < constants.aa2UpgradeMci);
											var float = string_utils.toNumber(value, bLimitedPrecision);
											if (float !== null)
												numValue = string_utils.encodeDoubleInLexicograpicOrder(float);
										}
										else
											numValue = string_utils.encodeDoubleInLexicograpicOrder(value);
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
									}
```

**File:** string_utils.js (L75-83)
```javascript
// df:address:feed_name:type:value:strReversedMci
function getValueFromDataFeedKey(key){
	var m = key.split('\n');
	if (m.length !== 6)
		throw Error("wrong number of elements in data feed "+key);
	var type = m[3];
	var value = m[4];
	return (type === 's') ? value : decodeLexicographicToDouble(value);
}
```
