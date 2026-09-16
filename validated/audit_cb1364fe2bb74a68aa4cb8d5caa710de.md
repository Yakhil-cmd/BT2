### Title
Delimiter Injection in Data Feed Lookups via Unsanitized `feed_name`/`value` in Oscript `data_feed[[...]]` - (File: `data_feeds.js`)

### Summary
The oscript `data_feed[[...]]` / `in_data_feed[[...]]` functions let an AA formula look up an oracle-posted data feed by `oracles`, `feed_name` and (optionally) `feed_value`. These string parameters are concatenated directly into LevelDB key range boundaries using `\n` as the field separator, without stripping or rejecting embedded `\n` characters from attacker-influenced input. This is the same bug class as the reported PAC4J LDAP injection: an ID/lookup parameter that is supposed to be an atomic value is instead spliced unescaped into a structured, delimiter-based query, letting an attacker forge the boundaries of that query and make it match records it was never meant to match.

### Finding Description
`formula/validation.js` `validateDataFeed()`/`validateDataFeedExists()` only checks that `feed_name` is a non-empty trimmed string: [1](#0-0) 

`formula/evaluation.js`'s `getDataFeed()` does the same weak check (non-empty string) before handing `feed_name`/`value` to the storage layer: [2](#0-1) 

In `data_feeds.js`, `feed_name` (and, for string values, the raw `value`) is concatenated straight into the LevelDB key using `\n` as the field delimiter, both for existence checks and for value reads: [3](#0-2) [4](#0-3) 

The physical key format is `df\n<address>\n<feed_name>\n<type>\n<encoded_value>\n<mci>` (and `dfv\n<address>\n<feed_name>\n<mci>` for the "last value" index), and lookups are implemented as LevelDB range scans (`gte`/`lte`) over this delimited string. Because `feed_name` (and the string form of `value`) is never checked for embedded `\n`, an attacker who controls the string passed into `feed_name=` (e.g. via `trigger.data.<field>` used inside an AA's `data_feed[[..., feed_name=trigger.data.name, ...]]` expression) can inject extra `\n`-delimited segments. This effectively forges the intended key/range boundary, so the range scan can span into, or exactly match, a different feed name/value/type/address segment that the oracle actually posted under a different, legitimate `feed_name` — analogous to an LDAP filter injection that lets attacker-controlled ID fields alter which directory entries are matched.

### Impact Explanation
If an AA's logic branches on the *existence* (`in_data_feed`) or *value* (`data_feed`) of an oracle feed to decide payouts (e.g. a price/oracle-triggered swap or lottery AA that takes `feed_name` partly from the trigger message), a malicious trigger sender can craft a `feed_name` string containing embedded `\n` so that the composite key/range constructed by `dataFeedByAddressExists`/`readDataFeedByAddress` unintentionally matches a feed the oracle posted under a different name/value than the one the AA author intended to check. This can let the attacker force a "found"/"not found" result, or read an unintended value, for a lookup that the AA logic and the oracle never sanctioned — leading to AA fund loss (incorrect payout condition satisfied) or freezing (condition never satisfiable), i.e., concrete AA fund loss/mismanagement of state, matching the required impact bar.

### Likelihood Explanation
Requires an AA author to feed trigger-controlled data into `feed_name=` or `feed_value=` of `data_feed[[...]]`/`in_data_feed[[...]]` (a documented, common oscript pattern for oracle-driven AAs) and an attacker able to post a trigger unit — which is the standard unprivileged trigger-sender threat model. The lack of any delimiter-safety check on `feed_name`/`value` in both `formula/validation.js` and `data_feeds.js` makes exploitation straightforward once such an AA exists; no special node/network compromise is needed.

### Recommendation
Reject `feed_name` and string `feed_value` values that contain the internal delimiter character `\n` (and other control bytes used in the key encoding) in `validateDataFeed`/`validateDataFeedExists` (`formula/validation.js`) and in `getDataFeed`/`readDataFeedValueByParams` (`formula/evaluation.js`, `data_feeds.js`), or switch to a length-prefixed/escaped key encoding in `data_feeds.js` so that no combination of attacker-controlled `feed_name`/`value` content can alter field boundaries of the LevelDB key.

### Proof of Concept
1. An AA is written so that the feed name used for an oracle lookup is derived from trigger data, e.g.:
   `data_feed[[oracles="ORACLE_ADDR", feed_name=trigger.data.name]] == trigger.data.expected`
   (this is valid oscript per the `df_param` grammar rule allowing `feed_name = expr`.) [5](#0-4) 
2. The oracle has legitimately posted an unrelated feed, e.g. `feed_name="secretFeed"` with some value, creating a LevelDB key such as `df\nORACLE_ADDR\nsecretFeed\ns\n<value>\n<mci>`.
3. An attacker sends an AA trigger with `data.name = "x\nsecretFeed"` (or another string crafted to shift the delimiter boundary within the composite key range used by `readDataFeedByAddress`/`dataFeedByAddressExists`).
4. Because `feed_name` is validated only for non-emptiness (`formula/validation.js:51-53`) and concatenated unescaped into the key (`data_feeds.js:139`, `data_feeds.js:292/305`), the range scan boundary computed for the "requested" feed name can be made to overlap the key range of `secretFeed`, causing the AA's `data_feed[[...]]`/`in_data_feed[[...]]` evaluation to return a value/existence result associated with `secretFeed` instead of failing as it should for a non-existent feed named `x`.
5. If the AA's payout/response logic depends on this result, the attacker can trigger an unintended fund transfer or bounce/no-bounce decision.

### Citations

**File:** formula/validation.js (L51-53)
```javascript
				case 'feed_name':
					if (value.trim() === '') return {error: 'empty feed name', complexity};
					break;
```

**File:** formula/evaluation.js (L608-610)
```javascript
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
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

**File:** data_feeds.js (L287-309)
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
```

**File:** formula/grammars/oscript.ne (L311-316)
```text
df_param ->  ("oracles"|"feed_name"|"min_mci"|"feed_value"|"what"|"ifseveral"|"ifnone"|"type") comparisonOperator (expr | %addressValue)  {% function(d) {
	var value = d[2][0];
	if (value.type === 'addressValue')
		value = value.value;
	return addLocation([d[0][0].value, d[1], value], d);
} %}
```
