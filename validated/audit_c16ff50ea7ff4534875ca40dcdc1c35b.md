### Title
Unescaped `\n` delimiter in data-feed KV keys allows oracle-posted `feed_name`/value to inject forged feed entries - (File: data_feeds.js)

### Summary
`data_feeds.js` builds raw, delimiter-joined KV-store keys for data feeds (`'df\n'+address+'\n'+feed_name+'\n'+prefixed_value+'\n'+mci`) directly from the `feed_name` and value fields of a `data_feed` message payload, without checking whether those attacker-supplied strings contain the `\n` delimiter itself. This is the same bug class as the reported `eventsource-encoder` issue: an unescaped line/field terminator embedded in a value that is supposed to occupy exactly one field lets the attacker inject additional, forged fields into a delimiter-based record.

### Finding Description
The data-feed key format is a plain `\n`-joined string with a fixed number of positional fields, and the reader assumes that exact field count: [1](#0-0) [2](#0-1) 

The reverse-parsing side hard-codes the expected number of `\n`-separated parts: [3](#0-2) 

Contrast this with the general-purpose canonical serializer `getSourceString`, which explicitly guards against the join character appearing inside a string or object key before concatenating fields: [4](#0-3) [5](#0-4) 

No equivalent guard exists in `data_feeds.js` for `feed_name` or for string `value`s before they are spliced into the `df\n...` key with `\n` as an unescaped separator. `feed_name` and the feed value are attacker-controlled: they come straight from the payload of a `data_feed` message that any unit author (oracle) can post — this is a normal, unprivileged unit-posting path, not something requiring special privileges.

### Impact Explanation
Because the key is built by naive string concatenation with `\n`, a `feed_name` (or a string value) containing embedded `\n` characters shifts the positional meaning of the fields that follow it in the key. This is structurally identical to the SSE bug: a field that is supposed to be a single opaque token can be used to inject fake delimiters and therefore fake "fields" into a downstream parser that trusts the delimiter to demarcate boundaries. Depending on how a given ocore build's `data_feed` payload validation restricts `feed_name`/value characters (this could not be fully confirmed from the retrieved code — see Likelihood), the practical outcomes are: `getValueFromDataFeedKey`/`getMciFromDataFeedKey` computing a different, attacker-shifted `mci` or `value` than intended (data-feed value confusion for an AA/oracle-consuming address), or the fixed-length assertion in `getValueFromDataFeedKey` throwing on read, which can crash the code path used during AA trigger data-feed lookups. Either a misread value or divergent exception handling on this same input across differing node logic paths can translate into inconsistent data-feed answers for AAs that condition fund release on oracle data — i.e., AA fund loss/freezing or disagreement on interpretation of the same on-chain `data_feed` message.

### Likelihood Explanation
I could not fully confirm from the retrieved code whether `validation.js`'s `data_feed` message validation already forbids `\n` (or other control characters) inside `feed_name` or string values before the message is accepted into a unit — grep matched 5 occurrences of `data_feed` in `validation.js`, but I was unable to retrieve and inspect that validation logic within the available tool budget. If such a character restriction already exists there, this specific injection path is not exploitable and this would not be a valid finding; if it does not, the path in `data_feeds.js`/`string_utils.js` shown above is directly reachable by any address that authors a `data_feed` message (an ordinary, unprivileged unit-posting action), making likelihood high once payload validation is confirmed absent.

### Recommendation
Reject `data_feed` messages (or reject/escape at key-construction time) whenever `feed_name` or a string feed value contains `\n` (or `\r`), mirroring the `STRING_JOIN_CHAR` guard already used in `string_utils.getSourceString`. This should be enforced both in unit validation (`validation.js`) so malformed units are never accepted into the DAG, and defensively in `data_feeds.js` key-building/parsing so no code path can misinterpret a shifted key.

### Proof of Concept
Because I could not verify the exact validation constraints in `validation.js` within the available investigation budget, I cannot provide a concrete end-to-end PoC unit payload with certainty that it would pass unit validation. This finding should be treated as provisional pending confirmation of whether `feed_name`/value character restrictions already exist in `validation.js`; a Devin session with full repository access would be needed to inspect `validation.js`'s `data_feed` handling and confirm or refute exploitability.

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

**File:** data_feeds.js (L290-306)
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
```

**File:** string_utils.js (L11-20)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
```

**File:** string_utils.js (L43-48)
```javascript
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						if (key.includes(STRING_JOIN_CHAR))
							throw Error("00 byte in object key in " + JSON.stringify(obj));
						arrComponents.push(key);
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
