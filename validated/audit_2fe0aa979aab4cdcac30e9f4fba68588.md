## Analysis Result

### Title
Newline-delimiter injection in data-feed key lookups via unsanitized `feed_name` in address/AA definitions - (File: `data_feeds.js`, `definition.js`)

### Summary
`matrix-appservice-irc`'s bug was that a user-controlled string (channel name) was concatenated into a command stream without stripping embedded newlines, letting an attacker smuggle extra "lines" (commands) past the parser. The analogous pattern in `ocore` is in the oracle/data-feed subsystem: `feed_name` is embedded, unescaped, into `\n`-delimited keys used both to build and to range-query the kvstore, while the value returned is later split again on `\n` and positionally indexed. `feed_name` itself is validated only for type/length, never for forbidden characters (unlike the `element` argument of the same address-definition operator, which is restricted by a strict character-class regex).

### Finding Description
Address/AA definitions can contain an oracle-based condition (the `feed_name`-taking branch in `definition.js`) whose only checks on `feed_name` are that it's a non-empty string and not longer than `constants.MAX_DATA_FEED_NAME_LENGTH`: [1](#0-0) 
Unlike `element` in the same block, which is constrained to a strict printable-character regex disallowing control characters, `feed_name` has no such restriction, so it can contain literal `\n` bytes. [2](#0-1) 

That attacker-controlled `feed_name` is later concatenated directly (with `\n` as the field separator) into kvstore range-query keys: [3](#0-2) 
and into the `dfv\n<address>\n<feed_name>` prefix used for value lookups: [4](#0-3) 

The stored/queried key format is assumed to be a fixed 6-field, `\n`-delimited string (`df:address:feed_name:type:value:reversed_mci`), and parsing code blindly splits on `\n` and indexes by position: [5](#0-4) 

Because `feed_name` is not sanitized against embedding `\n`, a definition author can craft a `feed_name` such as `"real_name\nn\n<crafted-lexicographic-value>\nffffffff"` (or similar). When this is substituted into `key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value`, the resulting range bounds (`gte`/`lte`/`gt`/`lt`) no longer correspond to what the definition author or a verifier would expect from the nominal feed name — the extra embedded fields shift the range boundaries in the underlying LevelDB-style key ordering, in the same way the IRC bug let a crafted channel name inject additional protocol lines. This can cause the range scan to match key ranges belonging to a different (or forged) value/type/mci window than the one the oracle actually posted, or to fail to match the real value while spuriously reporting a match for adjacent, attacker-chosen ranges.

### Impact Explanation
Address definitions and AA formulas can gate spending or AA branching on "did oracle X post data-feed value satisfying such-and-such relation" (`dataFeedExists`/`readDataFeedValue`, reached from `in merkle`/data-feed operators). If the key-range construction can be desynchronized by an attacker-chosen `feed_name` containing embedded delimiter characters, an attacker who authors the address/AA definition (which is itself the "unprivileged" reachable surface — anyone can define an address or AA) can attempt to make the oracle-gated condition evaluate as satisfied when the intended oracle attestation was never actually posted, or manipulate which stored data-feed record is matched. This maps to the "unauthorized spending" / "AA fund loss" impact bucket for conditions that rely on an oracle attesting a specific value before funds unlock.

### Likelihood Explanation
The `feed_name` field is fully attacker-controlled at definition-authoring time (no privileged actor involved) and is only length-checked, not character-checked, in `definition.js`. Anyone can define an address or an AA with such a definition and then attempt to trigger the vulnerable condition evaluation by posting a spending unit or an AA trigger. This makes the path directly reachable by an ordinary AA/address definition author, matching the CWE-20 (improper input validation) class of the reference advisory.

### Recommendation
- Reject `feed_name` values containing `\n` (or any of the other delimiter bytes used in key construction, e.g. `\r`, `\xff`) at definition-validation time in `definition.js`, mirroring the strict regex already applied to `element`.
- Alternatively, use a length-prefixed or otherwise unambiguous binary encoding for `address`/`feed_name`/`type`/`value`/`mci` fields in `data_feeds.js`/`string_utils.js` instead of relying on `\n` as a bare separator, so that no field value can inject additional "columns" into the key.
- Add defensive parsing in `string_utils.getValueFromDataFeedKey`/`getMciFromDataFeedKey` to reject/quarantine malformed keys rather than assuming a fixed split-length silently succeeds.

### Proof of Concept
Conceptual (validation-logic) PoC, since a live test harness isn't available in this analysis:
1. Author an address definition (or AA state var access) using the `feed_name`-taking oracle condition in `definition.js`, setting `feed_name = "price\nn\n<crafted-lexicographic-bytes>\nffffffff"`.
2. Because only `feed_name.length` is checked [1](#0-0) , this passes definition validation.
3. When the condition is evaluated, `dataFeedByAddressExists`/`readDataFeedByAddress` build `key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value` [6](#0-5)  — the embedded `\n` sequences in `feed_name` are indistinguishable from the delimiters the code relies on to separate `feed_name`/`type`/`value`/`mci`, letting the crafted string reshape the kvstore range query beyond what the nominal `feed_name` field should allow.

### Citations

**File:** definition.js (L466-469)
```javascript
				if (!isNonemptyString(feed_name))
					return cb("no feed_name");
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return cb("feed_name too long");
```

**File:** definition.js (L470-475)
```javascript
				if (!isNonemptyString(element))
					return cb("no element");
			//	if (!isStringOfLength(element_hash, constants.HASH_LENGTH))
			//		return cb("incorrect length of element hash");
				if (!element.match(/^[\w ~,.\/\\;:!@#$%^&*\(\)=+\[\]\{\}<>\?|-]{1,100}$/))
					return cb("incorrect format of merkled element");
```

**File:** data_feeds.js (L139-164)
```javascript
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

**File:** data_feeds.js (L287-306)
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
```

**File:** string_utils.js (L63-83)
```javascript
function encodeMci(mci){
	return (0xFFFFFFFF - mci).toString(16).padStart(8, '0'); // reverse order for more efficient sorting as we always need the latest
}

function getMciFromDataFeedKey(key){
	var arrParts = key.split('\n');
	var strReversedMci = arrParts[arrParts.length-1];
	var reversed_mci = parseInt(strReversedMci, 16);
	var mci = 0xFFFFFFFF - reversed_mci;
	return mci;
}

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
