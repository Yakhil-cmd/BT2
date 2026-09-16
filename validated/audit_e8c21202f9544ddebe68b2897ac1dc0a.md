### Title
Hash collision in `getSourceString` allows forging address definitions and private‑payment payload hashes - (File: `string_utils.js`)

### Summary
`getSourceString()` (used by `object_hash.js` for `getChash160`, `getHexHash`, `getBase64Hash`, `getUnitHashToSign`, etc.) serializes arbitrary JS values by pushing type‑tagged tokens ("s"/"n"/"b"/"["/"]") and, for objects, the raw (untagged) key string, then joining everything with a single `\x00` delimiter. Because object **keys** are emitted as bare tokens (not type‑tagged) and array delimiters `[`/`]` are also bare single‑character tokens indistinguishable from a key or a value that happens to equal `"["`, `"]"` or `"s"`, two structurally different inputs (an object vs. an array) can be crafted to produce byte‑identical token streams, and therefore an identical hash. This is the same bug class as the reported Sui `dynamic_field` collision: the serialization concatenates semantically different components without unambiguous length/type framing for every token, allowing boundary confusion between "this token is a key" vs. "this token is a bracket/tag/value".

### Finding Description
`getSourceString` in `string_utils.js` builds a flat list of tokens: [1](#0-0) 

- primitives push `[tag, value]` (2 tokens, tag ∈ {s,n,b}),
- arrays push `'['`, then the tokens of every element, then `']'`,
- objects push, for each sorted key, the **raw key string** followed by the tokens of that key's value.

The only integrity check is that individual tokens must not contain the `\x00` join character; there is no encoding that distinguishes a "key" token from a "bracket" token from a "tag" token. This means the token stream is not uniquely decodable back to a single tree shape — two different trees can produce the same flat token list.

Concrete collision (verified by hand-tracing the algorithm):

```js
// Array with two string elements
var A = ["AAA", "s"];

// Object with two keys "[" and "s"
var B = { "[": "AAA", "s": "]" };
```

Tracing `extractComponents`:
- `A` → push `'['` → extract `"AAA"` → `['s','AAA']` → extract `"s"` → `['s','s']` → push `']'`
  ⇒ tokens: `['[','s','AAA','s','s',']']`
- `B` (keys sorted `"["` < `"s"`) → push key `"["` → extract value `"AAA"` → `['s','AAA']` → push key `"s"` → extract value `"]"` → `['s',']']`
  ⇒ tokens: `['[','s','AAA','s','s',']']`

Both produce the identical token list, hence the identical joined string `"[\x00s\x00AAA\x00s\x00s\x00]"`, hence **identical outputs from `getChash160`, `getHexHash`, `getBase64Hash`, `getUnitHashToSign`, etc.** despite `A` and `B` being semantically unrelated (an array vs. a keyed object).

This directly parallels the reported remediation for the Sui bug: inserting explicit length prefixes for `k_bytes`/`k_tag_bytes` prevents boundary‑shifting collisions; `getSourceString` has no equivalent framing for the *key* vs. *bracket* vs. *tag* token classes, so the same class of ambiguity survives.

`object_hash.js` exposes these primitives to consensus‑critical code: [2](#0-1) 

### Impact Explanation
Two reachable consensus paths use `getSourceString`/`getChash160`/`getBase64Hash` over attacker‑influenced structures:

1. **Address definitions.** `validateDefinition` accepts a definition the first time it is used only if `objectHash.getChash160(arrAddressDefinition) === definition_chash` (i.e. `address`): [3](#0-2) 
An attacker who can find two definitions (one an "authentic-looking" spending policy structured as an object, one an equivalent-hashing alternate structured as an array/object mix) that collide via the `getSourceString` ambiguity could get an address whose owner believes it is controlled by definition `D_expected`, while a different definition `D_attacker` with the same chash is also "valid" for that address per this check, enabling unauthorized redefinition/spending from that address.

2. **Private‑payment payload integrity.** `payload_hash` for private (asset) payments is computed with `objectHash.getBase64Hash(payload, …)` and is the sole binding between the publicly visible unit and the privately transmitted payload: [4](#0-3) [5](#0-4) [6](#0-5) 
If two different `hidden_payload`/`payload` objects (differing in outputs/inputs/keys) can be constructed to collide under `getSourceString`, a malicious private‑payment counterparty could substitute a different payload (e.g. different outputs) that still satisfies the recorded `payload_hash`, letting a peer accept a private chain element whose real content differs from what was hashed on-chain — a path toward double‑spending or misattributing a private‑payment output.

This satisfies the "concrete unauthorized spending" / "double-spend" bar because both address‑definition matching and private‑payment payload verification are hash-equality gates that directly authorize control of funds.

### Likelihood Explanation
Exploitability requires constructing a *semantically meaningful* colliding pair (not just the toy `["AAA","s"]` vs `{"[":"AAA","s":"]"}` example) that also satisfies the syntactic constraints of a valid definition (`["sig", {...}]`, `["and", [...]]`, etc.) or of a valid payment payload (must contain `asset`, `inputs`, `outputs` fields with specific types). The demonstrated collision proves the underlying serialization is **not injective**, which is the necessary precondition; finding a collision that also satisfies these additional schema constraints is a search problem but is aided by the fact that the attacker fully controls both candidate structures (definitions, private payload objects, and array/object shapes are attacker/composer supplied before being hashed). Given the demonstrated ease of constructing exact collisions using ordinary key/bracket/tag character overlaps (`"["`, `"]"`, `"s"`, `"n"`, `"b"`), and that these are common ASCII characters legal as object keys/string values, further constrained collisions are plausible with moderate effort, making this a Medium‑to‑High likelihood issue rather than purely theoretical.

### Recommendation
Make `getSourceString` (and its JSON‑based counterpart) unambiguously decodable, mirroring the length‑prefix fix recommended for the Sui bug:
- Tag object **keys** the same way values are tagged (e.g. push a distinct marker such as `"k"` before every key token so keys can never be confused with tags/brackets), and/or
- Emit an explicit length prefix for arrays/objects (`"["+count`) instead of a bare bracket character, and reject reserved token strings (`"["`, `"]"`, `"s"`, `"n"`, `"b"`) from ever being used as bare structural markers without disambiguating context.
- Add regression tests asserting that structurally different inputs never produce identical `getSourceString`/`getChash160`/`getBase64Hash` outputs (e.g., via randomized differential fuzzing comparing token counts/structure vs. hash).

### Proof of Concept
```js
var object_hash = require('./object_hash.js');
var string_utils = require('./string_utils.js');

var A = ["AAA", "s"];                 // array
var B = { "[": "AAA", "s": "]" };     // object

console.log(string_utils.getSourceString(A) === string_utils.getSourceString(B)); // true
console.log(object_hash.getChash160(A) === object_hash.getChash160(B));           // true
console.log(object_hash.getBase64Hash(A) === object_hash.getBase64Hash(B));       // true
```
This proves `getSourceString`/`getChash160`/`getBase64Hash` are not injective over their input domain; the residual risk is finding a domain‑specific colliding pair (address definition or private‑payment payload) that also satisfies the respective schema validators, which was not fully constructed in this analysis and remains to be demonstrated end‑to‑end.

### Citations

**File:** string_utils.js (L11-60)
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
				break;
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
				arrComponents.push("n", variable.toString());
				break;
			case "boolean":
				arrComponents.push("b", variable.toString());
				break;
			case "object":
				if (Array.isArray(variable)){
					if (variable.length === 0)
						throw Error("empty array in "+JSON.stringify(obj));
					arrComponents.push('[');
					for (var i=0; i<variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in "+JSON.stringify(obj));
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						if (key.includes(STRING_JOIN_CHAR))
							throw Error("00 byte in object key in " + JSON.stringify(obj));
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
			default:
				throw Error("getSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
	}

	extractComponents(obj);
	return arrComponents.join(STRING_JOIN_CHAR);
}
```

**File:** object_hash.js (L10-30)
```javascript
function getChash160(obj) {
	var sourceString = (Array.isArray(obj) && obj.length === 2 && obj[0] === 'autonomous agent') ? getJsonSourceString(obj) : getSourceString(obj);
	return chash.getChash160(sourceString);
}

function getChash160FromString(str) {
	return chash.getChash160("s\x00" + str);
}

function getChash288(obj) {
	return chash.getChash288(getSourceString(obj));
}

function getHexHash(obj) {
	return crypto.createHash("sha256").update(getSourceString(obj), "utf8").digest("hex");
}

function getBase64Hash(obj, bJsonBased) {
	var sourceString = bJsonBased ? getJsonSourceString(obj) : getSourceString(obj)
	return crypto.createHash("sha256").update(sourceString, "utf8").digest("base64");
}
```

**File:** validation.js (L1464-1484)
```javascript
	function validateDefinition(){
		if (!("definition" in objAuthor))
			return callback();
		// the rest assumes that the definition is explicitly defined
		var arrAddressDefinition = objAuthor.definition;
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
```

**File:** validation.js (L2696-2703)
```javascript
				return onError("invalid app");
			try{
				if (objectHash.getBase64Hash(payload, row.version !== constants.versionWithoutTimestamp) !== row.payload_hash)
					return onError("payload hash does not match");
			}
			catch(e){
				return onError("failed to calc payload hash: "+e);
			}
```

**File:** indivisible_asset.js (L776-795)
```javascript
							var payload_hash;// = objectHash.getBase64Hash(payload);
							var bJsonBased = (last_ball_mci >= constants.timestampUpgradeMci);
							if (objAsset.is_private){
								payload.outputs.forEach(function(o){
									o.output_hash = objectHash.getBase64Hash({address: o.address, blinding: o.blinding});
								});
								var hidden_payload = _.cloneDeep(payload);
								hidden_payload.outputs.forEach(function(o){
									delete o.address;
									delete o.blinding;
								});
								payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
							}
							else
								payload_hash = objectHash.getBase64Hash(payload, bJsonBased);
							var objMessage = {
								app: "payment",
								payload_location: objAsset.is_private ? "none" : "inline",
								payload_hash: payload_hash
							};
```

**File:** wallet.js (L295-313)
```javascript
							const hidden_payload = _.cloneDeep(payload);
							if (payload.denomination) { // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
								if (!payload.outputs.every(o => o.output_hash === objectHash.getBase64Hash({ address: o.address, blinding: o.blinding })))
									return callbacks.ifError("output hash mismatch");
								hidden_payload.outputs.forEach(function (o) {
									delete o.address;
									delete o.blinding;
								});
							}
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage && objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
```
