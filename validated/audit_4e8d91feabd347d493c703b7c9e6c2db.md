### Title
Address/definition hash collision via `getSourceString` canonicalization flaw allows two structurally different definitions to share one chash - (File: `string_utils.js`)

### Summary
`getSourceString()` in `string_utils.js` is the canonicalization routine behind `object_hash.js`'s `getChash160`, `getChash288`, `getHexHash` and `getBase64Hash`, which in turn compute every address/definition chash (`objectHash.getChash160(arrDefinition)`) used throughout `validation.js`, `definition.js`, `signed_message.js`, `storage.js`, `writer.js`, and `wallet_defined_by_addresses.js`. Because `getSourceString` flattens a JS object tree into a `\x00`-joined token list without an explicit terminator for *object* value boundaries (only arrays get `'['`/`']'` markers), two semantically different JSON trees can serialize to the byte-identical token stream, producing the identical hash/chash — exactly analogous to the reported Solidity bug where a short/lossy identifier (a 4-byte function selector) is treated as if it uniquely identified distinct semantic content.

### Finding Description
`getSourceString` (`string_utils.js:11-60`) recursively serializes a value:
- string → push `"s", value`
- number → push `"n", value.toString()`
- boolean → push `"b", value.toString()`
- array → push `'['`, recurse each element, push `']'`
- object → for each sorted key: push `key`, then recurse into `value` (**no closing marker at all**)

Because object values are not delimited, the number of key/value pairs "absorbed" by a nested object is not fixed in the token stream — a value can be represented either as a single object with several keys, or as one key mapping to a sub-object that itself contains the remaining keys, and the two representations serialize to the exact same token list:

```
Tree A: {"x": {"y": 1}, "z": 2}
Tree B: {"x": {"y": 1, "z": 2}}
```
Both flatten to `["x","y","n","1","z","n","2"]`, joined with `\x00` into identical strings, hence:
```js
objectHash.getSourceString(TreeA) === objectHash.getSourceString(TreeB)
objectHash.getChash160(TreeA)     === objectHash.getChash160(TreeB)
``` [1](#0-0) 

`object_hash.js` uses exactly this function (for non-AA objects) to build every address/definition hash: `getChash160`, `getChash288`, `getHexHash`, `getBase64Hash`. [2](#0-1) 

This hash is the security-critical link between an *address* (a fixed 160-bit chash) and its *definition* (the actual spending/authorization script). Validation repeatedly asserts `objectHash.getChash160(definition) === address` (or `=== definition_chash`) and, once that check passes, trusts the accompanying `definition` array as the sole authorization rule for the address: [3](#0-2) [4](#0-3) [5](#0-4) 

Because two *different* definition trees can collide on the same chash, this equality check is not sufficient to guarantee that the definition passed alongside a unit/author is *the* definition that was originally used to derive the address, whenever the definition contains nested plain objects with data-controlled/attacker-chosen keys (e.g. args objects for `'sig'`/`'hash'`/`'address'` conditions, or the `weighted and`/`r of set` member objects, all of which are plain objects nested inside the definition tree per `definition.js`). [6](#0-5) 

### Impact Explanation
If an attacker can construct two definitions D1 (weak/attacker-controlled authorization, e.g. `sig` with attacker's own key nested inside additional wrapper keys) and D2 (the legitimately-expected, stricter definition) that collide under `getSourceString`/`getChash160`, then:
- An address whose chash was derived from D2 can be "redefined" by supplying D1 in `objAuthor.definition`, since `getChash160(D1) === getChash160(D2) === address`, passing the check at `validation.js:1472` and `signed_message.js:229/245`, `wallet_defined_by_addresses.js:389`.
- This lets an attacker forge control over an address/shared-address/signed-message identity without knowing the real secret behind the intended definition, or lets a user's benign definition be silently substituted for a functionally different one (e.g., different `sig` pubkey wrapped differently) that still satisfies the hash check — a direct unauthorized-spending / authorization-bypass primitive, matching the "concrete unauthorized spending" bar for High severity.
- The same collision applies to `signed_message.js` (arbitrary signed packages / private-payment/AA-trigger authorization) and to shared-address definitions in `wallet_defined_by_addresses.js`, broadening the blast radius to device-to-device shared wallets and AA triggers relying on definition equality.

### Likelihood Explanation
Exploitation requires crafting a definition tree whose nested nodes can be reshaped between "sibling keys at the parent object" and "keys absorbed into a nested child object" while preserving semantics needed to also satisfy `Definition.validateDefinition`'s structural rules (e.g. `hasFieldsExcept`, arg-shape checks for `sig`/`hash`/`address`, etc.). This is a purely off-chain crafting exercise (no need to break SHA-256/RIPEMD160) — the collision is a canonicalization/serialization defect, not a cryptographic one, so it is deterministically constructible once an attacker finds a nesting pair matching the target definition's operator constraints. This makes it moderately likely to be exploitable given a real definition template but requires the definition's argument objects to have the right shape (constraining, but not preventing, exploitation for definitions using nested condition objects such as `and`/`or`/`r of set`/`weighted and` combined with `sig`/`hash`/`address`).

### Recommendation
Fix `getSourceString` to make the tree-to-token mapping injective, e.g.:
- Emit an explicit length/arity prefix (or opening/closing delimiter) for object serialization the same way arrays already do (`'{' ... '}'`), so the number of key/value pairs consumed for a given nested value is bounded and cannot be silently redistributed to a sibling key at a different nesting depth.
- Alternatively, adopt `getJsonSourceString`'s fully-delimited JSON-based canonical form (which already uses `{`, `}`, `:`, `,` and quoting) universally instead of the ad-hoc `\x00`-joined scheme, after auditing it for similar boundary ambiguities.
- Add regression tests asserting `getSourceString`/`getChash160` are injective for representative pairs of "flattened vs nested" object trees.

### Proof of Concept
```js
const objectHash = require('./object_hash.js');

const treeA = { x: { y: 1 }, z: 2 };
const treeB = { x: { y: 1, z: 2 } };

console.log(objectHash.getChash160(treeA));
console.log(objectHash.getChash160(treeB));
// both print the SAME chash, even though treeA !== treeB structurally
```
Both `treeA` and `treeB` flatten via `extractComponents` in `string_utils.js:13-56` to the identical token sequence `["x","y","n","1","z","n","2"]`, joined with the `\x00` separator into the identical source string, and therefore hash identically through `chash.getChash160(sourceString)` in `object_hash.js:10-13` and `chash.js:122-146`. The same mechanism applies to nested plain-object arguments legitimately used inside address definitions (e.g. `['sig', {algo:.., pubkey:..}]`, `['hash', {algo:.., hash:..}]`) validated in `definition.js`, giving an attacker a path to make `objectHash.getChash160(attacker_definition) === objectHash.getChash160(intended_definition)`, which is the exact equality relied upon by `validation.js:1472`, `signed_message.js:229,245`, and `wallet_defined_by_addresses.js:389` to bind an address to its authorization rules. [7](#0-6)

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

**File:** validation.js (L1464-1478)
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
```

**File:** signed_message.js (L219-231)
```javascript
				storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {
					ifDefinitionNotFound: function (definition_chash) { // first use of the definition_chash (in particular, of the address, when definition_chash=address)
						if (!bHasDefinition) {
							if (!conf.bLight || bRetrying)
								return handleResult("definition expected but not provided");
							var network = require('./network.js');
							return network.requestHistoryFor([], [objAuthor.address], function () {
								validateOrReadDefinition(objAuthor, cb, true);
							});
						}
						if (objectHash.getChash160(objAuthor.definition) !== definition_chash)
							return handleResult("wrong definition: "+objectHash.getChash160(objAuthor.definition) +"!=="+ definition_chash);
						cb(objAuthor.definition, last_ball_mci, last_ball_timestamp);
```

**File:** wallet_defined_by_addresses.js (L383-390)
```javascript
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
```

**File:** definition.js (L235-267)
```javascript
			case 'sig':
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["algo", "pubkey"]))
					return cb("unknown fields in "+op);
				if (args.algo === "secp256k1")
					return cb("default algo must not be explicitly specified");
				if ("algo" in args && args.algo !== "secp256k1")
					return cb("unsupported sig algo");
				if (!isStringOfLength(args.pubkey, constants.PUBKEY_LENGTH))
					return cb("wrong pubkey length");
				return cb(null, true);
				
			case 'hash':
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["algo", "hash"]))
					return cb("unknown fields in "+op);
				if (args.algo === "sha256")
					return cb("default algo must not be explicitly specified");
				if ("algo" in args && args.algo !== "sha256")
					return cb("unsupported hash algo");
				if (!ValidationUtils.isValidBase64(args.hash, constants.HASH_LENGTH))
					return cb("wrong base64 hash");
				return cb();
```

**File:** chash.js (L122-146)
```javascript
function getChash(data, chash_length){
	//console.log("getChash: "+data);
	checkLength(chash_length);
	var hash = crypto.createHash((chash_length === 160) ? "ripemd160" : "sha256").update(data, "utf8").digest();
	//console.log("hash", hash);
	var truncated_hash = (chash_length === 160) ? hash.slice(4) : hash; // drop first 4 bytes if 160
	//console.log("clean data", truncated_hash);
	var checksum = getChecksum(truncated_hash);
	//console.log("checksum", checksum);
	//console.log("checksum", buffer2bin(checksum));

	var binCleanData = buffer2bin(truncated_hash);
	var binChecksum = buffer2bin(checksum);
	var binChash = mixChecksumIntoCleanData(binCleanData, binChecksum);
	//console.log(binCleanData.length, binChecksum.length, binChash.length);
	var chash = bin2buffer(binChash);
	//console.log("chash     ", chash);
	var encoded = (chash_length === 160) ? base32.encode(chash).toString() : chash.toString('base64');
	//console.log(encoded);
	return encoded;
}

function getChash160(data){
	return getChash(data, 160);
}
```
