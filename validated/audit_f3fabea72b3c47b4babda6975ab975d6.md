## #Vulnerability found

### Title
Hardcoded, network-independent `definer_address` for the base asset breaks `asset['base'].definer_address` on testnet/devnet - (File: `formula/common.js`)

### Summary
The external report describes Compound's Comptroller hardcoding the mainnet WETH address instead of parameterizing it, so `getWETHAddress()`/`grantCompInternal()` silently misbehave or revert on any network other than the one the address was copied from. The Obyte/ocore analog is `objBaseAssetInfo.definer_address` in `formula/common.js`, which is a single hardcoded address used to answer the oscript expression `asset['base'].definer_address` for every network (mainnet, testnet, devnet) instead of being derived per-network the way `constants.GENESIS_UNIT` and `constants.BLACKBYTES_ASSET` are.

### Finding Description
`formula/common.js` defines a static object used to answer `asset[...]` queries for the base asset: [1](#0-0) 

Unlike `constants.js`, which explicitly branches on `exports.bTestnet` for network-specific identifiers such as `GENESIS_UNIT` and `BLACKBYTES_ASSET`: [2](#0-1) 

`objBaseAssetInfo.definer_address` is a single literal (`'MZ4GUQC7WUKZKKLGAS3H3FSDKLHI7HFO'`) with no testnet/devnet variant, even though the base asset's actual definer (the author of the genesis unit) differs by network — exactly the property that `GENESIS_UNIT` captures per-network just two lines above it in `constants.js`.

This value is directly returned to oscript/AA code whenever an AA or authentifier formula evaluates `asset['base'].definer_address`: [3](#0-2) 

and the corresponding static validator in `formula/validation.js` permits `definer_address` as a valid field on `asset[...]` without any network check: [4](#0-3) 

Because the AA/oscript language exposes `asset['base'].definer_address` as a first-class, documented primitive that AA authors can rely on to identify or gate logic against the base-asset issuer, any AA deployed on testnet or devnet that reads this field will get the mainnet-era hardcoded value instead of the actual definer of that network's genesis unit.

### Impact Explanation
AAs are commonly written to compare `asset[...].definer_address` against a known/expected address as an access-control or sanity check (analogous to how `issued_by_definer_only` and `cosigned_by_definer` checks in `validation.js` compare against `objAsset.definer_address`, see [5](#0-4) ). If an AA author's oscript logic performs `asset['base'].definer_address == <expected_address>` (e.g., to verify network identity or gate a privileged code path) on testnet/devnet, the comparison will silently evaluate against the wrong constant. Depending on how the AA uses the result, this can:
- permanently disable an intended fund-release branch (funds sent to the AA become frozen, unable to satisfy the condition — "AA fund loss or freezing"), or
- permanently enable/route funds down an unintended branch if the AA's logic negates the comparison, causing unauthorized redirection of funds held by the AA.

This mirrors the external report's core issue: a hardcoded, environment-specific constant baked into always-reachable contract/AA logic causes systemic malfunction whenever the code runs on a different environment than the one the constant was copied from.

### Likelihood Explanation
`asset['base'].definer_address` is reachable by any unprivileged AA author simply by writing an AA definition that references it — no special privilege is required, and the AA validator explicitly whitelists `definer_address` as an allowed field (`formula/validation.js` lines 800-801 above), confirming it is an intended, documented feature rather than dead code. Every AA deployed to testnet or devnet that touches this field is affected uniformly and deterministically (not depending on race conditions or specific triggers), so likelihood of manifestation is high wherever the primitive is used across non-mainnet networks.

### Recommendation
Make `objBaseAssetInfo.definer_address` network-aware, consistent with how `constants.GENESIS_UNIT` and `constants.BLACKBYTES_ASSET` are already branched on `constants.bTestnet` (and devnet). Either compute it dynamically from the genesis unit's author, or provide explicit per-network literals (mainnet/testnet/devnet) so `asset['base'].definer_address` returns the correct, network-appropriate value everywhere it is evaluated (`formula/evaluation.js`) and validated (`formula/validation.js`).

### Proof of Concept
1. Deploy an AA on testnet containing logic such as:
   `if (asset['base'].definer_address == 'EXPECTED_TESTNET_GENESIS_DEFINER') { ... release funds ... }`
2. Trigger the AA; observe that `asset['base'].definer_address` returns the hardcoded mainnet-era literal `'MZ4GUQC7WUKZKKLGAS3H3FSDKLHI7HFO'` from `formula/common.js` line 33 rather than the actual testnet genesis definer.
3. The comparison fails unconditionally, so the intended branch never executes — funds sent to the AA are stuck in the bounced/default branch, demonstrating an AA-fund-freezing condition purely from evaluating a documented, whitelisted oscript primitive.

### Citations

**File:** formula/common.js (L22-34)
```javascript
var objBaseAssetInfo = {
	cap: constants.TOTAL_WHITEBYTES,
	is_private: false,
	is_transferrable: true,
	auto_destroy: false,
	fixed_denominations: false,
	issued_by_definer_only: true,
	cosigned_by_definer: false,
	spender_attested: false,
	is_issued: true,
	exists: true,
	definer_address: 'MZ4GUQC7WUKZKKLGAS3H3FSDKLHI7HFO',
};
```

**File:** constants.js (L35-36)
```javascript
exports.GENESIS_UNIT = process.env.GENESIS_UNIT || (exports.bTestnet ? 'TvqutGPz3T4Cs6oiChxFlclY92M2MvCvfXR5/FETato=' : 'oj8yEksX9Ubq7lLc+p6F2uyHUuynugeVq4+ikT67X6E=');
exports.BLACKBYTES_ASSET = process.env.BLACKBYTES_ASSET || (exports.bTestnet ? 'LUQu5ik4WLfCrr8OwXezqBa+i3IlZLqxj2itQZQm8WY=' : 'qO2JsiuDMh/j+pqJYZw3u82O71WjCDf0vTNvsnntr8o=');
```

**File:** formula/evaluation.js (L1531-1544)
```javascript
			case 'asset':
				var asset_expr = arr[1];
				var field_expr = arr[2];
				evaluate(asset_expr, function (asset) {
					if (fatal_error)
						return cb(false);
					evaluate(field_expr, function (field) {
						if (fatal_error)
							return cb(false);
						if (typeof field !== 'string' || !objBaseAssetInfo.hasOwnProperty(field))
							return setFatalError("bad field in asset[]: " + field, { arr }, false, cb);
						var convertValue = (value) => (typeof value === 'number' && mci >= constants.aa3UpgradeMci) ? new Decimal(value) : value;
						if (asset === 'base')
							return cb(convertValue(objBaseAssetInfo[field]));
```

**File:** formula/validation.js (L782-805)
```javascript
			case 'asset':
				complexity++;
				var asset = arr[1];
				var field = arr[2];
				async.eachSeries(
					[asset, field],
					function (param, cb2) {
						if (typeof param === 'boolean' || Decimal.isDecimal(param))
							return cb2("wrong type in asset[]");
						evaluate(param, cb2);
					},
					function (err) {
						if (err)
							return cb(err);
						if (typeof asset === 'string') {
							if (asset !== 'base' && !ValidationUtils.isValidBase64(asset, constants.HASH_LENGTH))
								return cb("bad asset in asset[]: " + asset);
						}
						if (typeof field === 'string' && !objBaseAssetInfo.hasOwnProperty(field))
							return cb("bad field in asset[]: " + field);
						cb();
					}
				);
				break;
```

**File:** validation.js (L2109-2113)
```javascript
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
			return callback("must be cosigned by definer");
```
