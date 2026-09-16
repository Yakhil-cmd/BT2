### Title
Cross-network / cross-address-reuse replay of `is_valid_signed_package` signed packages due to missing chain/network binding in `getSignedPackageHashToSign()` - (File: object_hash.js, signed_message.js, formula/evaluation.js)

### Summary
`is_valid_signed_package()` lets an AA authorize state changes (trades, payment-channel closes, off-chain balance transfers) based on an off-chain ECDSA signature over a `signed_message` object. The hash that is actually signed, produced by `getSignedPackageHashToSign()`, binds only to the `signed_message` content, `authors`, `version`, and (optionally) `last_ball_unit`. It never binds to the specific chain/network (there is no analogue of `chainid`/genesis-unit/`alt`), and binding to the DAG via `last_ball_unit` is optional (`bNetworkAware`), not mandatory. This mirrors the reported EVM bug class where a signature that omits `chainId` can be replayed on a different chain.

### Finding Description
`getSignedPackageHashToSign()` hashes a stripped copy of the package (`signed_message`, `authors`, optional `last_ball_unit`, optional `version`) with no chain-identifying field: [1](#0-0) 

`signed_message.js#validateSignedMessage` explicitly allows the package to omit `last_ball_unit` (`bNetworkAware = ("last_ball_unit" in objSignedMessage)`), and when it is absent, verification falls back to a purely local, network-agnostic definition check with no reference to any unit/DAG/network state at all: [2](#0-1) 

`formula/evaluation.js`'s `is_valid_signed_package` op only optionally checks `last_ball_unit` if present, and otherwise proceeds straight to `signed_message.validateSignedMessage`: [3](#0-2) 

Since address derivation (`getChash160`) depends only on the definition array (e.g., `["sig", {pubkey}]`) and not on any network parameter, the same address/definition — and therefore the same signature over the same `signed_message` — is valid on every ocore-based deployment that shares this codebase (e.g., Obyte mainnet vs. testnet, or any other alt-network fork built from this base, or a different AA on the same network that happens to check for the same address). The bundled sample AAs (`test/samples/payment_channels.oscript`, `test/samples/order_book_exchange.oscript`) use `is_valid_signed_package(trigger.data.sentByPeer, address)` / `is_valid_signed_package(trigger.data.orderX, address)` as the *sole* cryptographic authorization for moving AA-held balances, and neither includes any chain- or AA-address-binding field inside the signed payload beyond what the app author manually adds: [4](#0-3) [5](#0-4) 

Because `getSignedPackageHashToSign` never mixes in a chain/genesis/`alt` identifier, and `last_ball_unit` binding is optional, a signed package crafted (and intended for use) on one ocore network/AA can be replayed verbatim on another network/AA that independently validates the identical `signed_message`/`authors` structure with `is_valid_signed_package`, exactly analogous to the reported `borrowHash` missing `chainid`.

### Impact Explanation
Where an AA developer relies on `is_valid_signed_package` as the authorization primitive for funds movement (payment channels, order books, off-chain-settled DEX/payment designs — all patterns explicitly shipped as reference samples in this repo), and does not independently embed a network-unique or AA-specific fully-qualifying value inside `signed_message` (e.g., they trust the "sig is valid for address X" check alone, or bind only to `this_address`/`period`, which can collide across differently-configured deployments of the same code that reuse address/definition spaces), an attacker can replay a legitimately-issued signature across a different network instance or a differently-deployed but structurally identical AA to force unauthorized state transitions/fund movement. Since `is_valid_signed_package` is exposed as a first-class oscript primitive precisely to build such fund-authorization logic, and the hash-to-sign contains no chain/network-binding value by design, this is a genuine "signature scheme fails to bind to the deployment context" flaw at the base-layer (`object_hash.js`/`signed_message.js`), not merely an application bug — every AA built with this idiom inherits the gap unless the developer manually re-implements chain-binding themselves.

### Likelihood Explanation
Requires that: (1) a compromising signature was generated for a legitimate purpose on one deployment/AA, and (2) an attacker can present the identical `signed_message`+`authors` structure to a second AA/network instance whose validation of `is_valid_signed_package` does not otherwise reject it (e.g., missing distinguishing fields like a network id, or address collision across networks sharing the address-derivation scheme). This is not automatically exploitable against every AA (many will embed a `channel`/`period`/AA-address inside `signed_message`, reducing but not eliminating replay across genuinely distinct deployments sharing derivation), but the base primitive itself provides zero chain-binding guarantee, matching the pattern flagged in the external report exactly (hash missing a network/chain distinguisher). Likelihood is Medium given it depends on application-level reuse patterns, but the root cause is squarely in the core signing/validation primitive.

### Recommendation
Bind `getSignedPackageHashToSign()` (and ideally `getUnitHashToSign`) to the specific network/genesis, e.g. include `constants.GENESIS_UNIT` (or `constants.alt`) in the hashed structure, similarly to how EVM's recommendation was to fold `block.chainid` into the hash:
```js
function getSignedPackageHashToSign(signedPackage) {
    var unsignedPackage = _.cloneDeep(signedPackage);
    for (var i=0; i<unsignedPackage.authors.length; i++)
        delete unsignedPackage.authors[i].authentifiers;
    unsignedPackage.genesis_unit = constants.GENESIS_UNIT; // bind to network
    ...
}
```
Additionally, consider making `last_ball_unit` (DAG-anchoring) mandatory for any `signed_message` consumed via `is_valid_signed_package`, since that is the mechanism that currently *does* implicitly prevent cross-network replay (a `last_ball_unit` from one DAG cannot exist on another).

### Proof of Concept
1. Generate an address/definition `["sig", {pubkey}]` and compute `address = getChash160(definition)`; this address is identical on every ocore deployment (mainnet/testnet/alt-fork) sharing this chash algorithm.
2. Sign a `signed_message` (e.g., `{channel: SHARED_AA_ADDRESS, period: 1, amount_spent: 100}`) without `last_ball_unit`, producing `signature = ecdsaSig.sign(getSignedPackageHashToSign(pkg), privKey)` per `signed_message.js:signMessage`.
3. Submit `pkg` as `trigger.data.sentByPeer` to an AA (deployed on a second network, or a second AA reusing the same address/definition space) whose oscript calls `is_valid_signed_package(trigger.data.sentByPeer, address)` exactly as in `test/samples/payment_channels.oscript:45` — validation succeeds because `getSignedPackageHashToSign` never encoded any chain/network-distinguishing value, and `last_ball_unit` was never required.
4. The second AA accepts the signature as valid authorization and executes the corresponding fund-moving state transition, even though the signature was never intended for that deployment. [1](#0-0) [6](#0-5)

### Citations

**File:** object_hash.js (L97-103)
```javascript
function getSignedPackageHashToSign(signedPackage) {
	var unsignedPackage = _.cloneDeep(signedPackage);
	for (var i=0; i<unsignedPackage.authors.length; i++)
		delete unsignedPackage.authors[i].authentifiers;
	var sourceString = (typeof signedPackage.version === 'undefined' || signedPackage.version === constants.versionWithoutTimestamp) ? getSourceString(unsignedPackage) : getJsonSourceString(unsignedPackage);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest();
}
```

**File:** signed_message.js (L28-41)
```javascript
function signMessage(message, from_address, signer, bNetworkAware, handleResult){
	if (typeof bNetworkAware === 'function') {
		handleResult = bNetworkAware;
		bNetworkAware = false;
	}
	var objAuthor = {
		address: from_address,
		authentifiers: {}
	};
	var objUnit = {
		version: constants.version,
		signed_message: message,
		authors: [objAuthor]
	};
```

**File:** signed_message.js (L193-253)
```javascript
	var bNetworkAware = ("last_ball_unit" in objSignedMessage);
	if (bNetworkAware && !ValidationUtils.isValidBase64(objSignedMessage.last_ball_unit, constants.HASH_LENGTH))
		return handleResult("invalid last_ball_unit");
	
	function validateOrReadDefinition(objAuthor, cb, bRetrying) {
		var bHasDefinition = ("definition" in objAuthor);
		if (bNetworkAware) {
			conn.query("SELECT main_chain_index, timestamp FROM units WHERE unit=?", [objSignedMessage.last_ball_unit], function (rows) {
				if (rows.length === 0) {
					var network = require('./network.js');
					if (!conf.bLight && !network.isCatchingUp() || bRetrying)
						return handleResult("last_ball_unit " + objSignedMessage.last_ball_unit + " not found");
					if (conf.bLight)
						network.requestHistoryFor([objSignedMessage.last_ball_unit], [objAuthor.address], function () {
							validateOrReadDefinition(objAuthor, cb, true);
						});
					else
						eventBus.once('catching_up_done', function () {
							// no retry flag, will retry multiple times until the catchup is over
							validateOrReadDefinition(objAuthor, cb);
						});
					return;
				}
				bRetrying = false;
				var last_ball_mci = rows[0].main_chain_index;
				var last_ball_timestamp = rows[0].timestamp;
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
					},
					ifFound: function (arrAddressDefinition) {
						if (bHasDefinition)
							return handleResult("should not include definition");
						cb(arrAddressDefinition, last_ball_mci, last_ball_timestamp);
					}
				});
			});
		}
		else {
			if (!bHasDefinition)
				return handleResult("no definition");
			try {
				if (objectHash.getChash160(objAuthor.definition) !== objAuthor.address)
					return handleResult("wrong definition: " + objectHash.getChash160(objAuthor.definition) + "!==" + objAuthor.address);
			} catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
			// no last_ball_unit of its own; before the fix, always behave as before (-1) to keep old units re-evaluating the same way
			cb(objAuthor.definition, (mci >= constants.pemCurvesFixMci) ? mci : -1, 0);
		}
	}
```

**File:** formula/evaluation.js (L1666-1699)
```javascript
					evaluate(signed_package_expr, async function (signedPackage) {
						if (fatal_error)
							return cb(false);
						if (!(signedPackage instanceof wrappedObject))
							return cb(false);
						signedPackage = signedPackage.obj;
						if (ValidationUtils.hasFieldsExcept(signedPackage, ['signed_message', 'last_ball_unit', 'authors', 'version']))
							return cb(false);
						if (signedPackage.version) {
							if (typeof signedPackage.version !== 'string')
								return cb(false);
							if (signedPackage.version === constants.versionWithoutTimestamp)
								return cb(false);
							const fVersion = parseFloat(signedPackage.version);
							const maxVersion = 4; // depends on mci in the future updates
							if (fVersion > maxVersion)
								return cb(false);
						}
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
						}
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
```

**File:** test/samples/payment_channels.oscript (L40-50)
```text
							if (trigger.data.sentByPeer){
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
								$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
								if ($transferredFromPeer < 0)
									bounce('bad amount spent by peer: ' || $transferredFromPeer);
							}
```

**File:** test/samples/order_book_exchange.oscript (L27-49)
```text
			{ // execute orders, order1 must be smaller or the same as order2; order2 is partially filled
				if: `{
					$order1 = trigger.data.order1.signed_message;
					$order2 = trigger.data.order2.signed_message;
					if (!$order1.sell_asset OR !$order2.sell_asset)
						return false;
					if ($order1.sell_asset != $order2.buy_asset OR $order1.buy_asset != $order2.sell_asset)
						return false;

					// to do check expiry

					$sell_key1 = 'balance_' || $order1.address || '_' || $order1.sell_asset;
					$sell_key2 = 'balance_' || $order2.address || '_' || $order2.sell_asset;

					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;
```
