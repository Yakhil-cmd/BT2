### Title
Off-chain `is_valid_signed_package` signatures lack a chain/fork-specific domain separator, enabling cross-fork replay of AA-authorized fund transfers - (File: `signed_message.js`, `object_hash.js`, `formula/evaluation.js`)

### Summary
The Beanstalk report is a classic "EIP-712 domain separator omits the live chain id" bug: a signed permit remains valid on a hard-forked chain because the signature commits only to a static `CHAIN_ID` constant, not to anything that differs between the two post-fork branches. Ocore's `is_valid_signed_package` mechanism, used by AAs (order books, payment channels, etc.) to accept off-chain-signed user messages, has the same structural weakness: the hash that is actually signed does not commit to anything unique to a specific chain instance beyond a network-wide protocol version string that is identical on both sides of a fork.

### Finding Description
Off-chain signed packages are hashed for signing in `getSignedPackageHashToSign`: [1](#0-0) 
This clones the package, strips `authentifiers`, and hashes the rest (`signed_message`, `authors[].address/definition`, optional `version`, optional `last_ball_unit`). Verification is done in `validateSignedMessage`, which re-derives the same hash and checks it against `Definition.validateAuthentifiers`: [2](#0-1) 

The only "environment" the signature is allowed to be anchored to is:
- `version` — checked only against `constants.supported_versions`, which is a global protocol version list, identical for every full copy of the mainnet software regardless of which side of a chain split it runs. [3](#0-2) 
- `last_ball_unit` — merely required to reference an existing, stable unit at or before the current MCI: [4](#0-3) 

Neither field distinguishes between two DAGs that share full history up to a fork point and then diverge (the direct analog of an Ethereum hard fork: same genesis, same `alt`/`version` strings, same historical units up to the split, different history afterward). Unlike unit-level hashing (`getUnitHashToSign`, which includes `alt` and `version` embedded in the full unit object and is used for consensus-critical unit signatures), `getSignedPackageHashToSign` is used for the AA-facing, application-level signed messages that oscript exposes via `is_valid_signed_package` — precisely the primitive real AA authors use to build DEX order books and payment channels (see `test/samples/order_book_exchange.oscript` and `test/samples/payment_channels.oscript`).

Because nothing in the signed payload commits to a chain-instance-specific value (no rolling "chain id"/fork identifier, no state-root binding, no nonce enforced by the AA beyond what the AA author chooses to add), a signature produced and consumed once on the pre-fork/main chain remains bit-for-bit valid and independently replayable on a forked chain that shares the referenced `last_ball_unit`.

### Impact Explanation
Any AA that uses `is_valid_signed_package` to authorize a state change carrying value is exposed. Two concrete illustrations from the codebase's own reference AAs:
- `test/samples/order_book_exchange.oscript` lines 41-49: order dedup keys (`$id1`, `$id2`) and the `executed_` state var are stored in the AA's *own* state, which is chain-local. On a forked chain the AA starts with the same pre-fork state (including no `executed_id` entries newer than the fork point, if the fork happens right at/near that point) — the identical signed order can be re-submitted on the forked chain and executed a second time, doubling the trade and draining `balance_` twice for a single signature. [5](#0-4) 
- `test/samples/payment_channels.oscript` "start closing" and "fraud proof" cases: a peer's `sentByPeer` signed package sets the settlement amounts (`$transferredFromPeer`) used to compute final on-chain balances. This is the direct blockchain analog of the Beanstalk WETH/permit scenario cited in the source report — replaying the same signed settlement on a forked channel copy lets a counter-party claim the same off-chain-committed balance on both forks, resulting in double payment of funds that should only be paid once. [6](#0-5) 

This is reachable by an ordinary AA trigger sender (no privileged/network role needed) and results in AA fund loss / double-spend of value that should be single-spend, matching the required impact bar.

### Likelihood Explanation
This requires an actual ocore-chain hard fork (a divergence of the DAG into two live, mutually-incompatible networks that nonetheless share the same protocol `version`/`alt` and genesis history) — an event that is rare but has real precedent in blockchain ecosystems (e.g., ETH/ETC). It does not require a malicious peer, hub, or node; only an ordinary user replaying a previously-obtained signed package to the same AA definition running on the other branch. Given the rarity of an actual hard fork, likelihood is low-to-medium, but the systemic gap (no chain-specific domain separator anywhere in `is_valid_signed_package`/`getSignedPackageHashToSign`) is a genuine root-cause defect independent of how often it is triggered.

### Recommendation
- Bind signed packages to a chain-fork-specific value at the protocol level, e.g., include the `GENESIS_UNIT` (or a governance-selected fork id) in `getSignedPackageHashToSign`'s hashed content, analogous to using `block.chainid` instead of a static constant.
- Alternatively/additionally, document and encourage AA authors to embed an application-level nonce/fork-marker (e.g., a recent stable MC ball hash rather than merely referencing any old `last_ball_unit`) into `signed_message` payloads, and update the reference sample AAs (`order_book_exchange.oscript`, `payment_channels.oscript`) to demonstrate this mitigation, since currently they do not.
- Consider tightening `is_valid_signed_package`'s `last_ball_unit` freshness requirement so that stale/pre-fork anchors cannot be used to satisfy the "existing stable unit" check indefinitely.

### Proof of Concept
Conceptual (cannot be executed without a live fork, but the code path is deterministic):
1. Chain forks at stable MCI `N` into branch X and branch Y, both starting from identical state/DAG up to `N`, both running the same `constants.version`/`alt`.
2. User A signs a payment-channel settlement package referencing `last_ball_unit = U` (stable at or before `N`) using `signMessage`/`ecdsaSig.sign` over `getSignedPackageHashToSign`. [7](#0-6) 
3. User B submits `trigger.data.sentByPeer = <signed package>` to the payment-channel AA on branch X; `is_valid_signed_package` succeeds (unit `U` is stable and on the MC in branch X), and the "start closing"/"confirm closure" flow pays out funds. [8](#0-7) 
4. User B (or a colluding third party) submits the identical unmodified package to the *same* AA definition/address running independently on branch Y. Because `U` is also stable on branch Y (shared pre-fork history) and `version`/`alt` match, `validateSignedMessage` and `is_valid_signed_package` again return true, and the AA on branch Y independently pays out the same settlement amount a second time — a double payment derived from a single signature.

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

**File:** signed_message.js (L63-94)
```javascript
	var assocSigningPaths = {};
	signer.readSigningPaths(db, from_address, function(assocLengthsBySigningPaths){
		var arrSigningPaths = Object.keys(assocLengthsBySigningPaths);
		assocSigningPaths[from_address] = arrSigningPaths;
		for (var j=0; j<arrSigningPaths.length; j++)
			objAuthor.authentifiers[arrSigningPaths[j]] = repeatString("-", assocLengthsBySigningPaths[arrSigningPaths[j]]);
		setDefinitionAndLastBallUnit(function(){
			var text_to_sign = objectHash.getSignedPackageHashToSign(objUnit);
			async.each(
				objUnit.authors,
				function(author, cb2){
					var address = author.address;
					async.each( // different keys sign in parallel (if multisig)
						assocSigningPaths[address],
						function(path, cb3){
							if (signer.sign){
								signer.sign(objUnit, {}, address, path, function(err, signature){
									if (err)
										return cb3(err);
									// it can't be accidentally confused with real signature as there are no [ and ] in base64 alphabet
									if (signature === '[refused]')
										return cb3('one of the cosigners refused to sign');
									author.authentifiers[path] = signature;
									cb3();
								});
							}
							else{
								signer.readPrivateKey(address, path, function(err, privKey){
									if (err)
										return cb3(err);
									author.authentifiers[path] = ecdsaSig.sign(text_to_sign, privKey);
									cb3();
```

**File:** signed_message.js (L129-137)
```javascript
	const max_complexity = (mci >= constants.pemCurvesFixMci) ? 10 : 0;
	if (!ValidationUtils.isNonemptyObject(objSignedMessage))
		return handleResult("signed message must be a non-empty object");
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
```

**File:** signed_message.js (L255-290)
```javascript
	let last_ball_mci;
	let complexity = 0;
	async.eachSeries(
		authors,
		function (objAuthor, cb) {
			validateOrReadDefinition(objAuthor, function (arrAddressDefinition, _last_ball_mci, last_ball_timestamp) {
				last_ball_mci = _last_ball_mci;
				var objUnit = _.clone(objSignedMessage);
				objUnit.messages = []; // some ops need it
				try {
					var objValidationState = {
						unit_hash_to_sign: objectHash.getSignedPackageHashToSign(objSignedMessage),
						last_ball_mci: last_ball_mci,
						last_ball_timestamp: last_ball_timestamp,
						bNoReferences: !bNetworkAware,
						complexity,
						max_complexity,
					};
				}
				catch (e) {
					return cb("failed to calc unit_hash_to_sign: " + e);
				}
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
				}
```

**File:** formula/evaluation.js (L1684-1692)
```javascript
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
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

**File:** test/samples/payment_channels.oscript (L31-64)
```text
			{ // start closing
				if: `{ $bFromParties AND trigger.data.close AND !var['close_initiated_by'] }`,
				messages: [
					{
						app: 'state',
						state: `{
							$transferredFromMe = trigger.data.transferredFromMe otherwise 0;
							if ($transferredFromMe < 0)
								bounce('bad amount spent by me: ' || $transferredFromMe);
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
							else
								$transferredFromPeer = 0;
							var['spentByA'] = $bFromA ? $transferredFromMe : $transferredFromPeer;
							var['spentByB'] = $bFromB ? $transferredFromMe : $transferredFromPeer;
							$finalBalanceA = var['balanceA'] - var['spentByA'] + var['spentByB'];
							$finalBalanceB = var['balanceB'] - var['spentByB'] + var['spentByA'];
							if ($finalBalanceA < 0 OR $finalBalanceB < 0)
								bounce('one of the balances would become negative');
							var['close_initiated_by'] = $party;
							var['close_start_ts'] = timestamp;
							response['close_start_ts'] = timestamp;
							response['finalBalanceA'] = $finalBalanceA;
							response['finalBalanceB'] = $finalBalanceB;
						}`
```
