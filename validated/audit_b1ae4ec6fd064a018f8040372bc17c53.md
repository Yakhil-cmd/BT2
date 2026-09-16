Based on my investigation, I found a strong analog to the ChainSwap lock-and-drain bug class in the payment-channel style AA custody pattern, which relies on `is_valid_signed_package()`/PEM-key signature verification to release locked funds — structurally the same "asset is locked in a contract, released upon a cryptographic proof" pattern as Dora Factory's bridge.

### Title
Payment-channel / custody AA fund release relies on `is_valid_signed_package` whose underlying PEM-key curve validation is only enforced post-`pemCurvesFixMci`, allowing forged peer signatures to drain locked balances on unpatched deployments - (File: `formula/evaluation.js`, `signature.js`)

### Summary
`test/samples/payment_channels.oscript` implements a two-party payment channel: users lock base-asset funds into the AA [1](#0-0) , and later close the channel by presenting a peer-signed message proving the counterparty agreed to a new balance split, verified via `is_valid_signed_package(trigger.data.sentByPeer, ...)` [2](#0-1) . This exactly mirrors the ChainSwap custody pattern where an off-chain-authorized message unlocks on-chain locked value; the only barrier to fund extraction is the strength of the signature-verification primitive.

### Finding Description
`is_valid_signed_package` ultimately calls `signed_message.validateSignedMessage` → `Definition.validateAuthentifiers` → the `sig`/PEM verification path [3](#0-2) . For PEM-based signatures, `verifyMessageWithPemPubKey` dispatches to either a hardened secp256k1-only path or a generic OpenSSL `crypto.createVerify` path depending on `bPostPemCurvesFix` [4](#0-3) . The curve safety allowlist (`objSafePemTypes`) that restricts keys to non-exploitable curves is likewise gated by `bPostPemCurvesFix` [5](#0-4) ; before this fix MCI, any of the ~30 curves in `objSupportedPemTypes` — including weak/legacy curves like `secp112r1`, `secp128r1`, brainpool variants, etc. — are accepted for `is_valid_sig`/`is_valid_signed_package` [6](#0-5) . Weak-curve ECDSA keys are subject to known discrete-log/curve-confusion attacks, letting an attacker forge a valid-looking signature for a chosen peer address/message without possessing the private key. In the payment-channel AA, that forged "peer-signed" message directly controls the accepted `amount_spent` used to compute the released balances [7](#0-6) , i.e., an attacker forging a peer signature can bias the channel close to award themselves the counterparty's locked funds — the same "cryptographic-authorization bypass drains locked funds" bug class as the ChainSwap incident.

### Impact Explanation
If exploited before `pemCurvesFixMci` (or on any deployment/AA still relying on non-allowlisted curves for `is_valid_sig`/`is_valid_signed_package`), an attacker could forge a counterparty signature and cause a custody-style AA (payment channel, order-book exchange, or any oscript that gates fund release on `is_valid_sig`/`is_valid_signed_package`) to release funds that were never authorized by their true owner — direct unauthorized spending / AA fund loss, matching the "concrete unauthorized spending" bar in the validation rules.

### Likelihood Explanation
Exploitation requires (a) an AA author choosing to accept a PEM public key/curve that is not in the hardened `objSafePemTypes` set for authorizing fund release, and (b) the network being at an MCI before the `pemCurvesFixMci` upgrade (or the fix flag not applied), and (c) practical cryptanalysis of the specific weak curve to forge a signature. This is a real, unprivileged-reachable path (any unit poster can submit a trigger containing a crafted `signed_package`), but likelihood is moderated by the fact that the safe-curve allowlist was already introduced as a fix, and most production AAs use `sig`/secp256k1, not arbitrary PEM curves.

### Recommendation
Enforce the `objSafePemTypes` curve allowlist unconditionally (not gated by `bPostPemCurvesFix`) for all `validateAndFormatPemPubKey` calls reachable from `is_valid_sig`/`is_valid_signed_package`, and reject legacy/weak curves regardless of MCI so historical/backwards-compatibility branches cannot be abused to authorize fund release in custody-style AAs.

### Proof of Concept
1. Deploy an AA modeled on `test/samples/payment_channels.oscript`, but configure the "peer" identity with an address whose definition uses `['is_valid_sig', ...]` or `is_valid_signed_package` verification against a PEM public key using a non-`objSafePemTypes` curve (e.g., `secp112r1`), while the network MCI is below `pemCurvesFixMci`.
2. Attacker (not holding the real peer's private key) performs a curve-specific cryptanalytic attack against the weak curve to derive a forged signature over a `signed_message` claiming a favorable `amount_spent`.
3. Attacker submits `trigger.data.close` with a crafted `sentByPeer` signed package containing the forged signature.
4. `is_valid_signed_package` returns `true` via `verifyMessageWithPemPubKey` (generic OpenSSL path, curve not blocked pre-fix) [4](#0-3) , the AA accepts the forged `$transferredFromPeer`, and computes/pays out `$finalBalanceA`/`$finalBalanceB` in the attacker's favor [8](#0-7) .

Note: I could not fully verify the practical exploitability of each specific weak curve (i.e., confirm a concrete forgery is computationally feasible for every curve in `objSupportedPemTypes`) within the scope of this review — that would require deeper cryptographic analysis outside static code reading. This is flagged as uncertain.

### Citations

**File:** test/samples/payment_channels.oscript (L14-29)
```text
			{ // refill the AA
				if: `{ $bFromParties AND trigger.output[[asset=base]] >= 1e5 }`,
				messages: [
					{
						app: 'state',
						state: `{
							if (var['close_initiated_by'])
								bounce('already closing');
							if (!var['period'])
								var['period'] = 1;
							$key = 'balance' || $party;
							var[$key] += trigger.output[[asset=base]];
							response[$key] = var[$key];
						}`
					}
				]
```

**File:** test/samples/payment_channels.oscript (L40-63)
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
```

**File:** formula/evaluation.js (L1653-1699)
```javascript
			case 'is_valid_signed_package':
				if (!objValidationState.count_signed_packages)
					objValidationState.count_signed_packages = 0;
				if (objValidationState.count_signed_packages >= constants.MAX_SIGNED_PACKAGES_PER_AA_EVAL && bPostPemCurvesFix)
					return setFatalError("too many signed packages in evaluation", { arr }, false, cb);
				objValidationState.count_signed_packages++;
				var signed_package_expr = arr[1];
				var address_expr = arr[2];
				evaluate(address_expr, function (evaluated_address) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isValidAddress(evaluated_address))
						return setFatalError("bad address in is_valid_signed_package: " + evaluated_address, { arr }, false, cb);
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

**File:** signature.js (L27-48)
```javascript
function verifyMessageWithPemPubKey(message, signature, pem_key, bPostPemCurvesFix) {
	var contentB64 = pem_key
		.replace("-----BEGIN PUBLIC KEY-----", "")
		.replace("-----END PUBLIC KEY-----", "")
		.replace(/\s/g, "");
	var der = Buffer.from(contentB64, 'base64');
	var algIdStart = der[1] <= 0x7F ? 4 : der[1] === 0x81 ? 5 : der[1] === 0x82 ? 6 : -1;
	if (algIdStart >= 0 && der.slice(algIdStart, algIdStart + SECP256K1_ALG_ID.length).equals(SECP256K1_ALG_ID)
			&& bPostPemCurvesFix)
		return verifyMessageWithSecp256k1PemPubKey(message, signature, der);

	var verify = crypto.createVerify('SHA256');
	verify.update(message);
	verify.end();
	var encoding = ValidationUtils.isValidHexadecimal(signature) ? 'hex' : 'base64';
	try {
		return verify.verify({key: pem_key}, signature, encoding);
	} catch(e) {
		console.log("exception when verifying with pem key: " + e);
		return false;
	}
}
```

**File:** signature.js (L170-171)
```javascript
	if (bPostPemCurvesFix && !objSafePemTypes.has(typeIdentifiersHex))
		return handle("unsupported curve after pem curves fix MCI");
```

**File:** signature.js (L192-389)
```javascript
var objSafePemTypes = new Set([
	'06072a8648ce3d020106082a8648ce3d030107', // prime256v1 (P-256)
	'06072a8648ce3d020106052b81040021',        // secp224r1  (P-224)
	'06072a8648ce3d020106052b81040022',        // secp384r1  (P-384)
	'06072a8648ce3d020106052b8104000a',        // secp256k1  (verified via secp256k1 npm, not OpenSSL)
	'06092a864886f70d0101010500',              // RSA (PKCS #1)
]);

var objSupportedPemTypes = {
	'06072a8648ce3d020106092b2403030208010101': {
		name: 'brainpoolP160r1',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010102': {
		name: 'brainpoolP160t1',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010103': {
		name: 'brainpoolP192r1',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010104': {
		name: 'brainpoolP192t1',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010105': {
		name: 'brainpoolP224r1',
		hex_pub_key_length: 112,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010106': {
		name: 'brainpoolP224t1',
		hex_pub_key_length: 112,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010107': {
		name: 'brainpoolP256r1',
		hex_pub_key_length: 128,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010108': {
		name: 'brainpoolP256t1',
		hex_pub_key_length: 128,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106082a8648ce3d030101': {
		name: 'prime192v1',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106082a8648ce3d030102': {
		name: 'prime192v2',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106082a8648ce3d030103': {
		name: 'prime192v3',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106082a8648ce3d030104': {
		name: 'prime239v1',
		hex_pub_key_length: 120,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106082a8648ce3d030105': {
		name: 'prime239v2',
		hex_pub_key_length: 120,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106082a8648ce3d030106': {
		name: 'prime239v3',
		hex_pub_key_length: 120,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106082a8648ce3d030107': {
		name: 'prime256v1',
		hex_pub_key_length: 128,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040006': {
		name: 'secp112r1',
		hex_pub_key_length: 56,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040007': {
		name: 'secp112r2',
		hex_pub_key_length: 56,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b8104001c': {
		name: 'secp128r1',
		hex_pub_key_length: 64,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b8104001d': {
		name: 'secp128r2',
		hex_pub_key_length: 64,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040009': {
		name: 'secp160k1',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040008': {
		name: 'secp160r1',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b8104001e': {
		name: 'secp160r2',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b8104001f': {
		name: 'secp192k1',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040020': {
		name: 'secp224k1',
		hex_pub_key_length: 112,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040021': {
		name: 'secp224r1',
		hex_pub_key_length: 112,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b8104000a': {
		name: 'secp256k1',
		hex_pub_key_length: 128,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040022': {
		name: 'secp384r1',
		hex_pub_key_length: 192,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040004': {
		name: 'sect113r1',
		hex_pub_key_length: 60,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040005': {
		name: 'sect113r2',
		hex_pub_key_length: 60,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040016': {
		name: 'sect131r1',
		hex_pub_key_length: 68,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106052b81040017': {
		name: 'sect131r2',
		hex_pub_key_length: 68,
		algo: 'ECDSA'
	},
	'06072a8648ce3d02010605672b010401': {
		name: 'wap-wsg-idm-ecid-wtls1',
		hex_pub_key_length: 60,
		algo: 'ECDSA'
	},
	'06072a8648ce3d02010605672b010404': {
		name: 'wap-wsg-idm-ecid-wtls4',
		hex_pub_key_length: 60,
		algo: 'ECDSA'
	},
	'06072a8648ce3d02010605672b010406': {
		name: 'wap-wsg-idm-ecid-wtls6',
		hex_pub_key_length: 56,
		algo: 'ECDSA'
	},
	'06072a8648ce3d02010605672b010407': {
		name: 'wap-wsg-idm-ecid-wtls7',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d02010605672b010408': {
		name: 'wap-wsg-idm-ecid-wtls8',
		hex_pub_key_length: 56,
		algo: 'ECDSA'
	},
	'06072a8648ce3d02010605672b010409': {
		name: 'wap-wsg-idm-ecid-wtls9',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06092a864886f70d0101010500':{
		name: 'PKCS #1',
		algo: 'RSA'
	}
```
