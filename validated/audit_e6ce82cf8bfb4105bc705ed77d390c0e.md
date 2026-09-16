No vulnerability found for this question.

The CGGMP21 advisory concerns a missing check in a zero-knowledge proof used within a specific threshold-ECDSA MPC protocol (Paillier-based key generation/presigning), where a malicious co-signer can reconstruct the full private key by exploiting an unchecked ZK proof component. `ocore` (Obyte core) has no analogous cryptographic construct: its multisig ("r of set" address definitions) requires each cosigner to hold an independent, complete ECDSA keypair and produce an ordinary signature — there is no distributed/threshold key generation, no Paillier encryption, and no ZK proof of knowledge of key shares anywhere in the codebase. [1](#0-0) [2](#0-1) [3](#0-2) 

The closest "proof verification" logic in ocore is `is_valid_sig`/`vrf_verify` (PEM-key ECDSA/RSA signature and VRF verification) and `is_valid_merkle_proof` (simple hash-chain inclusion proof), none of which involve multi-party ZK proofs of Paillier plaintext properties or threshold key reconstruction. [4](#0-3) [5](#0-4) 

No unprivileged unit poster, AA author/trigger sender, asset issuer, private-payment counterparty, or paired device can reach any code path in `ocore` that resembles the missing-ZK-proof-check bug class from the advisory (no threshold MPC key generation exists in this codebase to exploit).

### Citations

**File:** wallet_defined_by_keys.js (L260-266)
```javascript
function createMultisigWallet(xPubKey, account, count_required_signatures, arrDeviceAddresses, walletName, isSingleAddress, handleWallet){
	if (count_required_signatures > arrDeviceAddresses.length)
		throw Error("required > length");
	var set = arrDeviceAddresses.map(function(device_address){ return ["sig", {pubkey: '$pubkey@'+device_address}]; });
	var arrDefinitionTemplate = ["r of set", {required: count_required_signatures, set: set}];
	createWallet(xPubKey, account, arrDefinitionTemplate, walletName, isSingleAddress, handleWallet);
}
```

**File:** composer.js (L551-579)
```javascript
			let authors_for_signing = [ ...objUnit.authors ];
			// multisigs come first to request their signatures from peers earlier, so that the peer sees the shared address as signer first and caches the response
			authors_for_signing.sort((a, b) => (Object.keys(b.authentifiers).length - Object.keys(a.authentifiers).length)); // descending by number of signatures
			async.each(
				authors_for_signing,
				function(author, cb2){
					var address = author.address;
					async.each( // different keys sign in parallel (if multisig)
						Object.keys(author.authentifiers),
						function(path, cb3){
							if (signer.sign){
								signer.sign(objUnit, assocPrivatePayloads, address, path, function(err, signature){
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
								});
							}
```

**File:** signature.js (L16-25)
```javascript
function verify(hash, b64_sig, b64_pub_key){
	try{
		var signature = Buffer.from(b64_sig, "base64"); // 64 bytes (32+32)
		return ecdsa.ecdsaVerify(signature, hash, Buffer.from(b64_pub_key, "base64"));
	}
	catch(e){
		console.log('signature verification exception: '+e.toString());
		return false;
	}
};
```

**File:** merkle.js (L84-102)
```javascript
function verifyMerkleProof(element, proof){
	// Node-as-Leaf issue might matter in some cases
	try {
		var index = proof.index;
		var the_other_sibling = hash(element);
		for (var i = 0; i < proof.siblings.length; i++) {
			// this also works for duplicated trailing nodes
			if (index % 2 === 0)
				the_other_sibling = hash(the_other_sibling + proof.siblings[i]);
			else
				the_other_sibling = hash(proof.siblings[i] + the_other_sibling);
			index = Math.floor(index / 2);
		}
		return (the_other_sibling === proof.root);
	}
	catch (e){
		return false;
	}
}
```

**File:** formula/evaluation.js (L1704-1734)
```javascript
			case 'is_valid_sig':
				var message = arr[1];
				var pem_key = arr[2];
				var sig = arr[3];
				evaluate(message, function (evaluated_message) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isNonemptyString(evaluated_message))
						return setFatalError("bad message string in is_valid_sig", { arr }, false, cb);
					evaluate(sig, function (evaluated_signature) {
						if (fatal_error)
							return cb(false);
						if (!ValidationUtils.isNonemptyString(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
						if (evaluated_signature.length > 1024)
							return setFatalError("signature is too large", { arr }, false, cb);
						if (!ValidationUtils.isValidHexadecimal(evaluated_signature) && !ValidationUtils.isValidBase64(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
						evaluate(pem_key, function (evaluated_pem_key) {
							if (fatal_error)
								return cb(false);
							signature.validateAndFormatPemPubKey(evaluated_pem_key, "any", function (error, formatted_pem_key){
								if (error)
									return setFatalError("bad PEM key in is_valid_sig: " + error, { arr }, false, cb);
								var result = signature.verifyMessageWithPemPubKey(evaluated_message, evaluated_signature, formatted_pem_key, bPostPemCurvesFix);
								return cb(result);
							}, bPostPemCurvesFix);
						});
					});
				});
				break;
```
