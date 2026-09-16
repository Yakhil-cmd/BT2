### Title
Attested-address definitions and asset spender-attestation checks never account for attestation revocation - ([File: storage.js])

### Summary
The `attested` address-definition primitive and the `spender_attested` asset-transfer restriction both rely on `filterAttestedAddresses()` [1](#0-0)  to decide whether an address is currently "attested" by a set of trusted attestor addresses. The query only checks for the *existence* of any past attestation record for the address (bounded only by the address's most recent `address_definition_change`), never for whether that attestation is still the attestor's current/valid statement. There is no revocation mechanism: once an attestor has posted a single `attestation` message for an address, that address is treated as permanently attested for as long as the address keeps the same definition — exactly analogous to CVE-2014-5253, where Keystone kept honoring domain-scoped tokens after the domain (the authorizing scope) was invalidated.

### Finding Description
`filterAttestedAddresses` is used both by the oscript/definition evaluator for the `attested` operator [2](#0-1)  and by the asset engine to gate transfers of `spender_attested` assets [3](#0-2) . Its SQL is:

```
SELECT DISTINCT address FROM attestations CROSS JOIN units USING(unit)
WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good'
    AND main_chain_index>IFNULL(
        (SELECT main_chain_index FROM address_definition_changes JOIN units USING(unit)
        WHERE address_definition_changes.address=attestations.address AND main_chain_index<=? AND is_stable=1 AND sequence='good' ORDER BY main_chain_index DESC LIMIT 1),
    0)
``` [4](#0-3) 

This query is a pure existence check: it returns the address as "attested" as soon as *any* single, still-stable attestation unit from a trusted attestor exists after the address's last definition change. The `attestation` message itself has no expiry, status, or revocation field — validation of the `attestation` message only checks that the payload has a valid address and a non-empty profile object [5](#0-4) . There is no code path anywhere that removes, supersedes, or otherwise revokes a previously-issued attestation record short of the attested address changing its definition (an action fully controlled by the *attested party*, not the attestor). If the attestor wants to revoke trust in an address (e.g., after a KYC failure, fraud detection, lost 2FA device, or expired credential), it has no way to retract the earlier attestation from the perspective of `attested`/`spender_attested` checks — the old attestation unit is immutable and permanently satisfies the "exists" condition, just as Keystone kept validating domain-scoped tokens issued before a domain was disabled.

### Impact Explanation
Any oscript/AA definition, asset, or standard address definition that uses `['attested', [address, [attestor,...]]]` to gate spending or authorization (e.g. KYC-restricted `spender_attested` assets, or multisig/2FA-style conditions requiring "attested by trusted service") continues to treat a previously-attested address as trusted forever, even after the attestor's real-world basis for attestation is revoked. This can allow:
- Continued spending/transfer authority over `spender_attested` assets by an address whose KYC/verification the attestor intended to revoke.
- Bypassing conditions in AA-based or contract-based address definitions that rely on `attested` as an access-control gate, because the condition is satisfied by stale, no-longer-valid attestations.

This maps to concrete unauthorized spending / access authorized by a stale, supposedly-revoked credential, consistent with the required impact classes (unauthorized spending / AA fund control based on invalid trust state).

### Likelihood Explanation
This is reachable by any unprivileged party who simply continues to hold an address that was attested in the past — no attacker action beyond normal usage is required, and the condition triggers automatically for any asset issuer, AA author, or address-definition author who relies on `attested`/`spender_attested`. The only requirement is that an attestor issued at least one attestation and later wants (or needs) to revoke it, which is a common real-world scenario (KYC providers, 2FA/device-attestation providers, whitelisting services). Because there's no protocol-level revocation primitive, this is a structural gap rather than a narrow edge case, making exploitation trivial once an attestor's off-chain trust decision changes.

### Recommendation
Introduce an explicit revocation mechanism for attestations, analogous to fixing token domain revocation in Keystone: e.g., support a "revocation" attestation message/flag from the same attestor that supersedes prior attestations for that address, and change `filterAttestedAddresses` to select only the *latest* attestation record per (attestor, address) pair and require that its content indicates a valid (non-revoked) status, rather than a mere existence check. Alternatively, require attestations to carry an explicit expiry and have `filterAttestedAddresses` filter on `mci <= max_mci AND (no revocation newer than this attestation)`.

### Proof of Concept
1. Attestor `A` posts an `attestation` message attesting address `X` (e.g., KYC-verified) — accepted per validation rules in `validateInlinePayload` [5](#0-4) .
2. An asset is defined with `spender_attested: true` and `arrAttestorAddresses = [A]`; `X` can now transfer/spend it because `filterAttestedAddresses` finds the attestation row [1](#0-0) .
3. Attestor `A` later determines `X` should no longer be trusted (fraud, KYC revoked, device lost) and has no on-chain means to retract the original attestation record.
4. `X` keeps its address definition unchanged (no `address_definition_change`), so the `main_chain_index > IFNULL(last_definition_change_mci, 0)` condition remains satisfied by the original attestation forever.
5. `X` continues to pass the `attested` check indefinitely and can keep spending/transferring the gated asset or satisfying any address-definition condition relying on this attestor, despite the attestor's intent to revoke trust — mirroring the unrevoked domain-scoped token issue in the reference CVE.

### Citations

**File:** storage.js (L1959-1974)
```javascript
// filter only those addresses that are attested (doesn't work for light clients)
function filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAddresses, handleAttestedAddresses){
	conn.query(
		"SELECT DISTINCT address FROM attestations CROSS JOIN units USING(unit) \n\
		WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good' \n\
			AND main_chain_index>IFNULL( \n\
				(SELECT main_chain_index FROM address_definition_changes JOIN units USING(unit) \n\
				WHERE address_definition_changes.address=attestations.address AND main_chain_index<=? AND is_stable=1 AND sequence='good' ORDER BY main_chain_index DESC LIMIT 1), \n\
			0)",
		[objAsset.arrAttestorAddresses, arrAddresses, last_ball_mci, last_ball_mci],
		function(addr_rows){
			var arrAttestedAddresses = addr_rows.map(function(addr_row){ return addr_row.address; });
			handleAttestedAddresses(arrAttestedAddresses);
		}
	);
}
```

**File:** storage.js (L1976-1991)
```javascript
// note that light clients cannot check attestations
function loadAssetWithListOfAttestedAuthors(conn, asset, last_ball_mci, arrAuthorAddresses, bAcceptUnconfirmedAA, handleAsset){
	if (arguments.length === 5) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, function(err, objAsset){
		if (err)
			return handleAsset(err);
		if (!objAsset.spender_attested)
			return handleAsset(null, objAsset);
		filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAuthorAddresses, function(arrAttestedAddresses){
			objAsset.arrAttestedAddresses = arrAttestedAddresses;
			handleAsset(null, objAsset);
		});
	});
```

**File:** definition.js (L904-915)
```javascript
			case 'attested':
				// ['attested', ['BASE32', ['BASE32']]]
				var attested_address = args[0];
				var arrAttestors = args[1];
				if (attested_address === 'this address')
					attested_address = address;
				storage.filterAttestedAddresses(
					conn, {arrAttestorAddresses: arrAttestors}, objValidationState.last_ball_mci, [attested_address], function(arrFilteredAddresses){
						cb2(arrFilteredAddresses.length > 0);
					}
				);
				break;
```

**File:** validation.js (L2011-2024)
```javascript
		case "attestation":
			if (objUnit.authors.length !== 1)
				return callback("attestation must be single-authored");
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "profile"]))
				return callback("unknown fields in "+objMessage.app);
			if (!isValidAddress(payload.address))
				return callback("attesting an invalid address");
			if (!isNonemptyObject(payload.profile))
				return callback("attested profile must be non empty object");
			// it is ok if the address has never been used yet
			// it is also ok to attest oneself
			return callback();
```
