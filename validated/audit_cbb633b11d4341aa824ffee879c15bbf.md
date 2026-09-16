I found a genuine analog: `spender_attested` assets combined with the `attested` definition condition create the exact same griefing pattern described in the bug report — a state that is checked only at the moment of a *specific* action, but where an unrelated third party can flip that state against the holder's will with no way to prevent it, causing fund freezing. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Transfer-condition/attestation revocation can retroactively freeze already-held asset balances without holder consent - (File: validation.js, storage.js)

### Summary
For `spender_attested` assets, ocore checks whether the **current** output owner is on the attestor's live attestation list at validation time, rather than checking attestation status only once (at receipt time) and then letting the holder freely move funds afterward. Any unprivileged third party — the asset's attestor (which for many community-run assets is not the holder) — can post a new `attestation`/`asset_attestors` message that removes an address from the attested list. This is analogous to the RewardsEngine bug: a state flag ("attested"/"eligible") that governs a right (spendability of already-owned funds) is re-evaluated dynamically based on external actions the holder cannot control, and any qualifying inflow the holder already legitimately received can retroactively become frozen because of an action unrelated to that specific inflow.

### Finding Description
When validating a payment of a `spender_attested` asset, `validatePaymentInputsAndOutputs` re-checks, for every input being spent, whether the *current* owner address is still on the attestor's attested list, using `objAsset.arrAttestedAddresses` computed from the asset's attestor list as of `last_ball_mci`:

```js
if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
    return cb("owner address is not attested");
``` [1](#0-0) 

The attested-address list itself is derived by `storage.filterAttestedAddresses`, which looks at the most recent `attestations` message from any of the trusted attestors, gated only by `main_chain_index<=last_ball_mci`:

```js
"SELECT DISTINCT address FROM attestations CROSS JOIN units USING(unit) \n\
WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good' \n\
    AND main_chain_index>IFNULL( \n\
        (SELECT main_chain_index FROM address_definition_changes ... ), 0)"
``` [4](#0-3) 

There is no requirement that the holder was attested *at the time they received the funds* — the check is a live, continuously re-evaluated condition. An attestor (which is a role distinct from "asset issuer" and can be operated by anyone the issuer designates, and in many real assets is a semi-automated oracle) posting a routine re-attestation cycle, an accidental omission, or a targeted revocation of one address, instantly makes every unspent output previously sent to that address unspendable — including outputs the holder received and held long before the revocation, with no window or checkpoint logic protecting already-legitimately-acquired balances. Because attestor units are ordinary units postable by an unprivileged address holding the attestor key (not requiring cooperation of the asset holder or definer), and the resulting effect ("not attested" -> permanently blocks all future spends of currently held outputs until re-attested) is unconditional and outside the holder's control, this mirrors the "any state-changing external event, regardless of intent, forces an unwanted status flip with no recourse for the affected party" root cause in the original report. The same `owner address is not attested` check is duplicated for private fixed-denomination inputs and public inputs alike. [5](#0-4) 

### Impact Explanation
This causes AA fund freezing / denial of ability to spend legitimately-held asset balances: any holder of a `spender_attested` asset can have their entire held balance of that asset frozen at any time by an action of the attestor (revocation, list rewrite omitting them, or even list-format errors), independent of when or how they acquired the funds. Because the check is enforced for every subsequent spend of that output, this is a persistent denial-of-service on those specific funds rather than a one-time validation failure, and it can be weaponized to selectively freeze specific addresses' balances if the attestor colludes with, or is itself, an adversary, or simply refreshes its attestor list without including a targeted address.

### Likelihood Explanation
Likelihood is Medium: exploitation requires control of, or collusion with, the attestor role for that specific asset (an unprivileged-but-trusted party distinct from the asset holder). This is a normal, expected actor in the `spender_attested` asset model (asset issuer, per rules), and re-publishing the attestor list or attestation set is an ordinary, permissionless action (`asset_attestors`/`attestation` messages), requiring no cooperation from the affected holder and no special privileges beyond already holding the attestor key that the asset itself designates as trusted.

### Recommendation
Decouple "was I allowed to receive this specific output" from "am I currently attested." Snapshot attestation status at the time the output is created (similar to how RewardsEngine now separates late inflow accounting from ongoing eligibility), so that a subsequent revocation only prevents *new* transfers involving that address but does not retroactively freeze outputs the holder already validly received while attested. Alternatively, require an explicit unbonding/quarantine period before revocation takes effect, and clearly document to asset issuers that spender-attested assets are not "held funds are always spendable" and depend on continuous attestor cooperation.

### Proof of Concept
1. An asset issuer creates asset `X` with `spender_attested: true` and attestor `A`.
2. Attestor `A` posts an `attestation` message attesting address `V` (victim). `V` receives a large amount of asset `X` and holds it — fully validated per current rules since `V` was attested at receipt time via `validatePayment`'s issuer/attested checks. See `validatePayment`'s `spender_attested` handling: ` [6](#0-5) `.
3. Time passes; `V` still holds the same unspent output(s).
4. Attestor `A` posts a new `asset_attestors`/`attestation` update that no longer lists `V` (e.g., routine refresh, mistake, or targeted action) — this requires no cooperation from `V` or the asset definer.
5. `V` attempts to spend the previously-received, previously-valid output. `filterAttestedAddresses` (per `storage.js:1960-1974`) no longer returns `V`, so `validatePaymentInputsAndOutputs` rejects the spend with `"owner address is not attested"` (`validation.js:2506`), permanently freezing `V`'s funds until re-attested by a party `V` does not control — exactly analogous to the reported pattern where an external, intent-agnostic event (there: any inflow; here: any attestor list change) unconditionally strips a right (there: reward eligibility; here: spendability of already-held funds) from an account holder who did nothing wrong.

### Citations

**File:** validation.js (L2115-2122)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
```

**File:** validation.js (L2430-2433)
```javascript
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
							return cb("owner address is not attested");
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

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

**File:** definition.js (L370-388)
```javascript
			case 'attested':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb(op+" must have 2 args");
				var attested_address = args[0];
				var arrAttestors = args[1];
				if (bAssetCondition && attested_address === 'this address')
					return cb("asset condition cannot reference this address in "+op);
				if (!isValidAddress(attested_address) && attested_address !== 'this address') // it is ok if the address was never used yet
					return cb("invalid attested address");
				if (!ValidationUtils.isNonemptyArray(arrAttestors))
					return cb("no attestors");
				for (var i=0; i<arrAttestors.length; i++)
					if (!isValidAddress(arrAttestors[i]))
						return cb("invalid attestor address");
				if (objValidationState.last_ball_mci < constants.attestedInDefinitionUpgradeMci)
					return cb(op+" not enabled yet");
				return cb();
```
