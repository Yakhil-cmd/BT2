### Title
Stored HTML/script injection via unsanitized cosigner `device_name` in `correspondent_devices` - (File: `device.js`)

### Summary
The Airflow CVE describes a malicious admin editing metadata-DB fields that later get rendered on a page without sanitization, producing stored XSS (plus incidental local-file disclosure). The closest reachable analog in ocore is the handling of the `name` field for paired/cosigner devices in `device.js`. When a device pairs directly, `handlePairingMessage` strips angle brackets from `body.device_name` before storing it [1](#0-0) . However, when a device is added as an *indirect correspondent* (a cosigner of a shared/multisig wallet introduced by another already-paired device), `addIndirectCorrespondents` inserts `correspondent.name` into `correspondent_devices.name` with **no sanitization at all** [2](#0-1) . Likewise `addUnconfirmedCorrespondent` stores `device_name` unsanitized [3](#0-2) .

### Finding Description
`correspondent_devices.name` is a free-text field (VARCHAR(100)) with no content restrictions at the schema level [4](#0-3) . This name is round-tripped and displayed to the user in every wallet UI that lists correspondents/cosigners, e.g. `readCorrespondents`, `readCorrespondentsByDeviceAddresses`, and `readSharedAddressCosigners`/`readCosigners` (multisig wallet member lists) [5](#0-4) [6](#0-5) [7](#0-6) .

Two entry points populate this field with attacker-supplied strings:
1. `handlePairingMessage` (direct pairing) — sanitizes with `body.device_name.replace(/<[^>]*>?/g, '')` before insert/update [8](#0-7) .
2. `addIndirectCorrespondents` (indirect cosigners introduced during multisig/shared-wallet setup by another paired device) — inserts `correspondent.name` with **no filtering** [2](#0-1) .

Because `addIndirectCorrespondents` is reachable purely by a device that legitimately holds a pairing with the victim and is participating in setting up a shared/multisig wallet (a normal cosigner-onboarding flow, not requiring admin privilege), any such counterparty can inject an arbitrary HTML/script payload as its own "cosigner name," which is then stored verbatim in the victim's local wallet database and surfaced unescaped by GUI wallets that consume ocore (Obyte desktop/Cordova wallets render correspondent/cosigner names in HTML views such as chat lists and wallet-setup dialogs). This mirrors the CVE's root cause: state fields settable by a less-trusted party are persisted without sanitization and later rendered on pages that trust them.

### Impact Explanation
If the consuming wallet GUI renders `name` as HTML (as GUI wallets commonly do for contact/cosigner lists and chat headers), a malicious pairing counterparty introduced as an indirect cosigner can achieve stored script execution in the victim wallet's UI context. Depending on the wallet's UI framework (Electron/Cordova), this can escalate to reading local files, exfiltrating wallet secrets, or triggering unauthorized signing/spending actions — analogous to the Airflow issue's combination of stored XSS + local file disclosure.

### Likelihood Explanation
Likelihood is moderate: it requires the victim to already have an active pairing with the attacker's device (or the attacker's device being introduced as a cosigner in a shared/multisig wallet-setup flow), which is a realistic scenario for counterparties in shared addresses, arbiter contracts, or textcoin/shared-wallet flows. No special privilege beyond being a paired device/cosigner is needed, and the sanitization already applied on the direct-pairing path shows the developers were aware of this exact class of risk but missed one of the code paths that stores the same field.

### Recommendation
Apply the same (or stronger, e.g. full HTML-entity-encoding rather than a naive tag-strip regex) sanitization to every code path that writes into `correspondent_devices.name`, specifically `addIndirectCorrespondents` and `addUnconfirmedCorrespondent` in `device.js`, and additionally enforce length/charset validation consistent with `handlePairingMessage`. Prefer output-encoding at render time in downstream GUIs rather than relying solely on input filtering.

### Proof of Concept
1. Device A pairs normally with Device B (legitimate pairing, sanitized).
2. Device A initiates creation of a shared/multisig wallet and sends cosigner info including a `device_name`/`name` containing `<img src=x onerror=alert(document.cookie)>` for one of the "other cosigners" it introduces (`arrOtherCosigners`).
3. Device B calls `addIndirectCorrespondents`, which inserts this payload unmodified into `correspondent_devices.name` [2](#0-1) .
4. When Device B's wallet GUI lists cosigners/correspondents (e.g., during wallet-setup approval screen), the unsanitized name is rendered, executing the injected script in the wallet UI context.

### Citations

**File:** device.js (L822-830)
```javascript
			// add new correspondent and delete pending pairing
			var safe_device_name = body.device_name.replace(/<[^>]*>?/g, '');
			db.query(
				"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, pubkey, hub, name, is_confirmed) VALUES (?,?,?,?,1)", 
				[from_address, device_pubkey, json.device_hub, safe_device_name],
				function(){
					db.query( // don't update name if already confirmed
						"UPDATE correspondent_devices SET is_confirmed=1, name=? WHERE device_address=? AND is_confirmed=0", 
						[safe_device_name, from_address],
```

**File:** device.js (L855-870)
```javascript
function addUnconfirmedCorrespondent(device_pubkey, device_hub, device_name, onDone){
	console.log("addUnconfirmedCorrespondent");
	if (!ValidationUtils.isNonemptyString(device_hub) || !network.isValidWsUrl(conf.WS_PROTOCOL + device_hub)){
		console.log("addUnconfirmedCorrespondent: invalid hub URL: ", device_hub);
		return onDone ? onDone(null) : null;
	}
	var device_address = objectHash.getDeviceAddress(device_pubkey);
	db.query(
		"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, pubkey, hub, name, is_confirmed) VALUES (?,?,?,?,0)", 
		[device_address, device_pubkey, device_hub, device_name],
		function(){
			if (onDone)
				onDone(device_address);
		}
	);
}
```

**File:** device.js (L872-892)
```javascript
function readCorrespondents(handleCorrespondents){
	db.query("SELECT device_address, hub, name, my_record_pref, peer_record_pref FROM correspondent_devices ORDER BY name", function(rows){
		handleCorrespondents(rows);
	});
}

function readCorrespondent(device_address, handleCorrespondent){
	db.query("SELECT device_address, hub, name, my_record_pref, peer_record_pref FROM correspondent_devices WHERE device_address=?", [device_address], function(rows){
		handleCorrespondent(rows.length ? rows[0] : null);
	});
}

function readCorrespondentsByDeviceAddresses(arrDeviceAddresses, handleCorrespondents){
	db.query(
		"SELECT device_address, hub, name, pubkey, my_record_pref, peer_record_pref FROM correspondent_devices WHERE device_address IN(?) ORDER BY name", 
		[arrDeviceAddresses], 
		function(rows){
			handleCorrespondents(rows);
		}
	);
}
```

**File:** device.js (L906-919)
```javascript
function addIndirectCorrespondents(arrOtherCosigners, onDone){
	async.eachSeries(arrOtherCosigners, function(correspondent, cb){
		if (correspondent.device_address === my_device_address)
			return cb();
		if (!ValidationUtils.isNonemptyString(correspondent.hub) || !network.isValidWsUrl(conf.WS_PROTOCOL + correspondent.hub))
			return cb(); // ignore silently and continue eachSeries
		db.query(
			"INSERT "+db.getIgnore()+" INTO correspondent_devices (device_address, hub, name, pubkey, is_indirect) VALUES(?,?,?,?,1)", 
			[correspondent.device_address, correspondent.hub, correspondent.name, correspondent.pubkey],
			function(){
				cb();
			}
		);
	}, onDone);
```

**File:** initial-db/byteball-mysql.sql (L536-545)
```sql
CREATE TABLE correspondent_devices (
	device_address CHAR(33) NOT NULL PRIMARY KEY,
	name VARCHAR(100) NOT NULL,
	pubkey CHAR(44) NOT NULL,
	hub VARCHAR(100) NOT NULL, -- domain name of the hub this address is subscribed to
	is_confirmed TINYINT NOT NULL DEFAULT 0,
	is_indirect TINYINT NOT NULL DEFAULT 0,
	is_blackhole TINYINT NOT NULL DEFAULT 0,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```

**File:** wallet_defined_by_addresses.js (L591-606)
```javascript
// returns information about cosigner devices
function readSharedAddressCosigners(shared_address, handleCosigners){
	db.query(
		"SELECT DISTINCT shared_address_signing_paths.device_address, name, "+db.getUnixTimestamp("shared_addresses.creation_date")+" AS creation_ts \n\
		FROM shared_address_signing_paths \n\
		JOIN shared_addresses USING(shared_address) \n\
		LEFT JOIN correspondent_devices USING(device_address) \n\
		WHERE shared_address=? AND device_address!=?",
		[shared_address, device.getMyDeviceAddress()],
		function(rows){
			if (rows.length === 0)
				throw Error("no cosigners found for shared address "+shared_address);
			handleCosigners(rows);
		}
	);
}
```

**File:** wallet_defined_by_keys.js (L395-413)
```javascript
function readCosigners(wallet, handleCosigners){
	db.query(
		"SELECT extended_pubkeys.device_address, name, approval_date, extended_pubkey \n\
		FROM extended_pubkeys LEFT JOIN correspondent_devices USING(device_address) WHERE wallet=?", 
		[wallet], 
		function(rows){
			rows.forEach(function(row){
				if (row.device_address === device.getMyDeviceAddress()){
					if (row.name !== null)
						throw Error("found self in correspondents");
					row.me = true;
				}
				else if (row.name === null)
					throw Error("cosigner not found among correspondents, cosigner="+row.device_address+", my="+device.getMyDeviceAddress());
			});
			handleCosigners(rows);
		}
	);
}
```
