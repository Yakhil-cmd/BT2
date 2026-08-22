# [H] Yarn transfers npm credentials over unencrypted http connection

## Summary
Severity: High (CVSS 8.2)
Program: Node.js third-party modules
Weakness: Missing Encryption of Sensitive Data
Reporter: chalker
State: resolved
Disclosed: 2019-08-14T11:27:55.400Z
CVE: CVE-2019-5448
Source: https://hackerone.com/reports/640904

## Details
# Module

**module name:** yarn
**version:** 1.16.0
**npm page:** `https://www.npmjs.com/package/yarn`

## Module Description

> Fast, reliable, and secure dependency management.

## Module Stats

> Replace stats below with numbers from npm’s module page:

166 703 downloads in the last day
849 928 downloads in the last week
3 772 290 downloads in the last month

# Vulnerability

## Vulnerability Description

For scoped packages that are listed as `resolved "http://registry.npmjs.org/@...` in yarn.lock, yarn trasfers npm credentials (i.e. `_authToken`) over unencrypted http connection. This allows any MitM (for example, a proxy or a VPN) to sniff out npm credentials, given that the developer in question performs `yarn install` on such a yarn.lock file.

A quick search shows that there is a number of `yarn.lock` files affected by this on GitHub, some examples:
 * https://github.com/EC-Nordbund/ec-verwaltungs-app/blob/ab961352d5dd53834a51793d6e2c4bc69a2b22d4/packages/api/yarn.lock#L36
 *  https://github.com/nujabes403/boilerplate2/blob/61613e526aec02c5dd4227457deb8676d66780d0/yarn.lock#L7

There seem to be __many of those__ on GitHub.

Looks like not only it was possible to craft a yarn.lock with a malicious intent, but also this seems to be a common pattern that yarn created itself at some point or under some circumstances and that gets persistent from older versions.

## Steps To Reproduce:

1. Perform an `npm login` or just write `//registry.npmjs.org/:_authToken=REDACTED-PLACEHOLDER-TOKEN` (which is the format npm uses) to ~/.npmrc. **Doing this from your own account would leak your npm credentials on next steps, so better just use a placeholder.**
2. Create an empty package with a single dependency on `"@babel/core": "^7.5.4"`
3. Perform `yarn install`
4. Replace all occurances of `https://registry.yarnpkg.com` with `http://registry.npmjs.org/` in the generated `yarn.lock`

_Trimmed to 38 lines — full report: https://hackerone.com/reports/640904_
