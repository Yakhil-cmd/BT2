# Q0748: token reaches stdout/stderr/log - getUsername in multi_account.go

## Question
Can attacker-triggered error handling in `getUsername` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L162) echo a request URL, header, or config value that still contains the token into output, a log file, or a telemetry payload?

## Target
- File/function: [internal/config/migration/multi_account.go:162](internal/config/migration/multi_account.go#L162) - `getUsername`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Force an error from an attacker-controlled endpoint and read the token from the reported message in CI logs.
- Invariant to test: Credentials are redacted on every output and telemetry path.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error branch and asserting the token string never appears in captured output.
