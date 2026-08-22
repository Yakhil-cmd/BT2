# Q2188: token reaches stdout/stderr/log - getViewer in flow.go

## Question
Can attacker-triggered error handling in `getViewer` in [internal/authflow/flow.go](internal/authflow/flow.go#L126) echo a request URL, header, or config value that still contains the token into output, a log file, or a telemetry payload?

## Target
- File/function: [internal/authflow/flow.go:126](internal/authflow/flow.go#L126) - `getViewer`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Force an error from an attacker-controlled endpoint and read the token from the reported message in CI logs.
- Invariant to test: Credentials are redacted on every output and telemetry path.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error branch and asserting the token string never appears in captured output.
