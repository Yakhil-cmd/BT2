# Q4895: token reaches stdout/stderr/log - (invoker).appendMetadata in invoker.go

## Question
Can attacker-triggered error handling in `appendMetadata` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L164) echo a request URL, header, or config value that still contains the token into output, a log file, or a telemetry payload?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:164](internal/codespaces/rpc/invoker.go#L164) - `(invoker).appendMetadata`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Force an error from an attacker-controlled endpoint and read the token from the reported message in CI logs.
- Invariant to test: Credentials are redacted on every output and telemetry path.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error branch and asserting the token string never appears in captured output.
