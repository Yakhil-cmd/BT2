# Q5907: token reaches stdout/stderr/log - authRecoveryCommand in cmd.go

## Question
Can attacker-triggered error handling in `authRecoveryCommand` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L304) echo a request URL, header, or config value that still contains the token into output, a log file, or a telemetry payload?

## Target
- File/function: [internal/ghcmd/cmd.go:304](internal/ghcmd/cmd.go#L304) - `authRecoveryCommand`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Force an error from an attacker-controlled endpoint and read the token from the reported message in CI logs.
- Invariant to test: Credentials are redacted on every output and telemetry path.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error branch and asserting the token string never appears in captured output.
