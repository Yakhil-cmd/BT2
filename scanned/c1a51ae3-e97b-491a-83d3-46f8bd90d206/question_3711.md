# Q3711: digest bound to the wrong bytes - (Client).ShowRefs in client.go

## Question
Does `ShowRefs` in [git/client.go](git/client.go#L243) compute or compare the artifact digest over data other than the exact bytes the user will run (for example a re-downloaded copy, a decompressed stream, or a manifest field)?

## Target
- File/function: [git/client.go:243](git/client.go#L243) - `(Client).ShowRefs`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve one artifact for verification and a different one for the actual download.
- Invariant to test: The verified digest is computed over the same bytes that are written to disk and returned to the caller.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test where the byte stream differs between verify and write, asserting a failure.
