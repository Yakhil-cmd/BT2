# Q5641: port forwarding binds a public interface - keypairForPrivateKey in ssh.go

## Question
Can `keypairForPrivateKey` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L524) be driven by remote data to bind the forwarded port on a non-loopback interface, exposing the victim's machine or the tunnel to the local network?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:524](pkg/cmd/codespace/ssh.go#L524) - `keypairForPrivateKey`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a forwarding configuration requesting 0.0.0.0.
- Invariant to test: Local listeners always bind loopback unless the user explicitly asks.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the bind address is loopback for hostile config.
