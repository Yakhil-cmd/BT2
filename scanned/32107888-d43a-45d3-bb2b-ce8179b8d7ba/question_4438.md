# Q4438: [prevent_with_label] double-escaping / no-escape of interpolated value in `ci.require`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR abuse `ci.require` so that a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded, defeating that the bytes handed to the shell differ from the literal step string authored in shipit.yml?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `ci.require` content on the fork branch under `prevent_with_label` (a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded)
- Exploit idea: `DeploySpec` reads `ci.require` from the fork shipit.yml; the bytes handed to the shell differ from the literal step string authored in shipit.yml
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build a DeploySpec whose `ci.require` carries the payload, assert the resulting argv/leak.
