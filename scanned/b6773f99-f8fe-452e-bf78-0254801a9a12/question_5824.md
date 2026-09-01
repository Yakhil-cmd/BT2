# Q5824: [allow_all] double-escaping / no-escape of interpolated value in `tasks.<name>.steps`

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR abuse `tasks.<name>.steps` so that a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded, defeating that the bytes handed to the shell differ from the literal step string authored in shipit.yml?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `tasks.<name>.steps` content on the fork branch under `allow_all` (a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded)
- Exploit idea: `DeploySpec` reads `tasks.<name>.steps` from the fork shipit.yml; the bytes handed to the shell differ from the literal step string authored in shipit.yml
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build a DeploySpec whose `tasks.<name>.steps` carries the payload, assert the resulting argv/leak.
