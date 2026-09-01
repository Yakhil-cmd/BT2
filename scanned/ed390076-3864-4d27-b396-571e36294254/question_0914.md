# Q0914: [prevent_with_label] machine_env value injection in `tasks.<name>.steps`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR abuse `tasks.<name>.steps` so that the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step, defeating that machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `tasks.<name>.steps` content on the fork branch under `prevent_with_label` (the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step)
- Exploit idea: `DeploySpec` reads `tasks.<name>.steps` from the fork shipit.yml; machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build a DeploySpec whose `tasks.<name>.steps` carries the payload, assert the resulting argv/leak.
