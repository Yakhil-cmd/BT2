# Q5991: [prevent_with_label] machine_env value injection in `provision.handler_name`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR abuse `provision.handler_name` so that the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step, defeating that machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `provision.handler_name` content on the fork branch under `prevent_with_label` (the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step)
- Exploit idea: `DeploySpec` reads `provision.handler_name` from the fork shipit.yml; machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build a DeploySpec whose `provision.handler_name` carries the payload, assert the resulting argv/leak.
