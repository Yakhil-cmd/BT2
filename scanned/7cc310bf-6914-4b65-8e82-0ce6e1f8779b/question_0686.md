# Q0686: [allow_with_label] machine_env value injection in `deploy.override`

## Question
On provisioning_behavior=`allow_with_label`, can an unprivileged fork PR abuse `deploy.override` so that the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step, defeating that machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `deploy.override` content on the fork branch under `allow_with_label` (the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step)
- Exploit idea: `DeploySpec` reads `deploy.override` from the fork shipit.yml; machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build a DeploySpec whose `deploy.override` carries the payload, assert the resulting argv/leak.
