# Q2048: machine_env value injection in shipit.yml `rollback.override`

## Question
Can an unprivileged fork PR author abuse the `rollback.override` section of the review-stack `shipit.yml` so that the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step, defeating the assumption that machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored?

## Target
- File/function: app/models/shipit/deploy_spec.rb + app/models/shipit/deploy_spec/file_system.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the `rollback.override` content on the fork branch (the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step)
- Exploit idea: `DeploySpec` reads `rollback.override` from the fork-authored shipit.yml and feeds it into command building where machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored
- Invariant to test: Every value read from a fork-authored shipit.yml is treated as untrusted and cannot alter the executed argv or leak Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a DeploySpec whose `rollback.override` carries the payload, run through Command building, assert the argv/leak.
