# Q1389: machine_env value injection in shipit.yml `provision.handler_name`

## Question
Can an unprivileged fork PR author abuse the `provision.handler_name` section of the review-stack `shipit.yml` so that the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step, defeating the assumption that machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored?

## Target
- File/function: app/models/shipit/deploy_spec.rb + app/models/shipit/deploy_spec/file_system.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the `provision.handler_name` content on the fork branch (the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step)
- Exploit idea: `DeploySpec` reads `provision.handler_name` from the fork-authored shipit.yml and feeds it into command building where machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored
- Invariant to test: Every value read from a fork-authored shipit.yml is treated as untrusted and cannot alter the executed argv or leak Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a DeploySpec whose `provision.handler_name` carries the payload, run through Command building, assert the argv/leak.
