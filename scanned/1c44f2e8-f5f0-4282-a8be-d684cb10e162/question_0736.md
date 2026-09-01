# Q0736: Deploy command injection via machine_env value injection

## Question
Can an unprivileged fork PR author cause code execution or secret disclosure when the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step, given that machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/environment_variables.rb + app/models/shipit/task_definition.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the shipit.yml steps / env values on the fork branch (the fork `shipit.yml` `machine.environment` sets a variable VALUE consumed by a later step)
- Exploit idea: machine_env values are treated as trusted deploy configuration although the review-stack branch is fork-authored
- Invariant to test: The bytes executed by the deploy shell equal the step string authored in shipit.yml, with each interpolated value escaped exactly once and no fallback to Shipit's process secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: construct the spec/env, run through EnvironmentVariables#interpolate / Command#parse_arguments, assert the resulting argv or leaked value.
