# Q5308: Deploy command injection via $VAR interpolation falling back to Shipit's ENV

## Question
Can an unprivileged fork PR author cause code execution or secret disclosure when a step references `$SOMEVAR` that is not in the task env so `EnvironmentVariables#interpolate` falls back to `ENV[VAR]`, given that an unset variable name resolves to Shipit's own process environment (which holds secrets) and is `Shellwords.escape`d into the command/output?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/environment_variables.rb + app/models/shipit/task_definition.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the shipit.yml steps / env values on the fork branch (a step references `$SOMEVAR` that is not in the task env so `EnvironmentVariables#interpolate` falls back to `ENV[VAR]`)
- Exploit idea: an unset variable name resolves to Shipit's own process environment (which holds secrets) and is `Shellwords.escape`d into the command/output
- Invariant to test: The bytes executed by the deploy shell equal the step string authored in shipit.yml, with each interpolated value escaped exactly once and no fallback to Shipit's process secrets.
- Expected Immunefi impact: Critical — Exfiltration of GITHUB_TOKEN / a user's github_access_token / deploy-time secrets
- Fast validation: minitest: construct the spec/env, run through EnvironmentVariables#interpolate / Command#parse_arguments, assert the resulting argv or leaked value.
