# Q2524: $VAR interpolation falling back to Shipit's ENV in shipit.yml `rollback.override`

## Question
Can an unprivileged fork PR author abuse the `rollback.override` section of the review-stack `shipit.yml` so that a step references `$SOMEVAR` that is not in the task env so `EnvironmentVariables#interpolate` falls back to `ENV[VAR]`, defeating the assumption that an unset variable name resolves to Shipit's own process environment (which holds secrets) and is `Shellwords.escape`d into the command/output?

## Target
- File/function: app/models/shipit/deploy_spec.rb + app/models/shipit/deploy_spec/file_system.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the `rollback.override` content on the fork branch (a step references `$SOMEVAR` that is not in the task env so `EnvironmentVariables#interpolate` falls back to `ENV[VAR]`)
- Exploit idea: `DeploySpec` reads `rollback.override` from the fork-authored shipit.yml and feeds it into command building where an unset variable name resolves to Shipit's own process environment (which holds secrets) and is `Shellwords.escape`d into the command/output
- Invariant to test: Every value read from a fork-authored shipit.yml is treated as untrusted and cannot alter the executed argv or leak Shipit secrets.
- Expected Immunefi impact: Critical — Exfiltration of GITHUB_TOKEN / a user's github_access_token / deploy-time secrets
- Fast validation: minitest: build a DeploySpec whose `rollback.override` carries the payload, run through Command building, assert the argv/leak.
