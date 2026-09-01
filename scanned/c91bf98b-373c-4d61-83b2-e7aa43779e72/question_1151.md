# Q1151: [prevent_with_label] $VAR interpolation falling back to Shipit's ENV in `provision.handler_name`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR abuse `provision.handler_name` so that a step references `$SOMEVAR` that is not in the task env so `EnvironmentVariables#interpolate` falls back to `ENV[VAR]`, defeating that an unset variable name resolves to Shipit's own process environment (which holds secrets) and is `Shellwords.escape`d into the command/output?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `provision.handler_name` content on the fork branch under `prevent_with_label` (a step references `$SOMEVAR` that is not in the task env so `EnvironmentVariables#interpolate` falls back to `ENV[VAR]`)
- Exploit idea: `DeploySpec` reads `provision.handler_name` from the fork shipit.yml; an unset variable name resolves to Shipit's own process environment (which holds secrets) and is `Shellwords.escape`d into the command/output
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: Critical — Exfiltration of GITHUB_TOKEN / a user's github_access_token / deploy-time secrets
- Fast validation: minitest[prevent_with_label]: build a DeploySpec whose `provision.handler_name` carries the payload, assert the resulting argv/leak.
