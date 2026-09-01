# Q0168: [allow_all] shell metacharacters in a step string in `deploy.variables`

## Question
On provisioning_behavior=`allow_all`, can an unprivileged fork PR abuse `deploy.variables` so that the fork's `shipit.yml` `deploy.override`/`dependencies.override` step contains `;`, `$(...)`, backticks or `&&`, defeating that `Command#parse_arguments` keeps the step as a single string and `PTY.spawn(env?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `deploy.variables` content on the fork branch under `allow_all` (the fork's `shipit.yml` `deploy.override`/`dependencies.override` step contains `;`, `$(...)`, backticks or `&&`)
- Exploit idea: `DeploySpec` reads `deploy.variables` from the fork shipit.yml; `Command#parse_arguments` keeps the step as a single string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell, so metacharacters execute
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build a DeploySpec whose `deploy.variables` carries the payload, assert the resulting argv/leak.
