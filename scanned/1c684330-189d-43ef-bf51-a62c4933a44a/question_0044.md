# Q0044: [prevent_with_label] format-string in TaskDefinition#render_title in `deploy.variables`

## Question
On provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR abuse `deploy.variables` so that the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env, defeating that `String#%` over attacker-controlled format and values cannot raise or disclose unintended data?

## Target
- File/function: app/models/shipit/deploy_spec.rb + lib/shipit/command.rb + lib/shipit/environment_variables.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> Command#start
- Attacker controls: the `deploy.variables` content on the fork branch under `prevent_with_label` (the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env)
- Exploit idea: `DeploySpec` reads `deploy.variables` from the fork shipit.yml; `String#%` over attacker-controlled format and values cannot raise or disclose unintended data
- Invariant to test: No value read from a fork-authored shipit.yml alters the executed argv or leaks Shipit secrets.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest[prevent_with_label]: build a DeploySpec whose `deploy.variables` carries the payload, assert the resulting argv/leak.
