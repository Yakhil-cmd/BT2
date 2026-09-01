# Q5109: format-string in TaskDefinition#render_title in shipit.yml `provision.handler_name`

## Question
Can an unprivileged fork PR author abuse the `provision.handler_name` section of the review-stack `shipit.yml` so that the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env, defeating the assumption that `String#%` over attacker-controlled format and values cannot raise or disclose unintended data?

## Target
- File/function: app/models/shipit/deploy_spec.rb + app/models/shipit/deploy_spec/file_system.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the `provision.handler_name` content on the fork branch (the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env)
- Exploit idea: `DeploySpec` reads `provision.handler_name` from the fork-authored shipit.yml and feeds it into command building where `String#%` over attacker-controlled format and values cannot raise or disclose unintended data
- Invariant to test: Every value read from a fork-authored shipit.yml is treated as untrusted and cannot alter the executed argv or leak Shipit secrets.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: build a DeploySpec whose `provision.handler_name` carries the payload, run through Command building, assert the argv/leak.
