# Q2556: format-string in TaskDefinition#render_title in shipit.yml `tasks.<name>.steps`

## Question
Can an unprivileged fork PR author abuse the `tasks.<name>.steps` section of the review-stack `shipit.yml` so that the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env, defeating the assumption that `String#%` over attacker-controlled format and values cannot raise or disclose unintended data?

## Target
- File/function: app/models/shipit/deploy_spec.rb + app/models/shipit/deploy_spec/file_system.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the `tasks.<name>.steps` content on the fork branch (the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env)
- Exploit idea: `DeploySpec` reads `tasks.<name>.steps` from the fork-authored shipit.yml and feeds it into command building where `String#%` over attacker-controlled format and values cannot raise or disclose unintended data
- Invariant to test: Every value read from a fork-authored shipit.yml is treated as untrusted and cannot alter the executed argv or leak Shipit secrets.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: build a DeploySpec whose `tasks.<name>.steps` carries the payload, run through Command building, assert the argv/leak.
