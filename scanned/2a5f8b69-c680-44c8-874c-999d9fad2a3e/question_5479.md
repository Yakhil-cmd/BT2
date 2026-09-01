# Q5479: Deploy command injection via format-string in TaskDefinition#render_title

## Question
Can an unprivileged fork PR author cause code execution or secret disclosure when the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env, given that `String#%` over attacker-controlled format and values cannot raise or disclose unintended data?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/environment_variables.rb + app/models/shipit/task_definition.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the shipit.yml steps / env values on the fork branch (the deploy spec `title` uses `%{...}`/`%<...>` conversions and `render_title` runs `@title % env.symbolize_keys` on attacker env)
- Exploit idea: `String#%` over attacker-controlled format and values cannot raise or disclose unintended data
- Invariant to test: The bytes executed by the deploy shell equal the step string authored in shipit.yml, with each interpolated value escaped exactly once and no fallback to Shipit's process secrets.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: construct the spec/env, run through EnvironmentVariables#interpolate / Command#parse_arguments, assert the resulting argv or leaked value.
