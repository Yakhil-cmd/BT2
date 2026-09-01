# Q5048: Deploy command injection via shell metacharacters in a step string

## Question
Can an unprivileged fork PR author cause code execution or secret disclosure when the fork's `shipit.yml` `deploy.override`/`dependencies.override` step contains `;`, `$(...)`, backticks or `&&`, given that `Command#parse_arguments` keeps the step as a single string and `PTY.spawn(env?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/environment_variables.rb + app/models/shipit/task_definition.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the shipit.yml steps / env values on the fork branch (the fork's `shipit.yml` `deploy.override`/`dependencies.override` step contains `;`, `$(...)`, backticks or `&&`)
- Exploit idea: `Command#parse_arguments` keeps the step as a single string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell, so metacharacters execute
- Invariant to test: The bytes executed by the deploy shell equal the step string authored in shipit.yml, with each interpolated value escaped exactly once and no fallback to Shipit's process secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: construct the spec/env, run through EnvironmentVariables#interpolate / Command#parse_arguments, assert the resulting argv or leaked value.
