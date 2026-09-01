# Q4778: Deploy command injection via double-escaping / no-escape of interpolated value

## Question
Can an unprivileged fork PR author cause code execution or secret disclosure when a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded, given that the bytes handed to the shell differ from the literal step string authored in shipit.yml?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/environment_variables.rb + app/models/shipit/task_definition.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the shipit.yml steps / env values on the fork branch (a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded)
- Exploit idea: the bytes handed to the shell differ from the literal step string authored in shipit.yml
- Invariant to test: The bytes executed by the deploy shell equal the step string authored in shipit.yml, with each interpolated value escaped exactly once and no fallback to Shipit's process secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: construct the spec/env, run through EnvironmentVariables#interpolate / Command#parse_arguments, assert the resulting argv or leaked value.
