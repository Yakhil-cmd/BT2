# Q3611: `GIT_ASKPASS` env-key injection via a pull request label name (uppercased) reaches a `git` invocation in `StackCommands#fetch`/`#git_clone`

## Question
Can an unprivileged fork PR author set `GIT_ASKPASS` through a pull request label name (uppercased), which `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body, so when Shipit runs a `git` invocation in `StackCommands#fetch`/`#git_clone` the value points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands, achieving code execution on the deploy host?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: the env KEY `GIT_ASKPASS` and its value via a pull request label name (uppercased)
- Exploit idea: `Command#unbundled_env` merges attacker-controlled keys with no allowlist over BASE_ENV, then the git subprocess inherits the merged env and honours attacker-set git variables; `GIT_ASKPASS` points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands
- Invariant to test: The set of keys in the environment hash passed to PTY.spawn is restricted to the deploy spec's machine_env and declared VariableDefinition names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a ReviewStack/task whose env contains `GIT_ASKPASS`, assert `Command#unbundled_env` includes it and that `interpolated_arguments`/PTY.spawn would inherit it.
