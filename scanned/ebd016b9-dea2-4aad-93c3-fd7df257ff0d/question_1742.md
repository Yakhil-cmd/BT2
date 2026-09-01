# Q1742: [allow_all] `PYTHONPATH` in a shell-interpreted `shipit.yml` step via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_all`, when the review stack runs a shell-interpreted `shipit.yml` step, can `PYTHONPATH` set through a pull request label name (uppercased) cause execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell and prepends an attacker module path so a python step imports attacker code?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `PYTHONPATH` via a pull request label name (uppercased) under `allow_all`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `PYTHONPATH` prepends an attacker module path so a python step imports attacker code
- Invariant to test: No fork-controllable key alters a shell-interpreted `shipit.yml` step.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: inject `PYTHONPATH` via a pull request label name (uppercased), assert it reaches the a shell-interpreted `shipit.yml` step process env.
