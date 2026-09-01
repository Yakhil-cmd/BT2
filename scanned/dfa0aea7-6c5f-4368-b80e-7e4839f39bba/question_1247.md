# Q1247: [allow_with_label] `PERL5LIB` in a shell-interpreted `shipit.yml` step via a pull request label name (uppercased)

## Question
On provisioning_behavior=`allow_with_label`, when the review stack runs a shell-interpreted `shipit.yml` step, can `PERL5LIB` set through a pull request label name (uppercased) cause execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell and adds an attacker perl include path?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `PERL5LIB` via a pull request label name (uppercased) under `allow_with_label`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `PERL5LIB` adds an attacker perl include path
- Invariant to test: No fork-controllable key alters a shell-interpreted `shipit.yml` step.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: inject `PERL5LIB` via a pull request label name (uppercased), assert it reaches the a shell-interpreted `shipit.yml` step process env.
