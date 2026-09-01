# Q0849: Concrete `GIT_TEMPLATE_DIR=/tmp/tmpl (with hooks/post-che` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `GIT_TEMPLATE_DIR` to `/tmp/tmpl (with hooks/post-checkout)` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it supplies a template dir whose hooks are copied into and run on the next `git clone`?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_TEMPLATE_DIR=/tmp/tmpl (with hooks/post-checkout)` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `/tmp/tmpl (with hooks/post-checkout)` supplies a template dir whose hooks are copied into and run on the next `git clone`
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_TEMPLATE_DIR`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_TEMPLATE_DIR=/tmp/tmpl (with hooks/post-checkout)`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
