# Q2841: Concrete `BUNDLE_GEMFILE=/tmp/Gemfile.evil` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `BUNDLE_GEMFILE` to `/tmp/Gemfile.evil` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it points bundler at an attacker Gemfile whose evaluated code runs?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `BUNDLE_GEMFILE=/tmp/Gemfile.evil` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `/tmp/Gemfile.evil` points bundler at an attacker Gemfile whose evaluated code runs
- Invariant to test: No spawned deploy process ever sees a fork-controlled `BUNDLE_GEMFILE`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `BUNDLE_GEMFILE=/tmp/Gemfile.evil`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
