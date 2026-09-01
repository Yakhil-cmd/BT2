# Q3768: Concrete `RUBYOPT=-r/tmp/evil` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `RUBYOPT` to `-r/tmp/evil` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `RUBYOPT=-r/tmp/evil` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `-r/tmp/evil` injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup
- Invariant to test: No spawned deploy process ever sees a fork-controlled `RUBYOPT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `RUBYOPT=-r/tmp/evil`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
