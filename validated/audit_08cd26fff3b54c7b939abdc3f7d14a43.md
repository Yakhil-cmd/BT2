## Title
`ReviewStackAdapter#archive!` marks a `ReviewStack` archived while its running `Command`/PTY process (and `GITHUB_TOKEN` in its env) keeps executing - ([File: app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb])

### Summary
`ReviewStackAdapter#archive!` calls `stack.remove_from_provisioning_queue`, `stack.deprovision`, and `stack.archive!(user)`, none of which send a signal to any in-flight `Command` process spawned via `PTY.spawn`. The lifecycle of the `ReviewStack`/`Task` *record* is decoupled from the lifecycle of the actual OS process, so a task started before the PR is closed continues running to completion with its full environment (including `GITHUB_TOKEN`) after the stack is marked archived.

### Finding Description
The claimed binding is: `ReviewStack#archived? == true` implies "no OS process is executing task steps for this stack." This does not hold.

`ReviewStackAdapter#archive!` [1](#0-0)  only calls `stack.remove_from_provisioning_queue` (a DB flag flip, [2](#0-1) ), `stack.deprovision` (a state-machine transition that invokes `stack.provisioner.down` [3](#0-2) ), and `stack.archive!(user)` inherited from `Stack`. None of these methods touch `Task#abort!`, iterate `stack.tasks.active`, or send any signal to a running `Command`.

Once a `PerformTaskJob` has been dequeued and `TaskExecutionStrategy::Default#capture!` has called `command.start`, a real PTY process is spawned via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` with the merged environment [4](#0-3) . That process is only interrupted if `Task#should_abort?` returns a nonzero counter, which is only incremented by `Task#request_abort` — itself only called from `Task#abort!` when the task `alive?` [5](#0-4) . `TaskExecutionStrategy::Default#check_for_abort` [6](#0-5)  polls this Redis-backed counter via the `yield_control` callback passed into `command.start` [7](#0-6) . Nothing in the `archive!` path ever calls `Task#abort!`, so `should_abort?`/`request_abort` are never triggered and the PTY process is never signaled.

Attack flow: attacker exploits the `provision?`/provisioning-handler weakness (question 1) to get arbitrary steps queued and executed via the deploy spec, then immediately closes the PR. `ClosedHandler#process` invokes `review_stack.archive!` [1](#0-0) , which flips `awaiting_provision` to false, transitions `provision_status` to `deprovisioning`, and sets `archived_since` on the `ReviewStack` row — but any `PerformTaskJob` already executing on a worker keeps running `PTY.spawn`'d subprocesses to completion, unaffected by the record's new `archived?` status. Any monitoring or alerting keyed off `ReviewStack#archived?` (e.g., dashboards filtering active/live stacks) will treat the stack as gone while its process, and its `GITHUB_TOKEN`-bearing environment, is still alive on the host.

### Impact Explanation
This is a continuation/aggravation of the underlying provisioning RCE (question 1): the archive path provides no kill-switch, so once malicious steps are executing, closing the PR does not stop them and actively hides the activity from any state that keys off `archived?`. The attacker gains a window to have arbitrary shell commands (with `GITHUB_TOKEN` and stack `env`) keep running on the deploy host after superficially "cleaning up" the evidence trail — matching the Critical category (RCE on the deploy host via `Command`/`PTY.spawn`, in-flight, with credential exposure). This finding is bounded to the review-stack-owned task/process; it doesn't independently grant RCE without the prerequisite provisioning bug, but it does defeat the expectation that archiving terminates execution and evades monitoring.

### Likelihood Explanation
Requires the precondition from question 1 (a task already enqueued via the provisioning bug) and requires the attacker to close the PR while that task is running or about to be dequeued — a race that is easy for an attacker to win reliably since they control both the provisioning trigger and the PR-close webhook timing, no privileged credentials needed beyond opening/closing their own PR.

### Recommendation
On `ReviewStack`/`Stack#archive!` (or within `ReviewStackAdapter#archive!` before calling `stack.archive!`), iterate `stack.tasks.active` and call `task.abort!(aborted_by: user)` for each, and ensure `TaskExecutionStrategy::Default#check_for_abort`/`Command#terminate!` is actually invoked (i.e., the process is signaled) synchronously or the archive is deferred until the task reaches a terminal status.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/review_stack_adapter_test.rb`-style, no live GitHub):
1. Create a `ReviewStack` with `provision_status: "provisioned"` and a `Task` in `running` status belonging to it.
2. Build a `Shipit::Command` with a long-running shell command (e.g., `sleep 5`), call `command.start`, capture `pid = command.pid`, assert `Process.kill(0, pid)` succeeds (process alive).
3. Call `ReviewStackAdapter#archive!` (or directly `review_stack.archive!(user)` following `remove_from_provisioning_queue`/`deprovision`) mid-execution.
4. Assert `review_stack.reload.archived?` is `true`.
5. Assert `Process.kill(0, pid)` still succeeds (no `Errno::ESRCH`), proving the OS process is still alive despite the record being archived — i.e., `archived? == true` while the bound OS process is still running, disproving the claimed equality.
6. Clean up by killing the leftover PTY process.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```

**File:** app/models/shipit/review_stack.rb (L79-81)
```ruby
      after_transition provisioned: :deprovisioning do |stack, _|
        stack.provisioner.down
      end
```

**File:** app/models/shipit/review_stack.rb (L109-113)
```ruby
    def remove_from_provisioning_queue
      return unless awaiting_provision

      update!(awaiting_provision: false)
    end
```

**File:** lib/shipit/command.rb (L85-101)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
      rescue Errno::ENOENT
        raise NotFound, "#{Shellwords.split(interpolated_arguments.first).first}: command not found"
      rescue Errno::EACCES
        raise Denied, "#{Shellwords.split(interpolated_arguments.first).first}: Permission denied"
      end
      @started = true
      self
    end
```

**File:** lib/shipit/command.rb (L147-149)
```ruby
    def yield_control
      @control_block&.call
    end
```

**File:** app/models/shipit/task.rb (L356-371)
```ruby
    def abort!(aborted_by:, rollback_once_aborted: false, rollback_once_aborted_to: nil)
      update!(
        rollback_once_aborted:,
        rollback_once_aborted_to:,
        aborted_by_id: aborted_by.id
      )

      if alive?
        aborting
        request_abort
      elsif aborting? || aborted?
        aborted
      elsif !finished?
        report_dead!
      end
    end
```

**File:** app/models/shipit/task_execution_strategy/default.rb (L49-57)
```ruby
      def check_for_abort
        @task.should_abort? do |times_killed|
          if times_killed > 3
            abort!(signal: 'KILL')
          else
            abort!
          end
        end
      end
```
