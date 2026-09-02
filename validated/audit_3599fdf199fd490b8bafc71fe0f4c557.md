### Title
Uncontrolled `GEM_HOME` (and any other env var name) injection via PR label name into shell-interpreted `shipit.yml` steps - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased, with value `"true"`) directly into the process environment used to run `shipit.yml` steps, with no allowlist. Since `Command#parse_arguments` keeps a step as a single string and `Command#start` runs `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, a label such as `gem_home` becomes `GEM_HOME=true` (or any attacker-chosen env var/value pair, subject to GitHub label-name character limits) in the child process environment for every shell-interpreted step of that review stack's `shipit.yml`.

### Finding Description
The broken binding: `Stack#env` (app/models/shipit/stack.rb:54-63) is expected to contain only server-controlled keys (`ENVIRONMENT`, `LAST_DEPLOYED_SHA`, `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`, `DEPLOY_URL`, `BRANCH`). `ReviewStack#env` breaks this by merging attacker-supplied data with zero filtering: [1](#0-0) 

This merged env flows through `TaskCommands#env` (`super.merge(@stack.env)...`) into every `Command.new(command_line, env:, chdir: steps_directory)` built for `deploy_spec.dependencies_steps!` and `steps`: [2](#0-1) 

`Command#initialize` stores that env verbatim (`@env = env.transform_values { |v| v&.to_s }`), and `Command#unbundled_env` merges it on top of `BASE_ENV`/`PATH`, which is then passed to `PTY.spawn`: [3](#0-2) 

Labels reach `pull_request.labels` via `LabelCapturingHandler#capture_labels`, which persists label names straight from the webhook payload with no allowlist or sanitization of the label string itself (only requires it be a `String`): [4](#0-3) 

The only guard that exists in this codebase for env vars is `EnvironmentVariables#permit`, which raises `NotPermitted` for any key not in an explicit `variable_definitions` allowlist: [5](#0-4) 
—but `ReviewStack#env` never calls `permit`; it merges labels directly into the hash that becomes the process environment, so this allowlist mechanism is bypassed entirely for label-derived variables.

Attacker's exact action: an unprivileged user opens a pull request against a repository with `provision_pr_stacks` (review stacks) enabled, and applies a label named e.g. `gem_home` to their own PR (label names/webhooks are attacker-controlled data emitted by GitHub, not privileged Shipit actions). `LabelCapturingHandler` captures `"gem_home"` into `pull_request.labels`; `ReviewStack#env` turns it into `GEM_HOME=true`; any shell-interpreted step in `shipit.yml` for that review stack runs with `GEM_HOME=true` in its environment.

Whether this rises to full RCE depends on whether `GEM_HOME=true` (a fixed literal `"true"`, not an attacker-chosen path, since `LabelCapturingHandler` always writes the string `"true"` for every label) can be leveraged to redirect gem resolution to an attacker-controlled path. Since the value is always the literal string `"true"`, not an arbitrary path controlled by the attacker, this specific vector does not by itself let the attacker point `GEM_HOME` (or any variable) at an attacker-controlled directory — the attacker can choose the **variable name** but not its **value**. This significantly weakens (though doesn't fully eliminate) the practical RCE impact described in the question, because `GEM_HOME=true` would just break gem resolution rather than redirect it to attacker-controlled content.

### Impact Explanation
Confirmed: any fork/PR-controllable key (via label name) reaches the shell-interpreted `shipit.yml` step's process environment unfiltered, violating the "no fork-controllable key alters a shell-interpreted step" invariant. This lets an attacker inject/override arbitrary env var names (e.g. `PATH`-adjacent tooling vars, `RUBYOPT`, `BUNDLE_GEMFILE`, etc., depending on what `shipit.yml` steps do) into the deploy host's shell for their own review stack, with value fixed to `"true"`. This is a real deviation from the intended env allowlist model (`EnvironmentVariables#permit`), but the fixed `"true"` value limits it — it is not a fully attacker-directed path/URL injection as the question's exploit idea assumes (`GEM_HOME` pointing to an "attacker-populated gem tree" would require an attacker-controlled value, which this mechanism does not provide). Blast radius is scoped to the repository/review stack the attacker's own PR belongs to.

### Likelihood Explanation
Preconditions: `provision_pr_stacks`/review-stack provisioning must be enabled for the target repository, the attacker must be able to open a PR and apply a label to it (standard GitHub permissions for forks depend on repo settings, but label application by a non-collaborator is often restricted by GitHub itself — labels typically can only be added by users with triage/write access, not by arbitrary outside contributors). This is an important caveat: while the code path is real, GitHub's own permission model for applying labels to PRs (as opposed to opening PRs) usually requires write/triage access to the repo, which may put this outside a fully "unprivileged" threat model — this should be verified against the specific repository's GitHub label permissions, which are outside this engine's code.

### Recommendation
In `ReviewStack#env`, do not merge raw, uppercased label names as environment variable keys. Either drop this feature or pass label data through an explicit allowlist (e.g., `EnvironmentVariables#permit` with a fixed, small allowed set of label-derived variable names), and validate label names against a strict charset/prefix (e.g., only accept labels matching `LABEL_<name>` and always route them through `permit`) before merging into any env hash consumed by `Command`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual)
test "PR label name becomes an unfiltered env var for shell-interpreted steps" do
  stack = shipit_review_stacks(:some_review_stack)
  pull_request = stack.pull_request
  pull_request.update!(labels: ["gem_home"])

  env = stack.env
  assert_equal "true", env["GEM_HOME"], "label-derived key reached Stack#env unfiltered"

  task_env = Shipit::TaskCommands.new(some_task).env
  assert_equal "true", task_env["GEM_HOME"], "label-derived key reached Command env"
end
```
This confirms the binding `Stack#env == {allowlisted keys only}` is broken by `ReviewStack#env`, which introduces `GEM_HOME` (or any uppercased label name) with no allowlist check, reaching the `Command`/`PTY.spawn` environment. However, since the value is always the literal `"true"` (not attacker-chosen), full "GEM_HOME redirect to attacker gem tree" RCE as stated in the question is not demonstrated by this path alone.

### Citations

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** lib/shipit/task_commands.rb (L17-27)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end
```

**File:** lib/shipit/command.rb (L92-105)
```ruby
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

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
