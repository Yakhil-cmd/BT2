## No vulnerability found for this question.

**Reasoning:**

The claimed broken binding is: `GITHUB_TOKEN never appears in strings passed to Task#write == true`. Tracing the code confirms this holds in the engine's own code paths, and the specific mechanisms suggested (git-askpass failure path, verbose git output) do not actually leak the token through `Task#write`.

- `GITHUB_TOKEN` is injected only as an OS environment variable via `Commands#base_env`, merged into `Command#env` and passed to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` — it is never placed into `@args`/argv. [1](#0-0) [2](#0-1) 
- `Command#to_s`, used by `capture!` when writing `"$ #{command}"`, only joins `@args` — the env hash (including `GITHUB_TOKEN`) is never interpolated into that string. [3](#0-2) [4](#0-3) 
- The `git-askpass` script reads `GITHUB_TOKEN` from its own process environment and echoes it only to stdout of the askpass subprocess, which becomes git's password input via the `GIT_ASKPASS` protocol — it is not piped into the parent `git` process's PTY output/stdout that `command.stream!` captures via `@out`. [5](#0-4) 
- `interpolate_environment_variables`/`EnvironmentVariables#interpolate` only substitutes `$VAR` references found inside command *arguments* (argv), not stdout — and this substitution path is unrelated to how git or askpass writes output. [6](#0-5) [7](#0-6) 
- `Task#write` simply appends whatever string it is given to Redis and the task logger, with no redaction logic. [8](#0-7) 

The question's hypothesized leak paths ("git-askpass failure path or verbose git output") are speculative and not demonstrated in this engine's code: no code path in `lib/shipit/commands.rb`, `lib/shipit/stack_commands.rb`, or `lib/shipit/command.rb` constructs a git URL or argv containing the literal token value (e.g., an `https://<token>@github.com/...` URL) — token delivery is exclusively via the `GIT_ASKPASS` env-var mechanism, which is the standard git credential-helper protocol specifically designed to avoid putting credentials in argv or process listings. Whether `git` itself could ever echo the password back to stdout under some verbose/trace flag is a property of the external `git` binary, not a defect in this engine's code, and no `-v`/trace flags are passed by `StackCommands`. This falls under "third-party gem/binary defects with no exploit path through this engine's own code," which is explicitly out of scope.

Since no reachable code path in this engine writes `GITHUB_TOKEN` into a string passed to `Task#write`, the binding holds (both sides remain `true`), and there is no reproducible exploit within the engine's own code.

### Citations

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
    end
```

**File:** lib/shipit/command.rb (L47-49)
```ruby
    def to_s
      @args.join(' ')
    end
```

**File:** lib/shipit/command.rb (L51-55)
```ruby
    def interpolate_environment_variables(argument)
      return argument.map { |a| interpolate_environment_variables(a) } if argument.is_a?(Array)

      EnvironmentVariables.with(env).interpolate(argument)
    end
```

**File:** lib/shipit/command.rb (L85-98)
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
```

**File:** app/models/shipit/task_execution_strategy/default.rb (L89-99)
```ruby
      def capture!(command)
        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        command.start do
          @task.ping
          check_for_abort
        end
        @task.write("\n$ #{command}\npid: #{command.pid}\n")
        @task.pid = command.pid
        command.stream! do |line|
          @task.write(line)
        end
```

**File:** lib/snippets/git-askpass (L1-16)
```text
#!/bin/sh

GITHUB_USER="${GITHUB_USER:-git}"
GITHUB_DOMAIN="${GITHUB_DOMAIN:-github.com}"

if [ "${1}" = "Username for 'https://${GITHUB_DOMAIN}': " ]; then
  echo "${GITHUB_USER}"
  exit 0
fi

if [ "${1}" = "Password for 'https://${GITHUB_USER}@${GITHUB_DOMAIN}': " ]; then
  echo "${GITHUB_TOKEN}"
  exit 0
fi

exit 1
```

**File:** lib/shipit/environment_variables.rb (L20-27)
```ruby
    def interpolate(argument)
      return argument unless @env

      argument.gsub(/(\$\w+)/) do |variable|
        variable.sub!('$', '')
        Shellwords.escape(@env.fetch(variable) { ENV[variable] })
      end
    end
```

**File:** app/models/shipit/task.rb (L238-241)
```ruby
    def write(text)
      log_output(text)
      Shipit.redis.append(output_key, text)
    end
```
