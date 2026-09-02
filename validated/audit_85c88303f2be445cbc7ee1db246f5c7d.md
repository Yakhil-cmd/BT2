### Title
`StatusHandler` updates commit status by SHA globally, breaking the organization-authenticated-versus-repository-written binding, enabling cross-repository status forgery via forked repos - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
This is an analog of the MEV-bots-during-pause report's underlying bug class: a value the system trusts (a payload field) is acted upon without being properly bound to the identity/scope that was actually verified. Here, the `X-Hub-Signature` verification in `WebhooksController` binds trust to a specific GitHub organization/repository (derived from `repository.owner.login`), but `StatusHandler#process` never re-checks that the commit it mutates belongs to that same repository — it matches purely on `sha` across the entire `commits` table.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` from the payload and fetches the matching `github_app`/secret for that organization to validate the HMAC signature [1](#0-0) . This proves only that *some* actor with that organization's webhook secret sent the request — it says nothing about which specific commit/stack the payload is allowed to affect.

Once verified, the payload is dispatched unmodified to the registered handler for the `status` event [2](#0-1) .

Unlike `PushHandler` and `CheckSuiteHandler`, which scope their side effects through `stacks` (which is derived from `Repository.from_github_repo_name(repository_name)`, i.e., the actual verified repository) [3](#0-2) [4](#0-3) [5](#0-4) , `StatusHandler#process` looks up `Commit.where(sha: params.sha)` with no repository/stack scoping at all: [6](#0-5) .

Because git commit SHAs are content-addressed and identical across forks that share history, an attacker who controls (or has push/webhook access to) a fork of a tracked repository — a different, unprivileged GitHub organization/repo whose webhook signature they legitimately control — can send a `status` webhook, signed with their own fork's webhook secret, for a `sha` that also exists in the original tracked repository's `commits` table (any commit prior to the fork point, which is guaranteed to share SHAs). `StatusHandler` will happily attach that fabricated status to the commit record belonging to the *victim's* stack, because the lookup is table-wide, not scoped by `repository_name`.

### Impact Explanation
`Commit#create_status_from_github!` → `add_status` fires `Hook.emit(:deployable_status, ...)` and, critically, calls `stack.schedule_merges if new_status.pending? || new_status.success?` [7](#0-6) . A forged "success" status therefore can unblock the merge queue / continuous-delivery pipeline (`ProcessMergeRequestsJob`) or satisfy CI-gating checks used by `MergeRequest::StatusChecker` for merges [8](#0-7) , and it also affects release-status computations feeding `Stack.schedule_continuous_delivery`. This crosses the "unauthorized deploy/merge via cross-repository writes" bar defined in the rules: an actor authenticated for repo A can write commit-status state belonging to stack/repo B.

### Likelihood Explanation
Requires: (1) a public tracked repository that has been forked (common on GitHub), (2) attacker having (or creating) a GitHub App/webhook installation on their own fork so they can legitimately sign a `status` webhook with a secret they control, and (3) targeting a commit SHA that predates the fork (guaranteed to exist verbatim in both repos). No privileged Shipit credentials, GITHUB_TOKEN, or `api_clients_secret` are needed — only a standing GitHub organization installation for the attacker's own fork, which is attacker-controlled infrastructure, not a Shipit secret. This is a realistic, low-effort path once the fork/webhook prerequisite is set up.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler`/`CheckSuiteHandler` do: restrict the `Commit` lookup to `stacks.flat_map(&:commits)` (or an equivalent `Commit.where(stack_id: stacks.select(:id), sha: params.sha)`) derived from `repository_name`/`stacks`, so a status payload can only affect commits belonging to the repository that was actually verified against the signing organization.

### Proof of Concept
1. Fork the tracked upstream repository `org/app` to `attacker/app`; both share commit `abc123...` (pre-fork history).
2. Install a GitHub App/webhook on `attacker/app` pointed at the same Shipit `webhooks_controller` endpoint, obtaining a legitimate webhook secret for `attacker` (or use the standard OAuth GitHub App flow — no Shipit privilege required).
3. Send a `status` event payload: `{"repository": {"owner": {"login": "attacker"}}, "sha": "abc123...", "state": "success", "context": "ci/required"}`, correctly HMAC-signed with `attacker`'s webhook secret.
4. `WebhooksController#verify_signature` resolves `repository_owner == "attacker"`, fetches `attacker`'s `github_app`, and validates the signature successfully [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, matches the commit belonging to `org/app`'s stack (since the SHA is identical), and calls `commit.create_status_from_github!`, injecting a forged `success` status onto `org/app`'s commit — potentially unblocking its merge queue or deploy gating [6](#0-5) [7](#0-6) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
