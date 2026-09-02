### Title
`StatusHandler` matches commits by SHA across *all* repositories, breaking the organization-scoping enforced by webhook signature verification - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an incoming `status` webhook against exactly one organization (the one derived from the payload's `repository.owner.login`), but `StatusHandler#process` never re-checks that binding: it looks up commits purely by `sha`, globally, across every stack/repository stored in Shipit. This is the same class of bug as the Primitive C02 report: one part of the system enforces a boundary (`notExpired`/signature-to-organization binding) while another part of the system that acts on the same data (`close`/`StatusHandler`) uses a weaker or absent check, letting an attacker who is validly authenticated for repository/org A cause writes against a commit that actually belongs to repository/org B.

### Finding Description
- `WebhooksController#verify_signature` resolves the org to verify against solely from the payload content: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, and validates the signature using that org's configured `webhook_secret` [1](#0-0) , [2](#0-1) .
- Once verified, `Shipit::Webhooks.for_event(event)` dispatches the raw `params` to every registered handler for that event type, with no further binding of "this payload was authenticated for org/repo X" to "this handler may only touch data belonging to X" [3](#0-2) .
- Most handlers re-derive scope by resolving `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` and then restrict to that repository's stacks, e.g. `Handler#stacks` [4](#0-3) , and `CheckSuiteHandler` [5](#0-4) .
- `StatusHandler`, however, does none of this: it queries `Commit.where(sha: params.sha)` with no repository/stack scoping whatsoever, then calls `commit.create_status_from_github!(params)` on every match [6](#0-5) .
- Because git commit SHAs are content-addressed, any two repositories that share history (a public repo and any fork of it, or two repos merged from a common upstream) will contain commits with identical SHAs across different `stack_id`s. `Commit#create_status_from_github!` writes a new `Status` row tied to that commit/stack via `statuses.replicate_from_github!(stack_id, github_status)` and triggers `deployable_status`/`schedule_merges` side effects [7](#0-6) , [8](#0-7) .

The binding that should hold as an equality is:
`organization authenticated by verify_signature (repository.owner.login) == organization/repository whose data StatusHandler is permitted to mutate`.
`StatusHandler` breaks this equality because it authorizes by `sha` alone, not by `repository.full_name`/owner.

### Impact Explanation
A commit's aggregate `status` (`Status::Group.compact`) directly feeds `Commit#deployable?` (`success? && !blocked?`) [9](#0-8)  and `schedule_continuous_delivery`, which enqueues a `ContinuousDeliveryJob` once a commit becomes deployable on a `continuous_deployment?` stack [10](#0-9) . If an attacker owns/administers any repository that shares a commit SHA with a victim stack's pending commit (e.g., they fork the victim's public repository and configure their own legitimate Shipit webhook on their fork, which is fully in their control and requires no privileged access to the victim's repository), they can send a genuine, correctly-signed `status` webhook from *their own* org for that shared SHA with `state: "success"` and a `context` matching the victim stack's required CI check. `StatusHandler` will apply that status to the victim's commit record regardless of which repository it actually came from, potentially satisfying `stack.deployable?`/required-status checks and triggering an unauthorized deploy via continuous delivery — this matches the "unauthorized deploy" Critical-impact criterion.

### Likelihood Explanation
This is exploitable without any credentials, tokens, or write access to the victim repository/stack — only a fork (or independently-authored repo sharing base history) with a valid webhook configured by the attacker for their own org. It requires the target stack to have `continuous_deployment` enabled and to share commit history/SHAs with an attacker-controlled repo (most plausible for open-source projects or template-forked internal repos), which somewhat limits but does not eliminate real-world likelihood.

### Recommendation
`StatusHandler` (and any other handler that queries by content-derived identifiers like `sha` without an accompanying repository scope) must resolve the target repository the same way `verify_signature` did, and constrain the `Commit` lookup to that repository's stacks — e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining `Commit` through `Stack -> Repository` filtered by `payload.dig('repository', 'full_name')`, mirroring the pattern already used in `Handler#stacks` and `CheckSuiteHandler`. More generally, the webhook dispatch pipeline should pass the already-verified repository/organization identity down to every handler and assert equality with any repository-scoping logic the handler performs, rather than letting each handler independently (and inconsistently) decide what "repository" a payload refers to.

### Proof of Concept
1. Attacker forks (or independently creates) a repository `attacker-org/target-fork` sharing base commit `SHA` with victim stack `victim-org/target` (a `Shipit::Stack` with `continuous_deployment: true` and a required CI `context`, e.g. `"ci/build"`).
2. Attacker configures a GitHub webhook + Shipit installation for `attacker-org` (their own org, with a legitimately configured `webhook_secret` in `Shipit.github(organization: 'attacker-org')`), and enables the `status` event.
3. Attacker triggers (or fabricates via their own CI on their own fork, which they fully control) a `status` event on `attacker-org/target-fork` for commit `SHA` with `state: "success"`, `context: "ci/build"`. GitHub signs this payload with `attacker-org`'s webhook secret.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature — the request passes [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: SHA)`, which matches the `Commit` row belonging to `victim-org/target`'s stack (because the SHA is identical), and calls `create_status_from_github!`, writing a `success` status for `"ci/build"` on the victim's commit [6](#0-5) .
6. If this satisfies `victim-org/target`'s required statuses, `Commit#deployable?` becomes true and `schedule_continuous_delivery` enqueues a deploy of that commit to production — an unauthorized deploy triggered entirely through the attacker's own, legitimately-owned repository/org, with no access to the victim repository.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
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
      new_status
    end
```
