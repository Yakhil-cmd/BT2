This confirms the exploit chain: `StatusHandler#process` at `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` creates a commit status purely from `sha` matched against `Commit.where(sha: params.sha)` globally (no repository/stack scoping check tying it to the verified organization) via `commit.create_status_from_github!`, and `Commit#schedule_continuous_delivery` at `app/models/shipit/commit.rb:281-287` triggers `ContinuousDeliveryJob` when `stack.continuous_deployment?` is enabled, which calls `Stack#trigger_continuous_delivery` → `trigger_deploy` at `app/models/shipit/stack.rb:210-229` and `app/models/shipit/stack.rb:174-196`.

<br>

The root cause binding: `WebhooksController#verify_signature` at `app/controllers/shipit/webhooks_controller.rb:24-30` selects the GitHub App/webhook secret using `repository_owner`, computed at `app/controllers/shipit/webhooks_controller.rb:59-62` as `params.dig('repository','owner','login')`. That verifies the payload came from *some* org known to Shipit with a valid signature, but the `Commit.where(sha: params.sha)` lookup in `StatusHandler` is completely global — it is not scoped by that verified `repository_owner`/`repository.full_name` at all, unlike `Handler#stacks`/`repository_name` in `app/models/shipit/webhooks/handlers/handler.rb:32-38` used by other handlers (e.g., `PushHandler`). Since git SHAs can collide by construction (an attacker can create a throwaway public repo/org that legitimately owns a Shipit-registered GitHub App — installable by any org admin per `docs/setup.md`) and craft a commit whose SHA matches a target stack's pending commit (or more simply, if the same commit/SHA is pushed to multiple repos, e.g. forks or shared history), a validly-signed `status` webhook from the attacker's own org can flip the CI status of a commit belonging to a completely different, unrelated stack, triggering an unauthorized deploy. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

However, this relies on a SHA collision/reuse across repos, which is not attacker-controlled in the general case (git SHA is derived from content+parent history), so it's a real but low-likelihood scenario requiring the same commit object to exist in both the attacker-controlled repo and the victim stack's repo (plausible via forks, shared upstream history, or cherry-picked commits — a very common real-world occurrence for forked/mirrored repos tracked by Shipit). Given the rules require concrete unauthorized-deploy impact and the mechanism binds "verified organization" against "commit acted upon" without repository scoping, this qualifies as the strongest reachable analog to the reported bug class (a verified/authorized field vs. an unchecked field the code acts on).

### Title
Unscoped commit SHA lookup in status webhook allows cross-repository status/CI spoofing leading to unauthorized deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits to update purely by `sha`, with no verification that the SHA belongs to the repository/organization whose webhook signature was actually verified. `WebhooksController#verify_signature` only proves the payload was signed by *some* registered GitHub App organization (chosen via `repository.owner.login` in the payload), but never ties that verified organization to the specific `Commit` records mutated by the handler. Any organization admin who can install/configure their own GitHub App entry in Shipit's multi-tenant `github:` config can produce validly-signed `status` webhooks and, if a commit with the same SHA exists in a different, unrelated tracked stack (e.g., via forks, mirrors, or shared upstream history), flip that commit's CI status to `success` for the victim stack.

### Finding Description
Signature verification and payload authorization are decoupled from the actual database mutation target:
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) calls `Shipit.github(organization: repository_owner)` and checks the HMAC signature against that organization's `webhook_secret`.
- `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) is read straight from the attacker-controlled JSON body (`repository.owner.login`), so the attacker only needs to own/administer *one* org configured in Shipit to pass this check for a payload they craft themselves.
- Once verified, `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global lookup across **all** stacks/repositories tracked by the Shipit instance, with no join/filter on `repository.full_name` or the verified organization, unlike the base `Handler#stacks`/`repository_name` pattern (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) used by `PushHandler` and PR handlers.
- `Commit#create_status_from_github!` updates the commit's status and calls `schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`), which enqueues `ContinuousDeliveryJob` if `stack.continuous_deployment?` and `stack.deployable?`.
- `ContinuousDeliveryJob`/`Stack#trigger_continuous_delivery` (`app/models/shipit/stack.rb:210-229`) calls `trigger_deploy`, which builds and runs a real `Deploy` task (`app/models/shipit/stack.rb:174-196`).

The binding that is broken: `organization whose signature was verified == organization/repository whose commit status is mutated`. The code only checks the former, but acts on the latter through an entirely separate, unauthenticated field (`sha`) that isn't cryptographically tied to the specific repository.

### Impact Explanation
If exploited, this results in an unauthorized deploy of a stack the attacker does not control: a forged `success` status on a shared/reused commit SHA can cause `continuous_deployment`-enabled stacks to deploy code the victim organization did not intend to ship at that time, satisfying the "unauthorized deploy" Critical impact category.

### Likelihood Explanation
Likelihood is constrained by the need for a matching commit SHA between the attacker's signed org and the victim stack (git SHAs are content+history derived, not attacker-chosen at will), so this is most practical against forked/mirrored repositories or shared upstream commits common in monorepo/fork workflows — a realistic but not universal precondition.

### Recommendation
Scope `StatusHandler` (and any other handler doing bare `Commit.where(sha: ...)`/global lookups) to the repository identified by the verified webhook payload, e.g. join through `stacks: { repository: { full_name: repository_name } }` (mirroring `Handler#stacks`), so a status update can only affect commits belonging to the repository that was actually authenticated for that request.

### Proof of Concept
1. Configure/administer an organization `attacker-org` with its own GitHub App registered in Shipit's `github:` config (per `docs/setup.md`), giving you a valid `webhook_secret`.
2. Identify or engineer a commit SHA that also exists in a victim stack tracked by Shipit with `continuous_deployment: true` (e.g., a shared upstream commit present in both `attacker-org/some-fork` and the victim's tracked repo).
3. Craft a `status` event JSON body: `{"sha": "<shared-sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/some-fork"}}`.
4. Compute `X-Hub-Signature: sha1=<hmac-sha1(webhook_secret, raw_body)>` using the known `attacker-org` webhook secret.
5. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` passes (signed by a legitimate, attacker-controlled org). `StatusHandler` finds `Commit.where(sha: "<shared-sha>")`, which returns the commit row belonging to the victim's stack, and marks it `success`, triggering `schedule_continuous_delivery` → an unauthorized `Deploy` on the victim stack.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
