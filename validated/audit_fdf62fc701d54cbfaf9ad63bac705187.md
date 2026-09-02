This confirms the exploitable analog: `StatusHandler#process` looks up commits globally by SHA, `Commit.where(sha: params.sha)`, with no scoping to the repository whose organization was authenticated by `verify_signature`. `verify_signature` in `WebhooksController` selects the GitHub App / webhook secret using `repository_owner` from the payload [1](#0-0) , but the handler that executes the effect (`StatusHandler`) never re-checks that the SHA belongs to a commit under that same organization/repository — it matches any commit across the entire installation by SHA alone [2](#0-1) . By contrast, other handlers (`PushHandler`, `CheckSuiteHandler`) correctly scope through `Handler#stacks`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any stack [3](#0-2) .

### Title
Cross-repository commit status forgery via unscoped SHA lookup in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the GitHub App/organization inferred from the payload's `repository.owner.login` (or `organization.login`) [1](#0-0) . This authenticates that the request legitimately originates from *that* organization's installed app. However, `StatusHandler#process` — invoked after successful verification — does not use the payload's `repository` field to scope its effect; it resolves target commits solely by `sha` across the *entire* Shipit installation: `Commit.where(sha: params.sha)` [2](#0-1) .

### Finding Description
The trust binding that should hold is: `organization authenticated by verify_signature == repository whose commits are written`. `verify_signature` uses `repository_owner` purely to select the webhook secret/app config for HMAC verification [4](#0-3) , but places no constraint on which `repository`'s stacks the handler may mutate. `StatusHandler`, unlike `PushHandler` and `CheckSuiteHandler`, never calls the base class's `stacks` helper (which correctly scopes lookups through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` [3](#0-2) ). Instead it queries `Commit.where(sha: params.sha)` globally.

Since git SHAs are content-addressed and often shared/predictable across forks, mirrors, or commits cherry-picked/rebased between unrelated repositories tracked by the same Shipit instance, an attacker who controls (or is a legitimate collaborator of) *any* organization/repository with a correctly configured Shipit webhook can send a `status` event whose `sha` matches a commit that actually belongs to a *different*, unrelated stack/repository also managed by this Shipit instance. Because the org used for signature verification (`repository.owner.login`, taken from the same attacker-controlled payload) only needs to match the org the attacker's own app/webhook is installed on, the HMAC check passes trivially for the attacker's own webhook secret — yet the effect (`commit.create_status_from_github!`) is applied to a `Commit` belonging to a completely different stack whose repository ownership was never checked.

### Impact Explanation
`create_status_from_github!` drives `Commit#add_status`, which updates the commit's CI status, can flip `deployable?`, and schedules `stack.schedule_merges` when the status becomes `pending`/`success` [5](#0-4) . Forging a `success` status on another organization's commit can make that commit `deployable?` and trigger an unauthorized merge/deploy queue action (`schedule_merges`) on a stack the attacker does not control and was never authorized to touch — matching the "unauthorized deploy, rollback or merge" High/Critical impact category, achieved purely by an attacker with only their own repository's webhook credentials (no privileged access to the victim stack).

### Likelihood Explanation
Likelihood is constrained by needing a SHA collision/reuse between the attacker's own authenticated repository and the victim's tracked repository within the same Shipit deployment — this is realistic in shared-fork/mono-organization Shipit setups (e.g. forks, mirrors, vendored branches, or cherry-picked commits) but not universal. The authentication step itself imposes no barrier since the attacker already legitimately owns a webhook/app installation for some repository tracked by the instance.

### Recommendation
Scope `StatusHandler#process` (and any other handler bypassing `Handler#stacks`) through the payload's `repository.full_name`/`Repository.from_github_repo_name`, restricting the `Commit.where(sha: ...)` lookup to `stacks.flat_map(&:commits)` or equivalent, so status updates can only ever apply to commits belonging to the repository whose organization was cryptographically verified.

### Proof of Concept
1. Attacker operates (or is an authorized member of) `attacker-org/attacker-repo`, which has a legitimately configured Shipit GitHub App/webhook (`webhook_secret` known to attacker via GitHub's own delivery mechanism, or attacker triggers a real CI status webhook from their own repo).
2. Attacker discovers/engineers a commit SHA that also exists as a tracked commit in `victim-org/victim-repo`'s Shipit stack (e.g., via a shared upstream commit, cherry-pick, or fork relationship both instances track).
3. Attacker sends a GitHub `status` webhook event with `repository.owner.login = attacker-org` (so `verify_signature` selects and validates against the attacker's own known webhook secret) but `sha` set to the victim commit's SHA, `state: success`.
4. `WebhooksController#verify_signature` passes because the HMAC matches the attacker's own app config for `attacker-org`.
5. `StatusHandler#process` runs `Commit.where(sha: <victim_sha>)`, finds the victim's commit, and calls `create_status_from_github!`, marking it `success` and potentially triggering `stack.schedule_merges` on `victim-org/victim-repo`'s stack — a write the attacker was never authorized to make.

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
