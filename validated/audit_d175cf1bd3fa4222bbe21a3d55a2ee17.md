### Title
Cross-organization commit status forgery via SHA-only scoping in `StatusHandler` bypasses per-org webhook signature binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `status` webhook is authenticated per-organization: `WebhooksController#verify_signature` resolves the `GitHubApp` config (and its `webhook_secret`) using `repository_owner`, which is read straight out of the payload (`repository.owner.login`/`organization.login`), and verifies the HMAC signature against that org's secret only. [1](#0-0) [2](#0-1)  However, once the signature is accepted, `StatusHandler#process` does not re-check that the status applies to a commit belonging to the same organization/repository that was authenticated — it looks up commits globally by SHA only: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2)  This contrasts with `Handler#stacks`, used by other handlers like `PushHandler`, which properly scopes lookups through `Repository.from_github_repo_name(repository_name)` derived from the same authenticated payload. [4](#0-3) 

### Finding Description
This breaks the binding: **organization authenticated (via `repository_owner` and its `webhook_secret`) == repository/commit actually written**.

Before the attacker's request: a legitimate installation of the Shipit GitHub App on organization `attacker-org` (which the attacker fully controls, e.g., a self-installed app on their own GitHub org/repo) can deliver correctly-signed `status` webhooks for events on `attacker-org`'s own repositories. Shipit's `verify_signature` looks up the `GitHubApp` for `repository_owner = attacker-org` and validates the signature using `attacker-org`'s `webhook_secret` — this succeeds because it is a genuine webhook from GitHub for that installation.

After: the `StatusHandler` invoked by `Webhooks.for_event('status')` does not consult `repository_owner`/`repository.full_name` at all. It matches `Commit.where(sha: params.sha)` across the entire `commits` table, spanning every stack/repository tracked by this Shipit instance, regardless of organization. [5](#0-4)  If a target's tracked commit (e.g., on `victim-org/prod-repo`) has the same SHA as a commit the attacker can produce a signed status for — trivially achievable since Git commit SHAs are derived only from tree/parent/commit metadata, so an attacker can fork/mirror the target's public commit history into their own controlled repo and get byte-identical commits/SHAs — then a single legitimately-signed `status` event from `attacker-org` writes a `Status` record onto the victim's commit via `commit.create_status_from_github!(params)`, which calls `statuses.replicate_from_github!` and recomputes `commit.status` / `deployable?`. [6](#0-5) [7](#0-6) 

This is the exact class of "leftover trust binding" bug from the report (arbitrary/uncontrolled parameter used post-authentication to act on a resource outside the authenticated scope), mapped onto Shipit's webhook trust model: signature verification authenticates an *organization*, but the write target is chosen by an attacker-influenced field (the SHA) with no repository/org check.

### Impact Explanation
`Commit#deployable?` gates whether `ContinuousDeliveryJob` fires and whether merges/deploys proceed (`success? && !blocked?`). [7](#0-6) [8](#0-7)  By injecting a forged `success` status (or a forged `failure`/blocking status for sabotage) onto a victim commit that Shipit tracks under a different, unrelated GitHub organization, an attacker who only controls their own GitHub org/App installation can influence CI-gating for a victim's stack, potentially triggering an unauthorized/premature deploy via `schedule_continuous_delivery`, or blocking a legitimate one. This satisfies the "unauthorized deploy" High/Critical impact bar, since it escalates a single-org-scoped webhook credential into cross-organization influence over deploy gating without any repository write access or privileged Shipit account.

### Likelihood Explanation
Requires: (1) the attacker's own GitHub App/org webhook is validly configured (a normal, low-privilege setup any onboarded org has), and (2) a commit SHA collision between the attacker's repo and the victim's tracked commit. This is not a cryptographic SHA-1 collision — it only requires the attacker to reproduce the *exact same commit content/history* (author, committer, timestamps, tree, message, parent) in a repo they control, which is achievable for any commit that is publicly visible (e.g., forking a public target repo, or replaying a known open-source commit that a victim also deploys). This is a realistic bar for public/open-source-adjacent deployments and squarely within "unprivileged attacker" scope required by the rules.

### Recommendation
Scope `StatusHandler#process` (and any other handler using bare `Commit`/global lookups) to the repository authenticated by the webhook, mirroring `Handler#stacks`: resolve commits via `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` (or equivalent) instead of an unscoped `Commit.where(sha: ...)`, so a status can only be applied to commits belonging to stacks under the repository/organization that produced the verified signature.

### Proof of Concept
1. Attacker owns `attacker-org/mirror-repo`, with the Shipit GitHub App installed and a valid `webhook_secret` configured for `attacker-org`.
2. Attacker forks/mirrors `victim-org/prod-repo`'s history into `attacker-org/mirror-repo`, producing commit `C` with SHA `deadbeef...` — identical to a commit Shipit already tracks for `victim-org/prod-repo`.
3. Attacker triggers (or fabricates via any CI integration they control on their own repo) a GitHub `status` event for commit `deadbeef...` with `state: success`, `context: <required CI context>`, for `attacker-org/mirror-repo`. GitHub signs this with `attacker-org`'s webhook secret.
4. `WebhooksController#verify_signature` succeeds (correct org, correct secret). [1](#0-0) 
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: 'deadbeef...')` — matching the victim's tracked commit as well — and calls `create_status_from_github!`, recording a forged `success` status on the victim's commit. [3](#0-2) 
6. If `victim-org/prod-repo`'s stack has continuous deployment enabled, `Commit#schedule_continuous_delivery` may now fire based on the forged status. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

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
