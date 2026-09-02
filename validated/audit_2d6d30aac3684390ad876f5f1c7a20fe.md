### Title
`StatusHandler` writes commit statuses without validating the webhook's authenticated repository, allowing cross-repository status forgery - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `WebhooksController` authenticates an inbound GitHub webhook by verifying the HMAC signature against the secret configured for the organization named in the payload (`repository_owner`) [1](#0-0) . That authentication only proves "this payload was sent by GitHub for organization/repo X." Every event handler is expected to re-bind that authenticated repository to the records it mutates via `Handler#stacks`, which resolves stacks strictly from `payload.dig('repository', 'full_name')` [2](#0-1) . `PushHandler` and `CheckSuiteHandler` both use this scoped `stacks` accessor before touching any commit [3](#0-2) [4](#0-3) . `StatusHandler`, however, bypasses this binding entirely and looks up commits globally by SHA across every stack in the installation: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) .

### Finding Description
The binding that is broken is: **the repository/organization whose webhook secret authenticated the request** ≠ **the repository/stack whose commit is actually written to**.

- The webhook is only authenticated per-organization: `Shipit.github(organization: repository_owner)` where `repository_owner` is read straight out of the JSON body [1](#0-0) [6](#0-5) .
- `StatusHandler#process` never consults `repository_name`/`stacks` (the mechanism every other handler uses to scope writes to the repository that was actually signed for) — it matches purely on commit SHA, globally, across the entire `Commit` table [7](#0-6) .
- Because Git SHAs are content-addressed, any external party who forks a public target repository (or otherwise reproduces an identical commit) will naturally produce commits with identical SHAs in their own, unrelated repository. If that party's repository belongs to a different GitHub organization that is *also* configured in this Shipit instance (Shipit explicitly supports multi-organization configuration, each with its own independent `webhook_secret` and GitHub App — see `config/secrets.development.example.yml` multi-org example), then a legitimately-signed `status` webhook from Organization B's repo/commit can carry a `sha` that collides with a commit tracked under a completely different stack belonging to Organization A. `StatusHandler` will apply that status to Organization A's commit, even though Organization B's secret is the only thing that was ever verified.
- This is the direct structural analog of the reported bug: the KintoID/Faucet signature validated one identity (the *signer*) but the state mutation was applied to a different identity (the *account*/`_signature.account`) without the signature covering that binding. Here, the webhook signature validates one repository (the one named in the signed payload / secret), but the mutation (`create_status_from_github!`) is applied to a commit resolved independently of that repository, with no check that the commit's `stack`/`repository` matches the authenticated one.

### Impact Explanation
`Commit#create_status_from_github!` drives `add_status`, which fires `commit_status`/`deployable_status` hooks and can call `stack.schedule_merges` and schedule continuous delivery once a commit becomes "success"/non-pending [8](#0-7) [9](#0-8) . An attacker who controls (or forks) a repository under one authenticated organization can inject a fabricated "success" status onto an unrelated commit in a different stack, satisfying required-status gating and triggering `schedule_merges` / `ContinuousDeliveryJob`, i.e., an unauthorized deploy/merge on a repository the attacker never had write access to. This matches the "Critical - unauthorized deploy, cross-repository writes" impact bar.

### Likelihood Explanation
Exploitation requires: (1) a multi-organization Shipit deployment (explicitly supported/documented), (2) the attacker having ordinary commit-status write access (e.g., a CI integration or `repo:status` token) on any repository under one of the configured organizations, and (3) producing a commit whose SHA collides with a commit in the target stack — trivially achievable by forking a public upstream repo, since forked commits are byte-for-byte identical and thus share the exact same SHA-1. No privileged Shipit session, API token, or webhook secret needs to be obtained; the attacker only needs to trigger GitHub's real webhook delivery for their own repository, which GitHub signs legitimately.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` and `CheckSuiteHandler` do: resolve commits only within `stacks` (derived from the authenticated `repository_name` in the payload), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)`, instead of an unscoped `Commit.where(sha: params.sha)`. More generally, every webhook handler should be audited to ensure the resource it mutates is always constrained to the repository that the webhook signature actually authenticated, not merely matched by an incidental field such as SHA.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `org-a` and `org-b`, each with its own GitHub App/webhook secret (per documented multi-org setup).
2. Shipit tracks `org-a/target-repo` as a stack; it has a commit `C` with SHA `abc123...` currently in `pending`/unmet-required-status state, blocking auto-merge/deploy.
3. Attacker, who only has status/CI write access to `org-b/attacker-repo`, forks `org-a/target-repo`'s history into `org-b/attacker-repo` (or otherwise reproduces commit `C` verbatim), producing an identical commit with SHA `abc123...` in `org-b`.
4. Attacker sets a "success" commit status on SHA `abc123...` in `org-b/attacker-repo` via the GitHub API (using their own legitimate `repo:status` token).
5. GitHub sends a `status` webhook to Shipit, signed with `org-b`'s webhook secret; `WebhooksController#verify_signature` verifies it successfully against `org-b`.
6. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, finds commit `C` belonging to the `org-a/target-repo` stack, and calls `create_status_from_github!`, marking it `success` — even though the request was never authenticated for `org-a`.
7. This satisfies required-status checks on `C`, triggering `stack.schedule_merges`/continuous delivery, resulting in an unauthorized merge/deploy on `org-a/target-repo`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

**File:** app/models/shipit/commit.rb (L280-287)
```ruby

    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
