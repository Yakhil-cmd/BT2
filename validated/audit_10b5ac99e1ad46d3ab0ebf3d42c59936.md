### Title
Cross-repository commit status/deploy-gating injection via SHA-only scoping in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `status` webhook is authenticated per-organization via HMAC (`WebhooksController#verify_signature` picks the secret using `repository.owner.login` from the payload), but `StatusHandler#process` then acts on **any** `Commit` row in the entire database that matches `params.sha`, with no check that the commit's `stack`/`repository` corresponds to the organization/repository that signed the webhook. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` derives the signing organization from the payload itself (`repository.owner.login`, falling back to `organization.login`) and verifies the HMAC using that org's configured `webhook_secret`: [1](#0-0) [2](#0-1) 

This only proves that *some* configured GitHub App/org sent the request — it says nothing about which repository/commit the payload is allowed to affect. `StatusHandler#process`, however, resolves target rows purely by `sha`, globally, with no repository/stack scoping at all: [3](#0-2) 

Contrast this with the base `Handler#stacks` helper used by other handlers (`PushHandler`, `CheckSuiteHandler`), which does scope by `repository.full_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

`StatusHandler` is the outlier: it looks up `Commit.where(sha: params.sha)` across the whole `commits` table and calls `commit.create_status_from_github!(params)` for every match, regardless of which `Stack`/repository owns that commit: [7](#0-6) 

`create_status_from_github!` writes a `Status` and, through `add_status`, can flip the commit's aggregate CI state, emit `:deployable_status`, and trigger `stack.schedule_merges` — i.e., it can make a commit appear CI-green and eligible for merge/deploy: [8](#0-7) 

**Binding broken:** `organization(webhook_secret) == repository(commit written)`. The signature only proves the sender is a configured org for *some* repo; the write path never re-checks that the `sha` belongs to a commit under a stack whose repository matches that org/repository. If two tracked repositories (in the same or different orgs, e.g. mirrors, forks, subtree splits, or repos that happen to share history/commit objects) contain a commit with the identical SHA, an attacker who can trigger a legitimately-signed `status` webhook from Org A's repo (e.g., by pushing a commit status via CI they control, or by getting Org A's app to relay any status event for a SHA they choose) can cause Shipit to record that status against the matching commit in Org B's stack, influencing `deployable?`/merge-queue decisions there.

### Impact Explanation
This is a cross-repository write: a signed webhook scoped to one repository/org is capable of mutating CI-status state (and downstream deploy-gating decisions such as `schedule_merges`, `deployable_status` hooks, and `deployable?`) for commits belonging to a *different* tracked stack, without any authorization check tying the payload's repository to the affected commit's stack. That matches the "cross-repository writes" / "unauthorized deploy" impact class, since status flips are a direct input to Shipit's continuous-deployment and merge-queue gating (`Commit#deployable?`, `Commit#schedule_continuous_delivery`).

### Likelihood Explanation
Exploitability hinges entirely on being able to get a same-SHA commit to exist across two Shipit-tracked repositories/stacks — this is not automatic for arbitrary attacker-chosen content, since SHA-1 is a hash of tree/commit contents (author, tree, parents, timestamps). It is realistic in scenarios that are common in real deployments: repository mirrors, forks tracked as separate stacks, subtree-split repos, or monorepo/multi-repo setups that intentionally share commit history — none of which require any Shipit privilege, GitHub App key, or elevated GitHub access beyond ordinary push/CI access to one of the tracked repositories. I could not fully verify from the indexed code whether any additional layer (outside `StatusHandler`) re-validates repository identity before `create_status_from_github!` is called during the direct webhook path, so likelihood should be treated as moderate rather than certain until confirmed by manual testing.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler`/`CheckSuiteHandler` do: restrict the `Commit` lookup to commits whose `stack` belongs to `stacks` (i.e., filter by `repository.full_name` from the payload) before calling `create_status_from_github!`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or an equivalent join, instead of an unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Configure Shipit to track two repositories, `org-a/repo` and `org-b/repo`, each with its own webhook secret.
2. Arrange (e.g., via a mirrored/forked history) for a commit with identical SHA `deadbeef...` to exist in both `org-a/repo`'s tracked stack and `org-b/repo`'s tracked stack.
3. From `org-a`'s GitHub App/webhook (properly signed with `org-a`'s `webhook_secret`), send a `status` event with `sha: "deadbeef..."`, `state: "success"`.
4. Observe `Shipit::Webhooks::Handlers::StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matching the commit in `org-b`'s stack via `Commit.where(sha: params.sha)` and calling `create_status_from_github!`, flipping that commit's status/deploy-gating state in `org-b`'s stack despite the webhook never being signed by `org-b`.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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
