## Analysis Result

### Title
Unscoped commit lookup in `StatusHandler` lets any organization's webhook forge CI status for commits belonging to a different, unrelated stack/repository, enabling unauthorized merges/deploys - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit's `WebhooksController` authenticates an incoming GitHub webhook against the `webhook_secret` of the organization named in the payload (`repository.owner.login`), then dispatches the raw payload to per-event handlers. For the `status` event, `Shipit::Webhooks::Handlers::StatusHandler` does not verify that the reported commit SHA belongs to the *repository/organization that was actually authenticated*. It instead looks up commits **globally**, across every stack in the entire installation, and writes a GitHub-reported CI status onto whatever commit row matches that SHA. [1](#0-0) 

Compare this to the sibling `CheckSuiteHandler`, which correctly scopes lookups through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`) before touching any commit: [2](#0-1) [3](#0-2) 

### Finding Description
The equality that should hold is:

`organization/repository whose webhook_secret authenticated this payload == repository that is written to as a result of processing it`

`WebhooksController#verify_signature` derives the signing organization strictly from the payload itself (`repository.owner.login`, falling back to `organization.login`) and picks that organization's `GitHubApp`/`webhook_secret` to validate the HMAC signature: [4](#0-3) [5](#0-4) 

This only proves that the request came from *some* configured GitHub organization — the one named inside its own payload — nothing more. It says nothing about which `Repository`/`Stack` the handler is permitted to mutate.

`StatusHandler#process`, however, ignores the `Handler#stacks` scoping helper entirely (which restricts operations to the `Repository.from_github_repo_name(repository_name)` that matches the authenticated payload) and instead queries `Commit` unscoped, by SHA alone, across **every** stack of **every** repository/organization configured in the Shipit instance: [1](#0-0) 

`Commit#create_status_from_github!` then persists a `Status` under that commit's real, pre-existing `stack_id`: [6](#0-5) [7](#0-6) 

Because Git commit SHAs are computed purely from commit content (tree, parents, author/committer, timestamps, message) and never include the hosting repository or organization, an attacker who controls a *separate* repository (their own fork, or any repo they can push to, in the same or a different GitHub organization onboarded into this Shipit install) can reconstruct an identical linear history/commit object that hashes to the exact same SHA as a commit that exists in a completely unrelated victim stack. The attacker's own repository legitimately triggers a `status` webhook, correctly signed with *their own* organization's `webhook_secret`. `verify_signature` passes because it only checks that signer against the payload's own `repository.owner.login` — it never re-validates that the SHA being reported actually belongs to that organization's repository. `StatusHandler` then blindly stamps the attacker-chosen `state`/`context`/`description` onto the victim commit under the victim's real stack.

This directly parallels the referenced Babylon bug: a specific field (`params.sha`, analogous to `stakingTx`) is acted upon by privileged application logic (writing a `Status` that feeds CD/merge gating, analogous to voting power) without the code performing the one additional check needed to prevent a specially-crafted value from bypassing the security property (verifying repository ownership of the SHA, analogous to rejecting coinbase transactions).

### Impact Explanation
A forged `success` status on a required CI context (e.g., `ci/travis`, `continuous-integration/*`) for a victim commit:
- Satisfies `MergeRequest::StatusChecker` / `required_statuses` in `stack.cached_deploy_spec`, allowing `MergeRequest#reject_unless_mergeable!` to pass and the merge queue to auto-merge the PR via `MergeRequest#merge!`. [8](#0-7) 
- Triggers `Status#schedule_continuous_delivery` and `Commit#enable_ci_on_stack`, feeding continuous deployment for the victim stack. [9](#0-8) 

This is an unauthorized-merge/unauthorized-deploy primitive achievable by anyone who controls a distinct repository whose webhook reaches this Shipit instance — not the victim repository, and without any Shipit session, `ApiClient` token, or GitHub write access to the victim repository. This matches the "Critical: unauthorized deploy, rollback or merge" impact bucket.

### Likelihood Explanation
The attacker needs: (1) push/webhook access to some repository (any repository) whose organization is configured in this Shipit instance (self-owned repo in a shared org, or their own organization if multi-tenant), and (2) the ability to reconstruct a commit object with an identical SHA to a target commit — achievable trivially for public target repositories by replaying the exact history (same author/committer identities, timestamps, tree, and messages), since none of these inputs to the SHA include the hosting repository. No SHA-1 collision attack is required. This is a realistic, low-cost path, not merely theoretical.

### Recommendation
`StatusHandler#process` must be scoped like `CheckSuiteHandler`/`Handler#stacks`: only look up commits within `stacks` derived from the authenticated `repository_name` of the current payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (or `Commit.joins(:stack).merge(stacks).where(sha: params.sha)`), instead of the current global `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker owns/controls `attacker-org/attacker-repo`, which is onboarded to the same Shipit instance (own GitHub App installation, own `webhook_secret`).
2. Attacker pushes a commit whose tree, parent chain, author, committer, and message are byte-identical to a real commit `abc123...` that exists in `victim-org/victim-repo`'s tracked branch/stack (feasible for any public repo history, or any history the attacker can observe). Git computes the identical SHA `abc123...`.
3. Attacker sets a `status` on `abc123...` in `attacker-repo` (e.g., via the GitHub API/UI) with `context: "ci/travis"`, `state: "success"`. GitHub delivers a `status` webhook to Shipit, signed with `attacker-org`'s `webhook_secret`.
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "attacker-org")` and verifies successfully — the signature is valid for that org.
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, matching the victim's commit row (in `victim-repo`'s stack), and calls `create_status_from_github!`, creating a `success` `Status` under the **victim stack**.
6. The victim stack's merge queue/CD pipeline now sees the required `ci/travis` context as passing for that commit, even though the actual CI run for `victim-repo` never reported success, enabling an unauthorized merge/deploy.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

**File:** app/models/shipit/merge_request.rb (L155-176)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
```
