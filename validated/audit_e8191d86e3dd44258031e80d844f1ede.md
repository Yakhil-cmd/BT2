### Title
Cross-repository status forgery via unscoped SHA lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` applies a GitHub `status` webhook to every `Commit` record in the entire Shipit database that shares the reported SHA, without checking that the commit belongs to the repository/organization whose webhook signature was actually verified. This breaks the trust binding "the organization whose webhook signature was verified" vs. "the repository/stack whose commit status is written," mirroring the reported `Trading.sol` bug class where a value accepted from the caller is acted upon without validating it matches the context the check was actually performed against.

### Finding Description
Webhook signature verification is scoped to a single GitHub organization/app, derived from the payload's `repository.owner.login` (or `organization.login`) field: [1](#0-0) [2](#0-1) 

This only proves the payload was sent by GitHub on behalf of *some* organization/app installation configured in Shipit — it does not prove which specific repository's data the payload is entitled to affect beyond that org.

Once verified, the controller dispatches the parsed JSON body to registered handlers for the event type: [3](#0-2) 

For the `status` event, `StatusHandler#process` looks up commits purely by SHA, with no repository/stack scoping whatsoever: [4](#0-3) 

`Commit.where(sha: params.sha)` matches across **all stacks in the Shipit installation**, regardless of which repository or organization the SHA came from. This is inconsistent with the design intent visible elsewhere in the engine, where stack/repo scoping is enforced (e.g. `Api::BaseController#stacks` scopes by `current_api_client.stack_id`, and merge/status flows elsewhere resolve through `stack.github_repo_name`). The `status` handler is the outlier that trusts the raw `sha` field without any binding check to the repository that was actually authenticated.

`Commit#create_status_from_github!` then creates a `Status` record and triggers `add_status`, which can schedule continuous delivery or unblock the merge queue for whatever stack the matched commit belongs to: [5](#0-4) [6](#0-5) 

### Impact Explanation
If the same commit SHA is tracked by more than one `Stack` in the same Shipit instance — a common situation for forks, mirrors, template-derived repositories, or multiple stacks tracking the same upstream repository (e.g., staging/production environments) — an attacker who controls a commit-status integration on **any one** of the organizations configured in Shipit (their own low-privilege repo/org with a legitimate GitHub App/webhook secret) can forge a `success`/`failure` status for that shared SHA. Because `StatusHandler` does not verify the commit's owning repository matches the authenticated organization, the forged status is applied to commits in **unrelated stacks belonging to other organizations/repositories** as well. If the affected stack has `continuous_deployment: true`, injecting a fabricated `success` status can trigger `stack.schedule_merges`/continuous delivery, i.e., an **unauthorized deploy** on a repository the attacker never had access to — satisfying the "unauthorized deploy" criterion for a Critical/High-impact finding without requiring a Shipit session, ApiClient token, or GitHub write access to the victim repository.

### Likelihood Explanation
Exploitability depends on the existence of a commit SHA shared between an attacker-controlled organization's repository and a victim stack tracked by the same Shipit instance (fork/mirror/template lineage, or multi-environment tracking of the same upstream repo — all realistic multi-tenant Shipit deployment patterns). Given that precondition, no privileged Shipit credential is required: the attacker only needs to cause GitHub to send a legitimately-signed `status` webhook for their own repo (trivial via any status-reporting integration, e.g. a personal access token with `repo:status` on their own repository).

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any similarly-unscoped handler) to the repository that the verified webhook signature actually belongs to — e.g., join through `Stack`/`Repository` using the payload's `repository` field, analogous to how `PushHandler` resolves the target stack, instead of matching bare SHAs globally across the entire `commits` table.

### Proof of Concept
1. Shipit instance is configured with two GitHub App organizations, `org-attacker` and `org-victim`, each with its own webhook secret, per `docs/setup.md`'s multi-org configuration.
2. `org-victim/repo` has stack `S_victim` with `continuous_deployment: true`, tracking commit `C` (SHA `abc123...`) that is also present (identical content/history) in `org-attacker/repo`, tracked by stack `S_attacker` — e.g., because `org-attacker/repo` is a fork of `org-victim/repo` sharing history up to `C`.
3. Attacker, who only controls `org-attacker/repo`, posts a commit status (`success`) for SHA `abc123...` via GitHub's Status API using their own token (no Shipit access needed).
4. GitHub sends a `status` webhook to Shipit's `/webhooks` endpoint, signed with `org-attacker`'s webhook secret. `verify_signature` passes because `repository_owner` resolves to `org-attacker`, which is a legitimately configured org.
5. `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, matching the commit `C` in **both** `S_attacker` and `S_victim`, and applies the forged `success` status to both.
6. Because `S_victim` has continuous deployment enabled, `Commit#add_status` triggers `stack.schedule_merges`, deploying `org-victim/repo` on the attacker's forged status — an unauthorized deploy of a repository the attacker never had write or webhook access to.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/status.rb (L1-20)
```ruby
# frozen_string_literal: true

module Shipit
  class Status < Record
    include Common
    include DeferredTouch

    STATES = %w[pending success failure error].freeze
    enum :state, STATES.zip(STATES).to_h

    belongs_to :stack, required: true
    belongs_to :commit, required: true

    deferred_touch commit: :updated_at

    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```
