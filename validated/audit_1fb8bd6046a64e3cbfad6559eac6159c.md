### Title
StatusHandler applies GitHub `status` webhook to any commit with a matching SHA across all stacks, regardless of which repository the signature authenticated - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub organization derived from the payload (`repository_owner`), but the `status` event handler then writes to `Commit` rows matched purely by `sha`, with no constraint tying the write back to the repository/organization that produced the verified signature. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp`/webhook secret to validate the request against using only `repository_owner`, derived from the payload itself: [1](#0-0) [2](#0-1) 

Once the signature is accepted, the full, unscoped `params` hash is dispatched to every registered handler for the event: [3](#0-2) 

For the `status` event, `StatusHandler#process` updates *every* `Commit` record in the entire Shipit installation whose `sha` matches the payload, with no filter on `stack`, `repository`, or organization: [4](#0-3) 

`Commit.sha` is only unique per-`stack`, not globally, as shown by the migration adding a composite unique index on `(sha, stack_id)`: [5](#0-4) 

This means the same commit SHA can legitimately exist in multiple `Stack` rows belonging to different repositories/organizations (e.g., forks or repos that share commit history). The webhook signature only proves "this event genuinely came from GitHub for organization X," it says nothing about which `stack`/`repository` the resulting DB write should be scoped to - yet `StatusHandler` writes to any commit matching the bare SHA, effectively treating the (authenticated organization) and (repository actually written) as the same binding when they are not enforced to be equal anywhere in the code.

The consequence of a successful match is not inert: `Commit#create_status_from_github!` → `add_status` triggers `stack.schedule_merges` whenever the new status is `pending` or `success`, and required/blocking statuses (`Stack#required_statuses`, `blocking_statuses`) are precisely what gates automatic merges/continuous deployment for a stack: [6](#0-5) [7](#0-6) 

### Impact Explanation
An attacker who legitimately controls any repository within an organization that has the Shipit GitHub App installed (fully unprivileged with respect to any *other* tracked repository/stack) can:
1. Copy/fork a commit that also exists in a victim stack tracked by the same Shipit instance (identical SHA — trivial when repos share history, e.g. forks/mirrors of the same upstream, which Shipit commonly tracks as separate stacks/environments).
2. Push a genuine GitHub `status` event for that SHA from their own repository (fully legitimate, GitHub-signed webhook — no forged signature, no stolen `webhook_secret` needed).
3. Shipit accepts the signature because it is valid for that organization, then `StatusHandler` blindly attaches the status to *every* `Commit` row across the whole installation with that SHA — including the victim's commit in an unrelated stack the attacker has no access to.
4. If the injected status is `success` for a `required`/`blocking` context, this can satisfy merge-queue and continuous-delivery gating logic (`schedule_merges`, `deployable?`) for the victim stack, resulting in an unauthorized deploy or merge that the attacker never had permission to trigger.

This matches the "unauthorized deploy, rollback or merge" Critical-impact category, achieved purely by exploiting the mismatch between the authenticated scope (organization via signature) and the write scope (global `Commit.where(sha:)`).

### Likelihood Explanation
Likelihood is moderate: it requires (a) the target Shipit instance to track multiple stacks/repositories sharing commit history (common for forks, mirrors, or multi-repo orgs with copied history) and (b) the attacker to have write/status-setting rights on some tracked repository other than the victim's. No secret material, no session, and no forged signatures are required — only ordinary GitHub repository permissions the attacker already legitimately holds on their own repo.

### Recommendation
Scope `StatusHandler` (and any handler consuming attacker-influenceable identifiers like `sha`) to the specific repository the signature was verified against, e.g. filter `Commit.joins(:stack).where(sha: params.sha, stacks: { repository: repository_from_payload })` rather than matching bare `sha` globally. More generally, ensure every webhook handler enforces that the entity it mutates belongs to the same repository/organization that `verify_signature` authenticated, closing the gap between "who signed this" and "what gets written."

### Proof of Concept
1. Shipit instance tracks Stack A (org `Acme`, repo `acme/upstream`) and Stack B (org `Acme`, repo `acme/downstream-fork`, a fork of `upstream`), both installed under the same GitHub App/webhook secret.
2. Attacker has ordinary contributor access to `acme/downstream-fork` only (no access to `upstream`).
3. Attacker identifies a commit SHA `c0ffee...` present in both `upstream`'s tracked history (Stack A) and the shared fork history (Stack B), e.g. a commit inherited before the fork diverged.
4. Attacker sets a commit status (`success`, context matching a `required_statuses` entry configured for Stack A, e.g. `ci/tests`) on `c0ffee...` via the GitHub API on their own repo `acme/downstream-fork` (fully authorized action for their own repo).
5. GitHub sends a genuinely signed `status` webhook to Shipit for `acme/downstream-fork`; `verify_signature` passes because the signature is valid for org `Acme`.
6. `StatusHandler#process` runs `Commit.where(sha: 'c0ffee...')`, matches the commit row belonging to Stack A (`upstream`), and calls `create_status_from_github!`, setting the required status to `success` on the victim's commit and triggering `stack.schedule_merges` for Stack A — despite the attacker never having write access to `acme/upstream`.

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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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
