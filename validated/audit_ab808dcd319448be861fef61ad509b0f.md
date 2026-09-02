### Title
Cross-repository commit-status forgery via unscoped `sha` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook against the **organization** derived from the payload (`repository_owner`), but `StatusHandler#process` writes commit-status data using only the raw `sha` field, with no check that the matched `Commit` actually belongs to a stack/repository owned by that authenticated organization. This breaks the binding "organization authenticated == repository/commit record written."

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC signature using `repository_owner`, which is read straight out of the untrusted JSON payload: [1](#0-0) [2](#0-1) 

Once the signature is verified for that organization, the controller dispatches to the event handler with the full raw payload: [3](#0-2) 

Most handlers correctly re-derive the target `Repository`/`Stack` from `repository.full_name` before acting, e.g. the base `Handler#stacks`/`#repository_name` helpers and `PushHandler`: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, never scopes to a repository at all — it looks up `Commit` records globally by SHA and mutates their status: [6](#0-5) 

Git commit SHAs are content hashes of the commit (tree + parents + metadata), so a forked repository naturally shares identical SHAs with its upstream for the common history. If an attacker controls (or has webhook-triggering access to) any organization/repository that this Shipit instance tracks — e.g. by forking a repository that is also tracked under a different, unrelated organization — a genuine, correctly-signed `status` webhook from the attacker's own org will still pass `verify_signature` (since it is validated against the attacker's own org's real webhook secret), yet `StatusHandler` will apply the status update to *every* `Commit` row sharing that SHA, including commits that belong to the victim organization's stack. This is precisely the equality the report's bug class targets: the entity whose secret was checked (`repository_owner`) is not the entity whose data is written (any repository containing a `Commit` with that SHA).

### Impact Explanation
Commit statuses feed into a stack's release/merge readiness signals (via `Commit#create_status_from_github!` and downstream `Status`/merge-status computation). An attacker able to trigger genuinely-signed webhooks for one onboarded organization can forge "success" (or malicious) CI status entries against commits belonging to a completely different, unrelated organization's stack tracked by the same Shipit instance, without ever needing that victim organization's webhook secret or repository write access. This can be used to make an unrelated repository's commit appear to have passing checks, contributing to an unauthorized deploy decision for that stack — matching the High-impact bar of "escalation... unauthenticated... state" manipulation across repository boundaries in this engine.

### Likelihood Explanation
Exploitability depends on the attacker controlling (or being able to trigger webhooks for) at least one organization already onboarded to the Shipit instance and having a commit SHA collision with the victim's tracked repository — most realistically achieved via a fork of a public/shared repository, which is a common and cheap setup requiring no special privileges beyond normal GitHub webhook configuration for the attacker's own org. It does not require any Shipit session, API token, or the victim's secret.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository identified in the payload (consistent with how `Handler#stacks`/`PushHandler` resolve `Repository.from_github_repo_name(repository_name)`), so that a status update can only affect commits within stacks belonging to the same repository (and therefore the same authenticated organization) that the webhook signature was verified against, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker administers (or has webhook rights to) Organization A, which is onboarded to the target Shipit instance with its own valid `webhook_secret`.
2. Attacker forks Organization B's tracked repository into Organization A (or otherwise obtains a repository sharing commit history/SHAs with Organization B's tracked repository).
3. GitHub sends a normal, correctly-signed `status` event for a commit SHA `S` that exists in both Organization A's fork and Organization B's original repository.
4. `WebhooksController#verify_signature` validates the signature using Organization A's secret and passes.
5. `StatusHandler#process` executes `Commit.where(sha: S)`, matching commit rows in *both* Organization A's and Organization B's stacks, and calls `create_status_from_github!` on all of them — writing a forged status onto Organization B's commit despite the webhook never having been authenticated for Organization B.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
