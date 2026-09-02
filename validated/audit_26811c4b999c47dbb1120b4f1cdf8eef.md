### Title
Webhook signature-verification identity (`repository.owner.login`) is not bound to the repository/commit actually mutated by handlers, allowing cross-repository forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using `repository_owner` (`params.dig('repository','owner','login')`), while every downstream `Webhooks::Handlers::Handler` subclass identifies the repository/commit to *mutate* using a completely different, independently-attacker-controlled field of the same JSON body — `payload.dig('repository','full_name')` in `Handler#repository_name`, or (worse) a bare global `sha` lookup in `StatusHandler`. These two fields are never cross-checked against each other, so the "organization that authenticated" and the "repository that is written" are two different bindings that an attacker who controls the secret for *any one* organization configured on the Shipit instance can decouple.

### Finding Description
`Shipit::WebhooksController#verify_signature` does: [1](#0-0) 
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

The secret used for the HMAC check is looked up per-organization via `Shipit.github(organization: repository_owner)`, and `verify_webhook_signature` just does a `secure_compare` of the HMAC over the *raw body* using that organization's `webhook_secret`: [3](#0-2) 

Crucially, only `repository_owner` is authenticated — nothing in this check constrains which repository the event payload is allowed to describe. Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers that use a *different* field to decide what to act on: [4](#0-3) 
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`PushHandler#process` and `CheckSuiteHandler#process` use `stacks` (i.e. `repository.full_name`) to look up the target `Stack`, and then call `stack.sync_github(...)` / `schedule_refresh_check_runs!` on it: [5](#0-4) [6](#0-5) 

`StatusHandler#process` is even less scoped — it doesn't use `repository_name`/`stacks` at all, it just matches on the global `sha` column across the entire instance: [7](#0-6) 
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

Since `repository.owner.login` (used to pick the verification secret) and `repository.full_name`/`sha` (used to pick the mutated record) are both attacker-supplied fields inside the same POST body, and there is no check that `repository.full_name` actually belongs to the organization named in `repository.owner.login`, an attacker who legitimately knows the `webhook_secret` for *one* organization/GitHub App configured in this Shipit instance can sign an arbitrary payload with that secret while pointing `repository.full_name` (or `sha`) at a stack/commit belonging to a *different* organization entirely.

Injected forged commit statuses feed directly into deployability logic: `Commit#deployable?` and `Commit#status` are computed purely from `statuses`/`check_runs` rows, and `add_status` triggers `stack.schedule_merges` and `schedule_continuous_delivery` when the new status is `success`: [8](#0-7) [9](#0-8) [10](#0-9) 

### Impact Explanation
An attacker who owns/administers a GitHub App or webhook integration for one organization tracked by this Shipit instance (an unprivileged actor with respect to *other* orgs/repos on the same instance) can:
- Forge `status` events with `state: success` for arbitrary commit SHAs belonging to unrelated stacks, satisfying `Commit#deployable?`/`blocking?` checks and triggering `stack.schedule_merges` / continuous delivery — enabling an **unauthorized deploy** on a repository the attacker has no legitimate relationship with.
- Forge `push`/`check_suite` events pointing `repository.full_name` at a victim stack, invoking `stack.sync_github(expected_head_sha: ...)` with attacker-chosen values.

This crosses the "cross-repository writes / unauthorized deploy" bar defined in the rules, since the binding broken is exactly "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
Requires the attacker to control (or know) the `webhook_secret` for at least one organization configured on the target Shipit instance — a realistic scenario for any multi-tenant/shared Shipit deployment where different teams/orgs each register their own GitHub App/webhook secret, since none of those secrets are meant to authorize actions on *other* organizations' repositories. No GitHub webhook is actually required — the attacker can POST directly to `WebhooksController#create` with a self-signed payload.

### Recommendation
After signature verification, assert that the organization whose secret validated the signature actually matches the owner of `repository.full_name` (and, in `StatusHandler`, scope the `Commit` lookup by `stack`/`github_repo_name` derived from that same verified repository, not solely by `sha`). Reject the event if `repository.owner.login` used for secret selection does not match the organization implied by `repository.full_name`.

### Proof of Concept
1. Attacker administers organization `attacker-org`'s GitHub App on a shared Shipit instance and knows its `webhook_secret`.
2. Attacker crafts:
```json
{
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" },
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>`, sets `X-Github-Event: status`, POSTs to `/github/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and the signature validates successfully. `StatusHandler` then writes a forged `success` status onto `victim-org/victim-repo`'s commit, potentially unblocking/triggering its deploy pipeline.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
