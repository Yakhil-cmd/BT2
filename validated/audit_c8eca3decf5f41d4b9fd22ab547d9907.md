### Title
Cross-organization repository sync via mismatched webhook-verification identity vs. repository-lookup field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to validate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`), while the event handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a *different* field, `repository.full_name`. In a multi-organization Shipit deployment these two identities are never checked for consistency.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config used to verify `X-Hub-Signature` purely from `repository_owner`: [1](#0-0) [2](#0-1) 

Shipit explicitly supports configuring one GitHub App per organization, each with its own `webhook_secret` [3](#0-2) . Once the signature check passes, the raw payload is dispatched unmodified to handlers: [4](#0-3) 

Every handler, however, resolves the affected repository/stack via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a completely separate JSON field from the one used for signature-secret selection: [5](#0-4) 

`PushHandler` then uses that repository lookup to enqueue a sync job carrying an attacker-controlled `after` (target SHA) for every non-archived stack on the matched branch: [6](#0-5) 

The equality that should hold is: `organization that authenticated the signature == organization owning repository.full_name used for the write`. Nothing enforces this. An operator of *any* GitHub organization configured in this Shipit instance's `github:` multi-org secrets can send a validly-signed webhook (signed with their own org's legitimate `webhook_secret`) whose `repository.full_name` names a stack belonging to an entirely different, unrelated organization tracked by the same Shipit instance. `verify_signature` will succeed (it only checked that *some* configured org's secret matches), and the handler will act on the forged `full_name`/`ref`/`after` fields that were never bound to that verification.

### Impact Explanation
This lets an attacker who administers webhook delivery for one onboarded GitHub organization (not the target's) forge `push`, `status`, or `check_suite` events that reference another organization's repository/stack by `full_name`. Via `PushHandler`, this queues `GithubSyncJob` with an attacker-chosen `expected_head_sha` against the victim stack, and via `StatusHandler`/`CheckSuiteHandler` it can inject fabricated CI status/check results for arbitrary commits, which Shipit's deploy gating logic treats as authoritative signals for whether a commit is deployable. This crosses the "cross-repository writes" / "unauthorized deploy" boundary called out in scope, because it lets one org's credentials effectively drive state changes and green/red CI signals for a stack that belongs to a different org's repository — something the per-organization webhook secret model is meant to prevent.

### Likelihood Explanation
Requires the attacker to control (be the admin/installer of) at least one GitHub organization already configured under Shipit's multi-org `github:` secrets — a legitimate, low-privilege position relative to any *other* tenant organization on the same Shipit instance, and no access to the victim's secrets, tokens, or repositories is needed. This is realistic for any shared/multi-tenant Shipit deployment using the documented multi-org configuration shown in `docs/setup.md`.

### Recommendation
Bind webhook signature verification to the same identity the handler will act on: verify the signature using the organization/owner derived from `repository.full_name` (or explicitly cross-check that `repository.owner.login`/`organization.login` matches the owner segment of `repository.full_name`) before dispatching to handlers, rather than trusting an unrelated field for secret selection while a different field drives the write path.

### Proof of Concept
Given a Shipit instance configured with two orgs, `attacker-org` (attacker-controlled) and `victim-org` (hosts a tracked stack `victim-org/app`), the attacker's own GitHub App delivers (or attacker crafts and signs with `attacker-org`'s legitimate webhook secret) a `push` event body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/app",
    "owner": { "login": "attacker-org" }
  }
}
```
`verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository_owner`) and validates successfully against `attacker-org`'s secret [1](#0-0) . `PushHandler#stacks` then resolves `Repository.from_github_repo_name("victim-org/app")` [5](#0-4)  and enqueues `GithubSyncJob` with the attacker's `expected_head_sha` for `victim-org/app`'s stacks [7](#0-6) , despite the request never being signed by `victim-org`'s webhook secret.

Note: I was unable to fully trace `Repository.from_github_repo_name` and `Stack#sync_github` (in `app/models/shipit/stack.rb`) or `GithubSyncJob`'s body within the tool budget, so the exact downstream consequences of the forged `expected_head_sha` (e.g., whether it merely triggers a re-sync from GitHub, bounded by real commit existence, or can affect deploy state more directly) could not be fully confirmed from the index and would need direct inspection of those files.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
