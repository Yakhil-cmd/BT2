### Title
Cross-repository webhook forgery via mismatch between the organization used for signature verification and the repository actually written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the request against using `repository.owner.login` (falling back to `organization.login`) pulled from the attacker-supplied JSON body itself. The event is then dispatched to handlers that resolve the target `Stack`/`Repository` using a *different* field from the same body — `repository.full_name` — with no check that the two are consistent. Since `webhook_secret` is explicitly documented as optional per configured GitHub App/organization, an attacker who knows (or controls) one configured organization with no `webhook_secret` set can send an unsigned, freely crafted payload whose `repository.owner.login` matches that unsecured org while `repository.full_name` points at an entirely different, secured repository/stack.

### Finding Description
`verify_signature` in [1](#0-0)  computes `repository_owner` purely from the untrusted request body (`params.dig('repository','owner','login') || params.dig('organization','login')`, see [2](#0-1) ) and uses it to pick a `GitHubApp` instance via `Shipit.github(organization: repository_owner)`. That instance's `verify_webhook_signature` explicitly short-circuits to `true` when no `webhook_secret` is configured for that organization: [3](#0-2) . Configuring an organization without a `webhook_secret` is an explicitly supported/documented setup (`docs/setup.md` and `config/secrets.development.example.yml` both show it as "optional"/nil).

Once signature verification passes (trivially, for the unsecured org), `create` dispatches the same raw, attacker-controlled JSON to the registered handlers: [4](#0-3) . Every handler resolves its target stack(s)/repository from `payload.dig('repository', 'full_name')` — a completely independent field from the one used for authentication: [5](#0-4) . For example `PushHandler` triggers `stack.sync_github` for whatever stack matches that `full_name` [6](#0-5) , and `PullRequest::ClosedHandler` archives a review stack resolved the same way [7](#0-6) .

This is the same class of bug as the report's root cause: a value that is checked/authenticated (`repository.owner.login`, analogous to the paired asset's price oracle used for validation) is not the same value that is actually acted upon (`repository.full_name`, analogous to the coin actually redeemed against). The binding "organization that authenticated == repository that is written" is broken: `repository_owner(payload) ≠ owner(repository.full_name(payload))` is never enforced.

### Impact Explanation
An attacker who can trigger delivery of, or directly POST to, `/webhooks` with `repository.owner.login` set to any organization configured with a blank `webhook_secret` can forge events for any *other* repository/stack tracked by the Shipit instance (multi-org deployments are an explicitly documented configuration in `config/secrets.development.example.yml`). Concretely this allows:
- Forged `push` events to trigger `GithubSyncJob`/`sync_github` against arbitrary stacks.
- Forged `pull_request` "closed" events to archive arbitrary review stacks belonging to unrelated repositories.
- Forged `status`/`check_suite` events to inject commit statuses/check results that Shipit's own deploy-safety checks rely on, on repositories the attacker does not control, potentially influencing whether a deploy/merge is judged safe.

This maps to the "unauthorized deploy/rollback/merge" / cross-repository-write impact bracket, since it lets an attacker who only controls (or knows the owner name of) one loosely-configured org manipulate state for repositories they have no access to.

### Likelihood Explanation
Requires a specific but explicitly supported deployment configuration: multiple GitHub organizations configured in `secrets.yml`, at least one without a `webhook_secret` set (documented as optional). Given multi-org support and optional secrets are first-class, documented features, this is a realistic operator configuration rather than a hypothetical misconfiguration outside the engine's control. No `ApiClient` token, session, or GitHub write access is required — only network access to the public `/webhooks` endpoint.

### Recommendation
- Require `webhook_secret` to be set for every configured organization (fail closed instead of `return true unless webhook_secret`).
- After the signature passes, re-derive/re-validate that `repository.owner.login` (the field used to select the verifying secret) matches the owner encoded in `repository.full_name` before dispatching to handlers, rejecting mismatches with `422`.
- Consider verifying the signature using every currently configured webhook secret rather than one selected by attacker-controlled payload content, or bind the verified organization identity to the handler dispatch so a payload cannot claim to belong to a repository under a different organization than the one whose secret validated it.

### Proof of Concept
1. Operator configures two GitHub orgs in `secrets.yml`: `orgA` (no `webhook_secret`) and `orgB` (has `webhook_secret`), each with repos tracked as Shipit stacks.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/secured-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "orgA")`; since `orgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` header is needed [8](#0-7) .
4. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/secured-repo")` [5](#0-4)  and triggers `sync_github` on `orgB`'s stacks, even though the request was never authenticated against `orgB`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
