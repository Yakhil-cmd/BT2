### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login`, but every event handler acts on the independent, unverified `repository.full_name` field, letting one authorized GitHub organization forge writes against another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against using a value pulled straight out of the untrusted, not-yet-verified JSON body (`repository.owner.login` / `organization.login`). Every downstream `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the `Repository`/`Stack` to act on using a *different* field of the same payload, `repository.full_name`. Nothing enforces that these two fields refer to the same organization, so the "organization whose secret authenticated the request" and "the repository that gets written to" are never bound together.

### Finding Description
`repository_owner` is computed before signature verification: [1](#0-0) [2](#0-1) 

This value is used only to pick the `GitHubApp` instance (and hence the `webhook_secret`) via `Shipit.github(organization: repository_owner)`, as documented for the multi-tenant configuration where each GitHub organization has its own independently-managed `app_id`/`webhook_secret`: [3](#0-2) [4](#0-3) 

Once the signature check passes, `params` (the same untrusted hash) is fed unmodified to every registered handler: [5](#0-4) 

But the base `Handler` class - and every concrete handler (`PushHandler`, `OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, etc.) - resolves the target `Repository`/`Stack` from `repository.full_name`, a field that is completely independent from `repository.owner.login`: [6](#0-5) [7](#0-6) [8](#0-7) 

There is no cross-check anywhere in `verify_signature` or in `Handler#stacks`/`Handler#repository_name` that `repository.full_name`'s owner matches the `repository_owner` (or `organization.login`) that was used to select the verifying secret. The equality that should hold - `organization whose webhook_secret authenticated the request == owner(repository.full_name) being written to` - is never enforced.

### Impact Explanation
In a multi-organization Shipit deployment (explicitly supported, see `docs/setup.md` "Using Multiple Github Applications" and `config/secrets.development.shopify.yml`), each onboarded GitHub organization owns and configures its own GitHub App, including its own `webhook_secret`. An entity that legitimately controls Org A's GitHub App configuration (an "unprivileged attacker" with respect to Org B, and to Shipit itself, since they hold no Shipit session, API-client token, or Shipit-side secret) can compute a valid HMAC over an arbitrary payload using Org A's own secret. By setting `repository.owner.login` (or `organization.login`) to `OrgA` (so `verify_signature` selects and successfully checks against Org A's secret) while setting `repository.full_name` to `OrgB/some-repo`, the forged, correctly-signed request is delivered to handlers that operate on Org B's stacks — stacks the attacker has no GitHub-side access to.

Depending on which event/handler is targeted this enables cross-organization interference with `Stack` state: forcing GitHub resynchronization, archiving/unarchiving review stacks, injecting fabricated pull-request metadata, or manipulating commit statuses that other flows (merge queue, CI gating) rely on for Org B's repositories - i.e., a cross-repository/cross-organization write performed without any credential belonging to the victim organization.

### Likelihood Explanation
Requires only that the attacker be able to configure a legitimate GitHub App for *some* organization onboarded to the shared Shipit instance (a normal, self-service action documented for multi-org setups) and knowledge of that organization's own `webhook_secret` (which they set themselves). No Shipit session, `ApiClient` token, or victim-organization credential is needed, and the payload/signature mismatch is not something GitHub itself would ever normally produce (GitHub always emits consistent `repository.owner`/`repository.full_name` pairs), meaning the disparity is only exploitable by a party crafting the webhook body directly, not by unrelated third parties passively observing traffic.

### Recommendation
- Short term: In `WebhooksController#verify_signature`, after selecting the `GitHubApp` and verifying the HMAC, re-derive the organization from `repository.full_name` (the value handlers will actually use) and assert it matches `repository_owner`/the organization whose secret validated the signature; reject (422) on mismatch.
- Long term: Have `Shipit::Webhooks::Handlers::Handler` accept the verified organization from the controller and require every handler to confirm the resolved `Repository`'s owner is the verified organization, rather than trusting `full_name` alone.

### Proof of Concept
1. Shipit is configured with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. Attacker controls `OrgA`'s GitHub App and therefore knows `OrgA`'s `webhook_secret`.
3. Attacker crafts a JSON payload for a `pull_request` (or `push`) event where:
   - `organization.login` / `repository.owner.login` = `"OrgA"`
   - `repository.full_name` = `"OrgB/victim-repo"`
4. Attacker computes `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` and POSTs to `/github/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")`, which succeeds because the signature was computed with `OrgA`'s real secret.
6. The event handler (e.g., `OpenedHandler`/`PushHandler`) resolves `Shipit::Repository.from_github_repo_name("OrgB/victim-repo")` and performs its write (`ReviewStackAdapter#find_or_create!`, `stack.sync_github`, `stack.archive!`, etc.) against `OrgB`'s stack, even though the request was never authenticated by `OrgB`'s GitHub App or secret.

Note: I was unable to fully inspect `app/models/shipit/webhooks/handlers/status_handler.rb` and `check_suite_handler.rb` contents before the tool budget was exhausted, so I cannot confirm the exact downstream effect on commit-status-gated merges/deploys for those specific handlers; the PoC and impact above are demonstrated concretely for the `push`/pull-request handlers whose source I did review.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```
