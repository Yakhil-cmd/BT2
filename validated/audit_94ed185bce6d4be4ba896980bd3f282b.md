### Title
Webhook Signature Authenticates Organization but Handlers Route on an Unvalidated `repository.full_name` Field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to validate the HMAC signature based on `repository.owner.login` (or `organization.login`), but the handlers that act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` using an entirely different field, `repository.full_name`, with no cross-check that the two refer to the same repository/organization.

### Finding Description
`verify_signature` computes `repository_owner` from the JSON body and uses it purely to pick *which* configured GitHub App's secret verifies the HMAC: [1](#0-0) [2](#0-1) 

Once the signature check passes, the raw body is parsed and dispatched to handlers unmodified: [3](#0-2) 

Every handler resolves the affected `Stack` via `Handler#stacks`/`#repository_name`, which reads a *different* JSON key, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

`PushHandler` (and other handlers) then act on whatever `Stack`s belong to that resolved repository: [5](#0-4) 

Shipit is explicitly designed to host multiple GitHub organizations in one instance, each with its own `webhook_secret` under `github:` in the secrets config: [6](#0-5) 

The binding the engine relies on is: `organization whose secret verified the signature == organization/repository the handler writes to`. Because `repository.owner.login` (used for signature-key selection) and `repository.full_name` (used for target resolution) are independent, unvalidated fields inside the same signed body, an attacker who legitimately administers *one* org configured on the instance (and thus knows that org's `webhook_secret`) can craft a payload where:
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` picks the secret they know, and the HMAC they compute with it passes verification), while
- `repository.full_name` = a victim org/repo hosted on the same Shipit instance.

The signature only proves "signed by org A's app secret" — it does not prove "this payload's actions apply to org A's repositories." This is the exact analog of the `DeliHookConstantProduct` bug class: a value used in one part of the calculation/verification (`repository.owner.login`, used for key selection/authentication) diverges from the value used in the actually-executed effect (`repository.full_name`, used for target write), producing a mismatch that should have been, but isn't, tied together.

### Impact Explanation
An attacker who controls one legitimate, Shipit-configured GitHub organization can forge a validly-signed webhook that is attributed to their own org for signature purposes, but whose effects are applied to a `Stack`/`Repository` belonging to a different organization on the same shared instance. Concretely, `PushHandler` will invoke `stack.sync_github(expected_head_sha:)` for the victim repository's stacks, i.e. writes/state changes are performed against a repository the attacker never proved control over — a cross-repository, cross-organization action driven by a signature that authenticates a different tenant. This falls under the Critical "cross-repository writes" impact bucket, since the authenticated organization and the repository actually mutated are never checked for equality.

### Likelihood Explanation
Likelihood requires the attacker to be a legitimate administrator of at least one GitHub organization/App configured on a multi-tenant Shipit instance (a supported, documented configuration, not a privileged Shipit account or stolen secret). Given that, forging the payload is trivial: it is a normal, self-signed HTTP POST to the public `/webhooks` endpoint with attacker-chosen JSON fields.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, cross-validate that the organization used to select the verifying secret (`repository.owner.login` / `organization.login`) matches the organization portion of `repository.full_name` before dispatching to handlers, and reject the webhook otherwise.

### Proof of Concept
1. Attacker administers `attacker-org`, which is configured in Shipit's `github:` secrets with `webhook_secret: S`.
2. Attacker builds a JSON payload for a `push` event: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/main", "after": "<sha>"}`.
3. Attacker computes `sha1=HMAC-SHA1(S, raw_body)` and sets it as `X-Hub-Signature`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully because it was signed with that org's real secret. [1](#0-0) 
5. `PushHandler#stacks` resolves stacks via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`, and `stack.sync_github` is invoked for the victim's stacks despite the attacker never being authenticated as, or authorized by, `victim-org`. [4](#0-3) [5](#0-4)

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
