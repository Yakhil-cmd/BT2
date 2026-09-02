### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while the acted-upon repository is bound to the unrelated `repository.full_name` field, allowing cross-repository forged webhook actions when any configured GitHub organization has no `webhook_secret` set - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which HMAC secret) to verify the request against using `repository_owner`, derived from the untrusted payload fields `repository.owner.login` / `organization.login`. But the payload's `repository.full_name` — a completely different field, also fully attacker-controlled and never covered by the signature check binding — is what every webhook `Handler` actually uses to resolve the target `Repository`/`Stack` that receives the action. There is no requirement, and no code path enforcing, that `repository.owner.login` and `repository.full_name`'s owner segment refer to the same repository.

### Finding Description
`verify_signature` computes the verification target purely from payload data: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves the per-organization config from `secrets.github`, and `GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that organization key — a documented, supported configuration (`webhook_secret: # nil` is shown as valid in `config/secrets.development.example.yml` and `docs/setup.md`): [3](#0-2) [4](#0-3) 

Meanwhile, every `Handler` subclass resolves the actual `Repository`/`Stack` to mutate using `repository.full_name`, an entirely separate payload field never covered by the signature check: [5](#0-4) 

The `PushHandler` triggers a repository sync on stacks belonging to whatever repo `full_name` resolves to: [6](#0-5) 

and `PullRequest::ClosedHandler` similarly resolves an unrelated `Repository` from `params.repository.full_name` to archive review stacks: [7](#0-6) 

**Equality that should hold but is broken:** `organization used to select/verify the signing secret == owner of the repository whose Stack is acted upon`. In this engine, the "authenticated organization" (`repository_owner` from `repository.owner.login`) and the "repository that is written" (`repository.full_name`) are two independent, unauthenticated payload fields with no cross-check binding them together — matching exactly the analog class called out in the rules ("an organization that authenticated versus the repository that is written").

**Before the attacker's payload:** GitHub always sends payloads where `repository.owner.login` and `repository.full_name`'s owner segment agree, so the binding holds implicitly in legitimate traffic.
**After the attacker's forged payload:** an attacker sets `repository.owner.login` (or `organization.login`) to an organization key that is configured in Shipit's multi-org `secrets.github` but has no `webhook_secret` set, causing `verify_webhook_signature` to unconditionally return `true` regardless of the (absent or garbage) `X-Hub-Signature` header — while setting `repository.full_name` to point at any other tracked repository/stack in the Shipit installation. The handler then acts on that unrelated, victim repository.

### Impact Explanation
This breaks the credential/authorization boundary between "webhook traffic proven to originate from GitHub for org X" and "the stack that gets mutated," enabling an unauthenticated actor to trigger `GithubSyncJob` on arbitrary stacks, forge `Status` records via `StatusHandler`, and archive/mutate review stacks and pull-request-driven state across repositories they do not control and were never involved in signing — an unauthorized cross-repository write against the engine's own trust model, without needing any secret, session, or API token. This aligns with the "cross-repository writes" / "unauthorized deploy" impact classes.

### Likelihood Explanation
The precondition — at least one organization entry in Shipit's multi-org `github:` config lacking a `webhook_secret` — is explicitly presented as a supported, valid configuration in the project's own setup documentation and example secrets files, not a misconfiguration the code rejects or warns about. Any installation using multi-org mode with even one org that has not set a webhook secret (a legitimate choice per the docs) is exposed with zero attacker-held credentials.

### Recommendation
Bind the verified organization to the actual acted-upon repository: derive the target repository/organization used by `Webhooks::Handlers::Handler#repository_name` from the same verified `repository_owner` value used in `verify_signature`, or reject/ignore payloads where `repository.full_name`'s owner segment does not match the organization whose secret was used to verify the signature. Additionally, consider disallowing (or loudly warning against) `webhook_secret`-less multi-org entries, since they cause `verify_webhook_signature` to accept any payload unconditionally for that org key.

### Proof of Concept
1. Deploy Shipit with multi-org GitHub config where org `benign-org` has `webhook_secret: nil` and org `victim-org` (or any tracked repo, e.g. `victim-org/victim-repo`) has stacks configured normally.
2. Send `POST /webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature` (or an arbitrary bogus value), with body:
```json
{
  "repository": { "owner": { "login": "benign-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
3. `verify_signature` calls `Shipit.github(organization: "benign-org")`, whose config has no `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of the signature header [3](#0-2) .
4. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` [5](#0-4)  and enqueues `stack.sync_github(expected_head_sha: params.after)` for that unrelated repository's stacks [6](#0-5) , without any valid GitHub-issued signature for `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L1-17)
```yaml
host: 'localhost:3000'
redis_url: 'redis://127.0.0.1:6379/0'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app
# Can be obtained there: https://github.com/settings/apps
# Set the "Authorization callback URL" as `<host>/github/auth/github/callback`

github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional

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
