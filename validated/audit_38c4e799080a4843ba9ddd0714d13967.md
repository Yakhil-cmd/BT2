### Title
Webhook signature check is bound to `repository.owner.login`, not `repository.full_name`, allowing forged commit statuses across organizations - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate the request against based on `repository.owner.login` (or `organization.login`) taken from the **unauthenticated request body**. All downstream event handlers, however, resolve the target `Stack`/`Repository` from a completely different, independently attacker-controlled field: `repository.full_name`. Because these two payload fields are never checked for consistency, and because `verify_webhook_signature` returns `true` unconditionally when the selected organization has no `webhook_secret` configured, an attacker can pick an organization with no configured secret to sail through signature verification while forging events for a stack that belongs to an entirely different (secret-protected) organization.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` picks the `GitHubApp` used for signature verification purely from payload data: [1](#0-0) [2](#0-1) 

`lib/shipit/github_app.rb#verify_webhook_signature` bypasses HMAC verification entirely when the selected organization has no `webhook_secret` configured: [3](#0-2) 

The docs explicitly document `webhook_secret` as optional and describe multi-organization setups where several distinct `GitHubApp` configs (each potentially with or without a secret) coexist on one Shipit instance: [4](#0-3) 

Once the request passes (or bypasses) signature verification, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-supplied JSON body to handlers. Every handler resolves its target repository/stack from `repository.full_name` — a field that was never validated against `repository.owner.login`/`organization.login` used for the trust decision: [5](#0-4) 

The `status` handler is especially impactful: it persists the attacker-supplied `state`/`description`/`target_url`/`context` directly as a commit status with no secondary verification against GitHub's API: [6](#0-5) 

The `push` handler similarly triggers a sync against any stack found via `repository.full_name`: [7](#0-6) 

**Trust binding broken (equality that should hold but doesn't):**
`organization used to authenticate the webhook (repository.owner.login)` == `organization/repository actually written to (repository.full_name)`.

**Exploit path:**
1. Shipit is configured (per documented multi-org setup) with at least two GitHub App entries in `config/secrets.yml`: e.g. `orgA` (no `webhook_secret` set, `# nil` as shown in the sample config) and `orgB/victim-repo` (has a real `webhook_secret`, hosts a protected `Stack` with `ci.require` configured).
2. An unauthenticated attacker POSTs to `/webhooks` with `X-Github-Event: status`, no valid `X-Hub-Signature`, and body:
   ```json
   {
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
     "sha": "<target commit sha>",
     "state": "success",
     "context": "required-ci-check"
   }
   ```
3. `repository_owner` resolves to `orgA`; `Shipit.github(organization: 'orgA')` returns the `GitHubApp` with no `webhook_secret`; `verify_webhook_signature` returns `true` unconditionally — no signature needed at all.
4. `StatusHandler` looks up the commit belonging to `orgB/victim-repo` via `repository.full_name` and calls `create_status_from_github!`, injecting a forged "success" status for a required CI check that never actually ran.
5. If a deploy of that commit is subsequently requested and Shipit's `ci.require` gate checks only the (now-forged) commit status, the attacker has caused an unauthorized deploy of a commit that never passed real CI — with no credentials, no GitHub webhook secret, and no session at all.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly and lets a fully unprivileged, unauthenticated network attacker inject forged CI status events (and forged pushes/check_suite/pull_request/membership events) for stacks belonging to a different, secret-protected GitHub organization, by choosing an organization slug that has no `webhook_secret` configured. Forged "success" statuses can satisfy `ci.require` deploy gating, resulting in an unauthorized deploy of an unreviewed/unvetted commit — matching the Critical impact category ("unauthorized deploy").

### Likelihood Explanation
Requires only that the Shipit instance is configured with the documented multi-organization `github:` mapping where at least one configured organization lacks a `webhook_secret` (explicitly shown as a valid/optional configuration in `docs/setup.md` and in `config/secrets.development.shopify.yml`), while another configured organization hosts the protected stack. No credentials, tokens, or prior access are required — a single unauthenticated POST to the public `/webhooks` endpoint suffices.

### Recommendation
- Bind the signature-verification identity to the same field used for target resolution: derive both `repository_owner` (used to pick the `GitHubApp`/secret) and the target repository strictly from `repository.full_name`'s owner segment, and reject the payload if `repository.owner.login`/`organization.login` disagrees with `repository.full_name`'s owner.
- Do not silently pass verification when `webhook_secret` is blank for one organization if any other configured organization has a secret; either require a webhook secret for every configured organization or fail closed rather than returning `true` when the header is absent/unverifiable.
- After signature verification, re-validate that the resolved `Stack`/`Repository` from `repository.full_name` belongs to the same organization whose secret was used to authenticate the request.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: status
Content-Type: application/json

{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "required-ci-check"
}
```
With `orgA` configured in `Shipit.github` without a `webhook_secret`, `verify_webhook_signature` returns `true` (`lib/shipit/github_app.rb:76-77`) with no `X-Hub-Signature` header required, and `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) writes a forged status onto the commit belonging to `orgB/victim-repo`, resolved purely via `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`).

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-25)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
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
