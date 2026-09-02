### Title
Webhook signature verified against `repository.owner.login`, but handlers act on unrelated `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/`webhook_secret` used to validate the HMAC signature based on `repository.owner.login` (or `organization.login`), but the event handlers that actually mutate application state select the target `Stack`/`Repository` using the independent `repository.full_name` field from the same JSON body. Because these two fields are never cross-checked, an attacker who legitimately controls a *different* GitHub organization onboarded to the same Shipit instance can forge a webhook that is correctly signed with their own org's secret while pointing `repository.full_name` at a victim organization's repository/stack.

### Finding Description
`WebhooksController#verify_signature` resolves the signing app strictly from the org login embedded in the payload: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only checks that the HMAC over the raw body matches the secret configured for that resolved organization; it has no notion of which repository the payload claims to describe: [3](#0-2) 

Once the signature passes, `create` dispatches the *entire, attacker-controlled* JSON body to handlers unmodified: [4](#0-3) 

Every handler resolves the target stack from a completely different field, `repository.full_name`, with no relation to the field used for signature verification: [5](#0-4) 

For example `PushHandler`, used to trigger `stack.sync_github`, blindly trusts `stacks` (derived from `repository.full_name`): [6](#0-5) 

Shipit explicitly supports hosting multiple independent GitHub organizations/apps on one instance, each with its own `webhook_secret`: [7](#0-6) [8](#0-7) 

**Binding broken:** organization authenticated (`repository.owner.login` / `organization.login`, whose secret validated the HMAC) ≠ repository actually written (`repository.full_name`, used by every handler to locate the `Stack`).

Before the attack: attacker only has legitimate credentials for their own onboarded org "attacker-org" (its own GitHub App installation and `webhook_secret`), and no access whatsoever to "victim-org"'s repositories, stacks, or secrets.

After the attack: attacker POSTs to `/webhooks` a JSON body with `repository.owner.login = "attacker-org"` (so `verify_signature` looks up and validates against attacker-org's own secret, which the attacker knows) and `repository.full_name = "victim-org/victim-repo"`, `ref`, `after`, etc. crafted at will. The signature check passes because it is computed correctly for attacker-org's secret over the full attacker-controlled body. `PushHandler` (or `pull_request` handlers that manipulate merge-queue/lock state) then resolves `victim-org/victim-repo`'s `Stack` and performs `sync_github`/merge-queue mutations on it — a write against a repository the attacker never authenticated for.

### Impact Explanation
This allows cross-repository writes/triggers: an attacker who is a legitimate GitHub-App customer of the same Shipit deployment for their own org can forge signed pushes or pull-request events that manipulate a *different* customer's stack (trigger `sync_github`, and depending on which `pull_request/*` handler fires, mutate merge-queue state, PR labels tracking, lock state, etc.), all without ever possessing that victim's `webhook_secret`, `github_access_token`, or any `ApiClient` token. This matches the Critical-tier impact of cross-repository writes / unauthorized deploy triggers defined in scope.

### Likelihood Explanation
Requires only that the attacker controls one legitimately onboarded GitHub organization on the shared Shipit instance (a normal, expected multi-tenant configuration per `docs/setup.md`'s "Using Multiple Github Applications" section) — no privileged Shipit account, no compromise of the victim's secrets, and no session/API token. This is a realistic unprivileged-attacker scenario for any multi-org Shipit deployment.

### Recommendation
In `WebhooksController#verify_signature`, and/or in `Handler#stacks`/`repository_name`, enforce that the organization used to select/verify the webhook secret is the same organization that owns `repository.full_name` (e.g., verify `repository.full_name.split('/').first == repository_owner`, or resolve the `Repository`/`Stack` via the same owner used for signature verification) before dispatching to handlers.

### Proof of Concept
1. Attacker is a legitimate customer of the shared Shipit instance, onboarded as GitHub org `attacker-org` with its own `webhook_secret` (`Shipit.github(organization: 'attacker-org').webhook_secret`).
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, raw_body)>` and `X-Github-Event: push`, and POSTs to `/webhooks`.
4. `verify_signature` resolves `repository_owner` → `"attacker-org"`, loads `Shipit.github(organization: 'attacker-org')`, and the signature validates successfully (since it was computed with that same secret).
5. `Webhooks.for_event('push')` invokes `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name('victim-org/victim-repo')`, and calls `stack.sync_github(expected_head_sha: '<attacker-chosen-sha>')` on the victim's stack — a cross-tenant write triggered purely by attacker-controlled JSON fields, despite the signature only proving authorship by `attacker-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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
