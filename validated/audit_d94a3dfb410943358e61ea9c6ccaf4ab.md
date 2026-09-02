### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while event processing is bound to `repository.full_name` - allows cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, a value taken from the JSON body itself (`repository.owner.login` or `organization.login`). Once the signature is accepted, `WebhooksController#create` dispatches the **entire raw payload** to the registered handlers, which resolve the target `Repository`/`Stack` using a *different* field of the same body: `repository.full_name` (`Shipit::Webhooks::Handlers::Handler#repository_name`). Because both fields are attacker-controlled body content and are never checked against each other, an entity that legitimately controls the GitHub App/`webhook_secret` for **one** organization configured in Shipit's multi-org setup can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` names an arbitrary **other** org/repo tracked by the same Shipit instance.

### Finding Description
- Signature verification chooses the credential to check against from the payload: [1](#0-0) [2](#0-1) 

- After verification, the *unmodified* JSON body is dispatched to handlers: [3](#0-2) 

- Handlers resolve the target repository/stack from a **different** field of the same body: [4](#0-3) 

- `Repository.from_github_repo_name` performs a plain DB lookup on `owner/name` parsed out of that field, with no cross-check against the org used to verify the signature: [5](#0-4) 

- Multi-org configuration (separate `webhook_secret` per organization) is a documented, supported deployment mode: [6](#0-5) [7](#0-6) [8](#0-7) 

**Binding that should hold:** `organization used to select/verify webhook_secret (repository_owner)` == `organization/repository whose Stack is mutated by the handler (repository.full_name)`.

**Before the attack:** for a genuine GitHub-originated webhook, `repository.owner.login` and the owner segment of `repository.full_name` are always the same (GitHub fills in both consistently for the actual repository that fired the event), so the binding trivially holds.

**After the attack:** an attacker who is an administrator of `OrgB` (one of potentially many orgs configured in Shipit's `github:` secrets map) knows `OrgB`'s `webhook_secret` (they configured/received it when setting up their own GitHub App integration). They can POST a fabricated body to `/github/webhooks` with:
- `repository.owner.login = "OrgB"` (or `organization.login = "OrgB"`) → `verify_signature` resolves `Shipit.github(organization: "OrgB")` and the HMAC checks out because it's signed with the secret the attacker knows.
- `repository.full_name = "OrgA/private-repo"` → the handler resolves and mutates `OrgA`'s `Repository`/`Stack`, which the attacker has no legitimate access to.

The binding `repository_owner == repository.full_name's owner` is broken: the org that "authenticated" the request is not the org whose repository is actually written to.

### Impact Explanation
This crosses the exact organization/repository trust boundary called out in scope: *"an organization that authenticated versus the repository that is written."* Depending on which webhook event/handler is targeted, the attacker can inject fabricated GitHub state into a Stack they don't control:
- `push` → enqueues `GithubSyncJob` for the victim stack, causing Shipit to sync from GitHub on attacker's trigger.
- `status`/`check_suite` → creates fake `Status`/check results on victim commits, which can flip `deployable_status`/`commit_status` and gate or unblock automatic deploys/merges on the victim stack.
- `pull_request` (labeled/opened/closed/etc.) → drives `ReviewStackAdapter`/label-capturing/merge-request logic for a repository the attacker doesn't own.

This is a cross-repository write triggered without possessing that repository's own webhook secret, matching the "cross-repository writes" / "unauthorized deploy" impact tier.

### Likelihood Explanation
Exploitability requires only that the attacker legitimately administers (and knows the `webhook_secret` for) any single org configured on a shared, multi-tenant Shipit deployment — a plausible, unprivileged-relative-to-other-tenants scenario explicitly supported by Shipit's documented multi-org configuration. No access to `GITHUB_TOKEN`, `api_clients_secret`, or another org's secret is needed; only the ability to author an arbitrary HTTP POST body signed with a secret the attacker already legitimately possesses for their own org.

### Recommendation
After signature verification, re-derive the organization strictly from `repository.full_name` (or `repository.owner.login`) and require it to match the organization whose `webhook_secret` was used to verify the signature; reject the request (422) on mismatch. Do not let handlers trust `repository.full_name` independently of the identity established during signature verification.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-org format).
2. Attacker (admin of `OrgB`, knows `OrgB`'s `webhook_secret`) builds a payload:
```json
{
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/private-repo" },
  "sha": "<victim-commit-sha>",
  "state": "success",
  "branches": [{ "name": "master" }]
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgB_webhook_secret, body)>` and set `X-Github-Event: status`.
4. POST to the webhook endpoint mounted per `config/routes.rb`. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgB")` (from `repository.owner.login`) and the signature validates successfully.
5. `Shipit::Webhooks.for_event('status')` handler is invoked with the full payload and resolves the target via `payload.dig('repository', 'full_name')` = `"OrgA/private-repo"`, mutating `OrgA`'s stack/commit status despite the request only being authenticated as `OrgB`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
