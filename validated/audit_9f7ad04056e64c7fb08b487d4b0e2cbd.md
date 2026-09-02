### Title
Webhook organization-signature verification is not bound to the repository the event handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify a webhook's HMAC signature against using an **unverified** field of the JSON body (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, the raw, still-untrusted payload is handed to every registered `Shipit::Webhooks::Handlers::*`, several of which resolve the target `Repository`/`Stack` from a **different** field of the same payload (`repository.full_name`). No code enforces that the organization whose secret validated the signature is the same organization that owns the repository the handler subsequently acts on.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from `params` (the raw JSON body) before any signature check occurs, and is used only to pick which `GitHubApp`/`webhook_secret` to verify against: [3](#0-2) 

Note also that `verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that organization — and the setup docs explicitly mark the webhook secret as **optional**: [4](#0-3) 

After verification, the handler dispatch loop passes the entire (still attacker-supplied) JSON body to matching handlers: [5](#0-4) 

The base `Handler` class and `PushHandler` resolve the actual target repository/stack from `repository.full_name`, a field completely independent of the `repository.owner.login`/`organization.login` field used for signature-organization selection: [6](#0-5) [7](#0-6) 

The equality the code implicitly assumes but never enforces is:
`organization_whose_secret_verified_signature == owner_of(repository.full_name_used_by_handler)`

Because `Shipit.github(organization: repository_owner)` supports multiple independently configured GitHub Apps/organizations (each with its own, optionally-empty `webhook_secret`, as shown in the test fixture with `OrgOne`/`OrgTwo`): [8](#0-7) [9](#0-8) 

an attacker who can get a validly-signed (or unsigned, if that org has no `webhook_secret`) webhook accepted for *any one* configured organization can set `repository.owner.login` to that organization (satisfying `verify_signature`) while setting `repository.full_name` to point at a repository/stack that belongs to a completely different, properly-secured organization tracked by the same Shipit instance. `PushHandler` will then act on that unrelated stack (`stack.sync_github(expected_head_sha: params.after)`) even though the cryptographic check never covered `repository.full_name` or the organization that actually owns it.

### Impact Explanation
This breaks the intended trust binding between "the organization whose webhook secret authenticated the request" and "the repository the request is allowed to affect." An unprivileged attacker can force Shipit to act (resync, and potentially trigger downstream continuous-deployment logic depending on `stack.sync_github`'s side effects) on a stack belonging to an organization/repository the attacker has no relationship to, purely by controlling (or exploiting the optional/absent secret of) one org configured on the same Shipit instance. In multi-organization Shipit deployments this is a cross-organization authorization bypass at the webhook boundary.

### Likelihood Explanation
Requires only an unauthenticated HTTP POST to `/webhooks` with a crafted `X-Github-Event`/`X-Hub-Signature` and a JSON body containing mismatched `repository.owner.login` and `repository.full_name`; no session, API token, or GitHub credentials are required. Exploitability is highest when any organization configured on the instance has no `webhook_secret` set (explicitly supported/optional per the setup docs), in which case the signature check is a no-op for that organization and any repository name can be substituted.

### Recommendation
Bind the verified signature to the actual repository the handler will act on: derive the organization used for the loop-up-and-verify step from the same field the handlers use to resolve `Repository`/`Stack` (`repository.full_name`), or, after selecting the app/secret by owner, re-validate that the resolved `Repository`'s owner matches the organization whose secret validated the signature before invoking any handler. Additionally, consider requiring `webhook_secret` to be present for every configured organization instead of treating it as optional.

### Proof of Concept
1. Shipit instance configured with two orgs, e.g. `OrgOne` (webhook secret unset or known to attacker) and `OrgTwo` (properly secured, tracks stack `OrgTwo/victim-repo`).
2. Attacker sends:
   ```
   POST /webhooks
   X-Github-Event: push
   X-Hub-Signature: sha1=<valid-or-omitted-for-OrgOne>
   {
     "repository": { "owner": {"login": "OrgOne"}, "full_name": "OrgTwo/victim-repo" },
     "ref": "refs/heads/master",
     "after": "<sha>"
   }
   ```
3. `verify_signature` computes `repository_owner = "OrgOne"`, loads `Shipit.github(organization: "OrgOne")`, and passes verification (trivially, if `OrgOne` has no `webhook_secret`).
4. `PushHandler` resolves the target via `payload.dig('repository', 'full_name') == "OrgTwo/victim-repo"`, and calls `sync_github` on the `OrgTwo` stack — an action never covered by any signature tied to `OrgTwo`.

Note: the exact downstream consequences of `Stack#sync_github` (e.g., whether it can trigger an automatic deploy through `continuous_deployment`) were not fully traced in this pass; confirming that code path would strengthen the severity assessment further.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
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
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
