### Title
Webhook signature is verified against the GitHub App keyed by `repository.owner.login`, but event handlers act on `repository.full_name` — an attacker can authenticate as one organization while writing state for another - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to verify the request's HMAC signature against using `repository_owner`, which is read straight out of the unauthenticated JSON body (`params.dig('repository', 'owner', 'login')`). Once the signature check for *that* organization passes, the entire raw body — including a completely independent `repository.full_name` field — is handed unmodified to `Shipit::Webhooks::Handlers::Handler`, which resolves the target `Stack`/`Repository` using `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing ties these two fields together, so the organization whose secret authenticated the request is not necessarily the organization/repository that the handler actually mutates.

### Finding Description
`verify_signature` computes `repository_owner` from the body and fetches the matching `GitHubApp` config to verify the `X-Hub-Signature` header: [2](#0-1) [3](#0-2) 

`verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization, and otherwise HMACs the *entire raw body* with that organization's secret: [4](#0-3) 

Once this passes, `create` re-parses the same raw body and dispatches it to handlers based only on `X-Github-Event`, with no re-check that `repository.full_name` matches `repository.owner.login`: [5](#0-4) 

Handlers such as `PushHandler` resolve the `Stack`/`Repository` to act on purely from `repository.full_name` in the payload, independent of which org's secret validated the request: [1](#0-0) [6](#0-5) 

This is structurally the same class of bug as the reported issue: the value used to establish trust (`_prevUserAddress` / here, `repository.owner.login` used to pick the signing organization) is not verified to correspond to the value actually acted upon (`bid position` / here, `repository.full_name` used to select the Stack that gets written to). Concretely: any organization configured in `Shipit.github` with no `webhook_secret` set (which the setup docs list as optional — `webhook_secret: # nil` in `config/secrets.development.example.yml`), or whose secret the attacker knows (e.g., their own onboarded org), lets an attacker send a signed-looking (or unsigned-but-accepted) webhook whose `repository.owner.login` is that permissive/known org, while `repository.full_name` names a *different*, victim stack tracked by this Shipit instance. `verify_signature` only checks the org named in `owner.login`; the handler then blindly syncs/updates the victim stack named in `full_name`.

### Impact Explanation
Because the resolved `Repository` for signature purposes and the `Repository` actually mutated by the handler are two independently attacker-controlled fields in the same unauthenticated JSON body, an attacker can forge `push` events (triggering `Stack#sync_github` on a victim stack via `PushHandler`) or `status`/`check_suite` events affecting commit deployability/merge-readiness for a stack they do not own, using only a signature that is valid for an org they control or that has no secret configured at all. This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope, and can manifest as an unauthorized sync/deploy-readiness manipulation on a repository the attacker does not otherwise have write access to.

### Likelihood Explanation
Exploitability depends on deployment specifics: it requires at least one organization configured in the Shipit instance's `Shipit.github` config with either no `webhook_secret` set, or a secret the attacker can obtain by being a legitimate GitHub App installer/member of that org — a realistic multi-tenant scenario explicitly supported by this engine's config format (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml` show multiple orgs configured on one instance). Given that setup, no additional privileges (no Shipit session, no `ApiClient` token) are needed — only the ability to POST to `/webhooks` with a crafted payload and, if required, a valid signature for the attacker's own org.

### Recommendation
Cross-validate that `repository.owner.login` (the field used to select the verifying `GitHubApp`/secret) is consistent with `repository.full_name` (the field used by handlers to resolve the target `Stack`), rejecting the webhook if they disagree. Alternatively, derive the target Stack/Repository lookup from the same organization that was used for signature verification rather than trusting a second, independently-controlled payload field.

### Proof of Concept
1. Configure Shipit with two organizations in `Shipit.github`: `victim-org` (tracked stacks, has a `webhook_secret`) and `attacker-org` (no `webhook_secret` configured, or one the attacker knows).
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<forged sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker POSTs this to `/webhooks` with `X-Github-Event: push` and (if needed) a signature computed with `attacker-org`'s secret, or omits/mismatches the header entirely if `attacker-org` has no secret configured.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches that org's `GitHubApp`, and the check passes (trivially, if no secret is set) [2](#0-1) .
5. `PushHandler.call(params)` resolves the target stack via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"` and invokes `stack.sync_github(...)` on the victim's stack [1](#0-0) [6](#0-5) , even though only `attacker-org`'s (non-)secret was verified.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
