### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while event handlers act on the unverified `repository.full_name` — allows cross-tenant status/push forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC validation based on a value read out of the **unverified** JSON body, and that value is not the same field the downstream event handlers use to decide which `Repository`/`Stack` the event applies to. This breaks the intended binding "organization whose signature authenticated the request == repository that gets written to."

### Finding Description
`verify_signature` computes the signing organization purely from the raw, not-yet-verified payload: [1](#0-0) [2](#0-1) 

`repository_owner` is taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) in the JSON body supplied by the caller. `Shipit.github(organization: repository_owner)` looks up the per-organization config (each configured GitHub org has its own `webhook_secret`, as shown in `config/secrets.development.shopify.yml`), and the signature is verified against **that** org's secret: [3](#0-2) 

Once the signature check passes, the actual event handlers determine which `Repository`/`Stack` to mutate using a **different** field from the same payload — `repository.full_name` — via `Handler#repository_name`/`#stacks`: [4](#0-3) 

`Repository.from_github_repo_name` does a naive lookup by `owner/name` split from that string with no cross-check against the organization that produced a valid signature: [5](#0-4) 

Because `repository.owner.login` (used for auth) and `repository.full_name` (used for the write) are independent JSON fields that a caller fully controls, an attacker who legitimately administers **any** GitHub organization that is configured in this Shipit instance (and therefore knows/can produce a signature valid for that org's `webhook_secret`) can set:
- `repository.owner.login` = their own org (so `verify_signature` picks their own org's `webhook_secret` and the HMAC validates), while
- `repository.full_name` = `"victim-org/victim-repo"` (a totally different, unrelated tenant's tracked repository)

This is the equality-breaking analog to the CTF/Venus finding pattern of "value the check is performed on ≠ value the action actually uses": here it's "org authenticated" ≠ "repository written."

### Impact Explanation
The most damaging handler reachable this way is `StatusHandler`, which looks up commits purely `by sha` (global, not scoped by repository/stack) and writes a GitHub-originated commit status: [6](#0-5) 

Commit statuses gate CI-required-status checks that determine `deployable?`/`ci.require` gating used before allowing a deploy to be triggered (`Stack#required_statuses`, `soft_failing_statuses`, etc., delegated from `cached_deploy_spec`, referenced in `app/models/shipit/stack.rb`). By forging a `status` event with a valid signature for their own org, but a `sha` belonging to a commit tracked under a **different** tenant's stack, an attacker can inject a fabricated "success" status for a required CI context on a commit they do not control, potentially satisfying the deploy-eligibility checks for a repository/stack the attacker has no legitimate access to and thereby facilitating an unauthorized deploy of that commit. `PushHandler`/`Handler#stacks` similarly resolve `stacks` via the mismatched `full_name`, letting an attacker trigger `stack.sync_github` (GithubSyncJob) for a stack outside their org.

This matches the "Critical — unauthorized deploy" / "High — unauthenticated read/write of stack state" impact classes: the deployment-trust binding "authenticated GitHub org == repository the event is applied to" is broken by an unprivileged-but-onboarded attacker (an admin of any tenant org with its own valid webhook secret), with no requirement for a Shipit session, `ApiClient` token, or the victim's own `webhook_secret`.

### Likelihood Explanation
Requires only: (1) the Shipit instance is configured for more than one GitHub organization (a documented, supported multi-tenant setup, per `config/secrets.development.shopify.yml`), and (2) the attacker controls one such onboarded org (able to generate a valid signature for it, e.g. by actually triggering a webhook from their own repo and modifying/replaying the body, or by knowing their own org's `webhook_secret` since they administer that org's GitHub App installation). No access to the victim org, no Shipit credentials, and no GitHub write access to the victim repository are needed — only that the target commit `sha`/`repository.full_name` are known (both are typically public/observable). This is a plausible, low-friction attack path in any Shipit deployment serving multiple tenants.

### Recommendation
Verify the signature and derive the "acting organization/repository" from the *same*, already-verified fields. Concretely:
1. In `WebhooksController#verify_signature`, capture the organization used to select the webhook secret and store it (e.g., `@verified_organization`).
2. Pass `@verified_organization` down to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` and have every `Handler` subclass validate that `payload.dig('repository', 'owner', 'login')` (or `organization.login`) used for the actual repository/stack lookup equals `@verified_organization` before processing; reject (422) on mismatch.
3. Alternatively, stop keying secret selection off attacker-controlled payload fields at all — verify the signature against every configured org's secret and only proceed if the org that matched is also the org referenced by `repository.full_name`.

### Proof of Concept
1. Configure two tenant orgs in Shipit, e.g. `attacker-org` and `victim-org`, each with its own `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. Attacker (who administers `attacker-org` and therefore controls/knows a valid signature for it) sends:
```
POST /github/webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC computed with attacker-org's webhook_secret over body below>

{
  "sha": "<sha of a commit tracked by victim-org/victim-repo stack>",
  "state": "success",
  "context": "required-ci-check",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the signature validates (`app/controllers/shipit/webhooks_controller.rb:24-30`).
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of the `repository.owner` field — and calls `create_status_from_github!`, writing a forged "success" status onto `victim-org/victim-repo`'s commit (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), which the attacker never had write access to.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
