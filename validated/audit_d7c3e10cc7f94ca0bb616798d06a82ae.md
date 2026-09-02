I found a genuine binding break: the webhook signature verification selects its `GitHubApp`/secret using an **organization** value taken from the *unauthenticated* payload (`repository.owner.login` or `organization.login`), while the actual entity acted upon by handlers is a **repository** identified by a completely different payload field (`repository.full_name`). These two values are never cross-checked against each other.

### Title
Webhook organization used to select the signing secret is not bound to the repository the handler acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to verify against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `organization.login`) [1](#0-0) . Once the signature check passes, every registered handler is invoked with the same raw payload and independently re-reads `repository.full_name` to resolve the target `Repository`/`Stack` [2](#0-1) . Nothing ties the "organization" whose secret validated the signature to the "repository" that the handler subsequently mutates - they are two independent fields of the same attacker-influenced JSON body.

### Finding Description
The equality that should hold is:

`organization whose webhook_secret authenticated the request == owner of the repository actually mutated by the handler`

In practice the engine only enforces: `HMAC_sha1(secret_for(payload['repository']['owner']['login']), raw_body) == X-Hub-Signature`. This makes the "authenticated organization" field self-referential - it is read from inside the very body the signature is supposed to protect - and separately, `PushHandler`/other handlers resolve the acted-on stack purely from `payload['repository']['full_name']` [3](#0-2) . If an installation onboards multiple GitHub organizations (the multi-org config format is explicitly supported, see `config/secrets.development.shopify.yml`) with different `webhook_secret`s, an attacker who only knows/controls the (potentially unset or weak) secret for organization A can craft a payload where `repository.owner.login` is `A` (so the signature check resolves and validates against A's secret) while `repository.full_name` names a stack that actually belongs to organization B. `Shipit.github(organization: repository_owner)` is only used to pick the HMAC key, not to constrain which repositories the payload is allowed to reference [4](#0-3) .

This is exploitable in the specific case where a target organization's `webhook_secret` is nil/blank: `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank [5](#0-4) . An unprivileged external attacker who knows (from public config docs/templates) that an org has no `webhook_secret` configured can post directly to `/webhooks` with `repository.owner.login` set to that unconfigured org (bypassing the HMAC check entirely) while setting `repository.full_name` to a **different**, fully-configured, privileged organization's repository/stack. The push handler will then act on that stack: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` [3](#0-2) .

### Impact Explanation
This crosses the "unauthenticated read/write of stack state" and potentially "unauthorized deploy" bars: `sync_github` with an attacker-chosen `expected_head_sha` can force resynchronization of undeployed-commit tracking and CI status refresh for a stack the attacker does not control, and other handlers (status, check_suite, membership) similarly resolve their target purely from body fields that are not covered by any signature bound to that specific repository's own organization. Because the signature only proves "some request signed with organization A's secret", not "this specific repository belongs to organization A", it lets an attacker who controls (or lacks) one org's secret inject events for any other org's repositories configured on the same Shipit instance.

### Likelihood Explanation
Likelihood is Medium: it requires a multi-organization Shipit deployment (explicitly a first-class supported configuration in this engine) where at least one configured organization has no `webhook_secret` (also an explicitly supported/documented configuration - see the `# nil` webhook_secret entries in `config/secrets.development.shopify.yml`). Given that, no credentials, session, or write access is needed - a bare HTTP POST to the public `/webhooks` endpoint suffices.

### Recommendation
Bind the signature verification to the repository actually being acted upon, not to an independently-read "organization" field: after determining the organization from the payload, verify that `payload['repository']['full_name']`'s owner matches `repository_owner`, and reject events where a handler's target repository organization differs from the organization whose secret validated the signature. Alternatively, require that every organization onboarded onto a multi-tenant Shipit instance configure a non-blank `webhook_secret`, and fail closed (422) rather than treating a blank secret as "always verified".

### Proof of Concept
1. Configure Shipit with two GitHub orgs in `secrets.yml`: `org-unsecured` (no `webhook_secret`) and `org-victim` (has stacks, has a secret).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "org-victim/some-repo",
    "owner": { "login": "org-unsecured" }
  }
}
```
3. `repository_owner` resolves to `org-unsecured`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (absent/garbage) `X-Hub-Signature` header [5](#0-4) .
4. `PushHandler#process` still resolves stacks via `payload['repository']['full_name']` = `org-victim/some-repo` and triggers `stack.sync_github(expected_head_sha: ...)` on the victim organization's stack [3](#0-2) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
