### Title
Webhook Signature Verification Selects the Signing Organization From an Unverified Field, Allowing Cross-Organization Event Forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate an incoming webhook against based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated JSON body, before the signature has been checked. Because `verify_webhook_signature` treats a **blank/unset** `webhook_secret` as automatically valid, any organization configured in a multi-org Shipit deployment without a `webhook_secret` becomes a skeleton key: an attacker can address the request to that organization (satisfying `verify_signature`) while populating the rest of the payload — notably `repository.full_name`, which downstream handlers use to resolve the actual `Repository`/`Stack` — with the identity of a *different*, fully-configured organization/repository. This breaks the intended binding "organization that authenticated the request == repository that gets written to."

### Finding Description
`verify_signature` computes the signing organization purely from attacker-supplied JSON, prior to any cryptographic check: [1](#0-0) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

That value is fed into `Shipit.github(organization: repository_owner)`, which looks up the corresponding `GitHubApp` and its `webhook_secret` in the multi-org config format documented in `docs/setup.md` and exercised in `test/dummy/config/secrets_double_github_app.yml`: [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly bypasses HMAC verification whenever no `webhook_secret` is configured for that organization: [3](#0-2) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Once `verify_signature` passes, `create` dispatches the *entire* raw payload — including `repository.full_name` — to the registered handlers: [4](#0-3) 

Handlers such as `PushHandler` resolve the target `Stack`/`Repository` from `repository.full_name` (owner+name), a field distinct from `repository.owner.login` used only for the signature-app lookup: [5](#0-4) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repository) are independent, attacker-controlled JSON fields in the same unsigned/unverified request when the selected org has no secret, nothing enforces that they refer to the same organization. The equality the system implicitly relies on —
`organization_that_signs(payload) == organization_of(repository_acted_upon)`
— is not enforced, and can be broken whenever any organization in the multi-org config omits `webhook_secret`.

### Impact Explanation
This allows an unauthenticated attacker to forge `push`, `status`, or `check_suite` events for a Stack belonging to an organization that *does* have a properly configured `webhook_secret`, by simply routing the request through any other configured organization that has none. Consequences include triggering `GithubSyncJob`/`sync_github` on arbitrary stacks (via forged `push`), injecting fabricated commit `Status` records that CI/merge-queue gating logic depends on, or spoofing `check_suite` results — each of which can influence or trigger deploys, rollbacks, or merges on target repositories the attacker does not control. This meets the "unauthorized deploy, rollback or merge" / "unauthenticated read of stack state" bar for High/Critical impact defined in scope.

### Likelihood Explanation
Likelihood is contingent on the deployment being configured with Shipit's documented "Using Multiple Github Applications" feature (`docs/setup.md`) and at least one configured organization having `webhook_secret` left blank — a state the example configs (`config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml`) show is an anticipated, valid configuration, not a misconfiguration outside the documented setup. No credentials, session, or API token are required to exploit it — only knowledge that such an organization exists (discoverable, e.g., by testing which organization name a webhook to `/webhooks` accepts without a valid signature).

### Recommendation
After resolving the target repository/stack for a webhook event, verify that the repository's stored `owner` matches the organization whose `webhook_secret` was used to accept the request, rejecting the event otherwise. Additionally, consider requiring `webhook_secret` to be present for every organization in a multi-org configuration (fail closed rather than fail open when absent), and never allow `verify_webhook_signature` to return `true` when no secret is configured.

### Proof of Concept
1. Deploy Shipit with a multi-org config where `OrgA` has a `webhook_secret` set and `OrgB` has `webhook_secret: nil` (a valid documented configuration, per `docs/setup.md`).
2. Send `POST /webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/target-repo",
    "name": "target-repo"
  }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required because `verify_signature` resolves `Shipit.github(organization: 'OrgB')`, whose `verify_webhook_signature` returns `true` unconditionally since `OrgB` has no `webhook_secret`.
3. `PushHandler#process` runs against `OrgA/target-repo`'s stacks (resolved via `repository.full_name`), invoking `stack.sync_github(expected_head_sha: params.after)` on a stack the attacker does not have any legitimate access to.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
