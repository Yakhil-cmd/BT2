### Title
Cross-organization webhook confusion allows unauthenticated org to trigger actions on another org's repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the request against based on `repository_owner`, derived from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified
end
```

`verify_webhook_signature` trivially returns `true` when the resolved application has no `webhook_secret` configured: [3](#0-2) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Once past `verify_signature`, `create` dispatches the *entire raw payload* to handlers, which independently derive the target `Repository`/`Stack` from a **different field**, `payload.dig('repository', 'full_name')`, via `Handler#repository_name`: [4](#0-3) 

Because Shipit supports multi-organization configuration where each org can have its own (or no) `webhook_secret`, an attacker who controls (or is a member of) any GitHub organization configured in Shipit with **no `webhook_secret` set** can craft a webhook payload where `repository.owner.login`/`organization.login` names their own (unprotected) org — satisfying `verify_signature` trivially — while `repository.full_name` names a **different, victim** organization's repository that does have deploy stacks configured. The handler layer never re-checks that the "authenticating" organization matches the repository actually acted upon.

This breaks exactly the trust binding: *"an organization that authenticated versus the repository that is written."* The `verify_signature` before_action authenticates based on `repository.owner.login`, but `PushHandler`/`Handler#stacks` acts on `repository.full_name`, a sibling field in the same unsigned JSON body that is never cross-checked against the authenticated org.

### Impact Explanation
An attacker able to register/administer a GitHub organization (or app installation) that Shipit is configured to trust with no `webhook_secret` (a documented, supported multi-org configuration, see `docs/setup.md` "Using Multiple GitHub Applications") can forge a `push` webhook whose `repository.full_name` points at a victim organization's repository/stack. This causes `PushHandler#process` to invoke `stack.sync_github(expected_head_sha: params.after)` — and other handlers can trigger pull-request/review-stack archiving, membership team creation, etc. — for a repository/org the attacker does not control, without ever presenting a valid signature for that org. This is an authentication-bypass-class issue enabling cross-repository/cross-organization actions (sync triggers, review-stack archive/unarchive, injected commit metadata) that should require a per-organization verified signature.

### Likelihood Explanation
Requires the host Shipit deployment to configure at least two GitHub organizations, one of which has no `webhook_secret` configured (explicitly supported and documented, and shown as a valid config in `test/dummy/config/secrets_double_github_app.yml`, where `webhook_secret:` is left `nil` for both orgs). Given multi-org configs are an intentional, documented feature and `webhook_secret` is explicitly optional per the setup docs, this is a realistic operational configuration, not a hypothetical edge case.

### Recommendation
`verify_signature` and downstream handlers must resolve the repository/organization consistently: the organization used to select and verify against a `webhook_secret` must be the same value used by handlers to resolve `Repository`/`Stack`. Either (a) always require `repository.full_name`'s owner segment to match the organization used for verification, rejecting the payload if they differ, or (b) mandate that every configured GitHub App/organization define a non-blank `webhook_secret` (removing the `return true unless webhook_secret` bypass), or (c) verify against the app config whose owner matches `repository.full_name`'s owner rather than a separately-sourced `repository.owner.login`/`organization.login` field.

### Proof of Concept
1. Shipit configured with two orgs, e.g. `OrgAttacker` (no `webhook_secret`) and `OrgVictim` (has stacks configured), similar to `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgAttacker" },
    "full_name": "OrgVictim/target-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgAttacker")`, whose `webhook_secret` is unset, so `verify_webhook_signature` returns `true` unconditionally — no valid signature for `OrgVictim` is ever required.
4. `create` parses the same body and dispatches to `PushHandler`, which resolves the target via `payload.dig('repository', 'full_name')` = `"OrgVictim/target-repo"`, and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — action taken on a repository never authenticated for this request. [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
