### Title
Webhook signature is verified against the *claimed* organization but the event handlers act on an unrelated `repository.full_name`, and an unset `webhook_secret` makes the check pass unconditionally - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary

### Finding Description
The DYAD bug is a case where the code checks one quantity (collateral − debt) but pays out based on a different, unguarded quantity (debt), breaking the intended `paid_amount == checked_amount` binding. `Shipit`'s webhook pipeline has the same shape of bug: the field used to select *which secret verifies the signature* is not the same field used to decide *which repository/stack the event is applied to*.

`WebhooksController#verify_signature` picks the GitHub App/organization config - and therefore the HMAC secret - purely from the payload's `repository.owner.login` (or `organization.login`): [1](#0-0) [2](#0-1) 

But every handler that actually mutates state resolves its target repository from a **different field**, `repository.full_name`, via `Handler#stacks`/`#repository_name`: [3](#0-2) 

and `PushHandler`/`CheckSuiteHandler` use whatever `Repository.from_github_repo_name(repository_name)` resolves to, independent of the organization that was used to select the verifying secret: [4](#0-3) 

Worse, `StatusHandler` does no repository scoping at all - it matches commits **globally by `sha`** across every stack in the installation: [5](#0-4) 

Finally, the signature check itself has a silent bypass: if the resolved organization's config has no `webhook_secret` set, `verify_webhook_signature` returns `true` unconditionally instead of rejecting: [6](#0-5) 

The setup docs explicitly document `github.webhook_secret` as optional ("If you've set a webhook secret during the App creation, you should copy it here"), so this is a supported, not a hypothetical, configuration: [7](#0-6) 

The binding that should hold is:
`organization_used_to_select_secret(repository.owner.login) == organization_that_owns_the_repository_actually_mutated(repository.full_name)`

Before any fix, this equality is never checked. Once the "authenticate on one field" step passes (either because the org's `webhook_secret` is unset, making it trivially `true`, or because a previously-onboarded organization's secret happens to be blank), the handler layer trusts a completely independent field (`repository.full_name`) to decide what `Stack`/`Commit` rows to write - including stacks belonging to organizations whose webhook secret *is* correctly configured.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary called out as an in-scope analog. On any multi-tenant Shipit install that has at least one GitHub organization configured without a `webhook_secret` (an explicitly supported, documented configuration), an unauthenticated party can:
- Send a forged `push` event whose `repository.owner.login` matches the secret-less organization but whose `repository.full_name` names a Stack belonging to an entirely different, properly-secured organization, causing `Stack#sync_github` to run against attacker-chosen `expected_head_sha` for that unrelated repository — an unauthorized cross-repository write/trigger. [4](#0-3) 
- Send a forged `status` event that is accepted the same way and, because `StatusHandler` performs no repository scoping whatsoever, forge a commit status (e.g. mark CI as passing) for **any commit sha in the entire installation**, regardless of which org "authenticated" the request. [5](#0-4) 

This is an authentication-bypass-class impact (forged, unauthenticated GitHub events accepted as genuine) that leads to cross-repository state writes and can be leveraged to make a stack falsely appear deployable/mergeable — matching the required "cross-repository writes" / "unauthorized deploy" impact bucket.

### Likelihood Explanation
Requires only that the Shipit deployment has onboarded at least one organization whose `github.webhook_secret` was left unset - a state the project's own setup docs present as normal/optional, not requiring any leaked credential, session, or private key. No `ApiClient` token, session, or GitHub App private key is needed; the request is a plain unauthenticated `POST` to the webhooks endpoint.

### Recommendation
- In `WebhooksController#verify_signature`, reject (422) rather than accept when `webhook_secret` is blank for the resolved organization, unless the app explicitly runs in a documented "no verification" mode.
- Cross-check that the organization used to select the verifying secret (`repository.owner.login`/`organization.login`) matches the owner embedded in `repository.full_name` before dispatching to handlers.
- In `Handler#repository_name`/`#stacks`, and specifically in `StatusHandler`, scope lookups (including `Commit.where(sha: ...)`) to the repository verified by the signature check, not merely a same-named but potentially cross-tenant sha match.

### Proof of Concept
1. Configure (or find) an onboarded GitHub organization `org-without-secret` in `Shipit.github_teams`/app config that has no `webhook_secret` set (per `docs/setup.md`, this field is optional).
2. As an unauthenticated client, `POST /webhooks` with header `X-Github-Event: push` and body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "owner": { "login": "org-without-secret" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. `WebhooksController#verify_signature` resolves `repository_owner` to `org-without-secret`, whose `webhook_secret` is blank, so `verify_webhook_signature` short-circuits to `true` regardless of the actual header value.
4. `PushHandler#process` resolves the target via `repository.full_name` = `victim-org/victim-repo` and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a stack belonging to an entirely different, properly-secured organization.
5. Repeating with `X-Github-Event: status` and any `sha` demonstrates the global, repository-unscoped commit-status forgery via `StatusHandler`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```
