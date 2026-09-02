### Title
Webhook signature verification keys off `repository.owner.login`, but event handlers dispatch writes based on the unrelated `repository.full_name` field, breaking the "organization authenticated = repository written" binding - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the inbound signature against using `repository_owner`, taken from the payload's `repository.owner.login` (or `organization.login`) field. [1](#0-0) [2](#0-1)  Once the request is accepted, every `Handler` subclass determines the target `Repository`/`Stack` to act on using a *different* field: `payload.dig('repository', 'full_name')`. [3](#0-2)  In a multi-organization Shipit deployment (as documented and tested in `test/dummy/config/secrets_double_github_app.yml`, which configures independent `webhook_secret`s per org), these two fields are never checked for consistency against each other.

### Finding Description
The trust chain Shipit relies on is: "the organization whose secret validated this signature" == "the repository the payload's handler will act on." These are two different JSON fields in the same payload:
- Verification binds to `repository.owner.login` (`repository_owner`).
- Handler dispatch (`PushHandler`, `CheckSuiteHandler`, `MembershipHandler`, etc., via `Handler#stacks`/`#repository_name`) binds to `repository.full_name`. [4](#0-3) 

Because the HMAC signature covers the entire raw request body, an attacker cannot arbitrarily tamper with a legitimate payload from Org A without invalidating Org A's signature. However, a Shipit instance that hosts multiple organizations, each with an independently configured GitHub App/`webhook_secret` (exactly the scenario the engine explicitly supports, per `Shipit.github(organization: ...)` and the double-app fixture), lets an attacker who administers their **own** connected organization (call it OrgB, with a legitimately-known `webhook_secret`) construct and sign an entirely new payload themselves. Nothing stops them from setting `repository.owner.login`/`organization.login` to `"OrgB"` (so verification passes with OrgB's own secret) while setting `repository.full_name` to `"OrgA/victim-repo"` (a repository belonging to a different, unrelated org onboarded to the same Shipit instance). `verify_signature` only proves the payload was signed with OrgB's secret — it proves nothing about which repository `full_name` claims to belong to.

### Impact Explanation
This lets an org-admin of any organization connected to a shared multi-tenant Shipit instance force actions against another organization's repositories/stacks without holding any credentials for that other organization: e.g. forcing `PushHandler` to invoke `stack.sync_github` for an arbitrary victim stack, or forcing `MembershipHandler`/`CheckSuiteHandler` to mutate `Team`/`Commit` state tied to a victim repository — all executed using **Shipit's own stored GitHub credentials** for the victim org (`Shipit.github(organization: ...)` inside `Stack`, `MergeRequest`, `Team`, etc.), not the attacker's. This is a genuine cross-organization/cross-repository write capability that the signature check was supposed to prevent, matching the "organization authenticated vs. repository written" binding called out as in-scope.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where more than one organization/GitHub App is configured (a documented, supported configuration — see `test/dummy/config/secrets_double_github_app.yml`), and requires the attacker to control (or be an admin/owner of) at least one of those onboarded organizations so they legitimately know that org's `webhook_secret`. No compromise of the victim org, no `ApiClient` token, and no session on the target Shipit instance is required — only the ability to send an HTTP POST to the shared `/github/webhooks` endpoint with a payload signed by their own org's secret.

### Recommendation
After `verify_signature` succeeds, re-derive `repository_owner` from the *same* field the handlers use (`repository.full_name`'s owner segment) and reject the request (422) if it does not match the organization whose secret validated the signature. Alternatively, have handlers resolve the target `Repository`/`Stack` using `repository_owner` (the field actually covered by verification) rather than trusting `full_name` independently, ensuring a single, verification-bound field drives both signature selection and write dispatch.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgB` (attacker-administered) and `OrgA` (victim), each with its own `webhook_secret`, mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a JSON payload for the `push` event:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "owner": { "login": "OrgB" },
       "full_name": "OrgA/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature` using OrgB's known `webhook_secret` over the raw body and POSTs to `/github/webhooks`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'OrgB')` and successfully verifies the signature (app/controllers/shipit/webhooks_controller.rb:25-30).
5. `Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` resolution uses `payload.dig('repository', 'full_name')` = `"OrgA/victim-repo"` (app/models/shipit/webhooks/handlers/handler.rb:36-38), triggering `stack.sync_github` against the victim's OrgA stack, using Shipit's OrgA credentials — despite the request never being signed by OrgA's secret.

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
