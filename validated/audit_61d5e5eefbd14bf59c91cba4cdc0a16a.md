### Title
Cross-organization webhook signature confusion allows forged writes to unrelated repositories - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate an inbound webhook's HMAC signature based on `repository.owner.login` (falling back to `organization.login`), while the event handlers that subsequently act on the payload resolve the target `Stack`/`Repository` from a completely different field: `repository.full_name`. These two fields are never checked for consistency, so the organization whose secret authenticates the request is not bound to the repository that is actually written to.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and uses it to fetch the corresponding `github_app`/secret via `Shipit.github(organization: repository_owner)` [1](#0-0) [2](#0-1) .

Once the signature check passes, `create` dispatches the *entire raw payload* to the registered handlers [3](#0-2) . Handlers such as `PushHandler` resolve the affected `Stack` using a different field, `repository.full_name`, via `Handler#stacks`/`#repository_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) , then triggers `stack.sync_github(...)` for whatever repository that `full_name` names [5](#0-4) .

Because `repository.owner.login` (used for auth) and `repository.full_name` (used for the actual write target) are independent, attacker-controlled JSON fields, a party who legitimately controls a webhook secret for **any** organization/repository configured in this Shipit instance can craft a payload where `repository.owner.login` matches their own org (so the HMAC they compute with their own secret verifies), while `repository.full_name` names a **different** organization/repository that they do not control. The signature check binds "organization authenticated" to their own org, but the write is performed against the repository named in `full_name`, breaking the equality `organization authenticated == repository written`.

### Impact Explanation
This allows a party with a legitimate webhook secret for one tenant/organization on a shared Shipit instance to forge cross-repository events (e.g., `push`, `status`, `check_suite`) that get accepted as authentic and dispatched against another organization's `Stack`, triggering unintended GitHub sync operations (`sync_github`), commit status writes (`StatusHandler`), or check-run refreshes for repositories outside the attacker's control. This is a cross-repository write achieved purely by manipulating unauthenticated payload fields, matching the Critical "cross-repository writes" impact category.

### Likelihood Explanation
Exploitability depends on the Shipit deployment configuring more than one GitHub organization/app (each with its own `webhook_secret`) while sharing a single `WebhooksController` endpoint, and on an attacker legitimately possessing a webhook secret for at least one of those configured organizations. In such multi-tenant deployments this is straightforward to exploit — the attacker only needs to send a raw POST with a custom `repository.full_name` and a valid `X-Hub-Signature` computed from their own org's secret. It is not exploitable in single-org deployments where `repository_owner` and `full_name` inherently agree.

### Recommendation
Derive both the signing-secret lookup and the target-repository resolution from the *same* payload field (e.g., always use `repository.full_name`, parsed once, to determine both the organization for signature verification and the repository handlers act on), or explicitly assert after verification that `repository.owner.login` matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (attacker-controlled, webhook secret known to attacker) and `org-b` (victim, has a tracked `Stack`).
2. Attacker crafts payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a_webhook_secret, payload)`.
4. POST to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `org-a`, fetches `org-a`'s `github_app`, and the signature verifies successfully [1](#0-0) .
6. `PushHandler` resolves `repository_name` = `org-b/victim-repo` from `full_name` [6](#0-5)  and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim's stack [5](#0-4) , despite the request never being authenticated for `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
