### Title
Webhook signature is verified against the organization named in `repository.owner.login`, while the actual write target is selected from the untied `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to HMAC-verify the request against using an attacker-controlled field of the very payload being verified — `repository.owner.login` (or `organization.login`) — while every event `Handler` (`app/models/shipit/webhooks/handlers/handler.rb`) resolves the repository/stacks to mutate using a *different* field of the same payload, `repository.full_name`. Nothing binds these two fields together, so an attacker who legitimately controls a GitHub organization/App installation wired into this Shipit instance (and therefore knows that organization's `webhook_secret`) can craft a signed payload whose `repository.owner.login` names their own org (to pass verification) while `repository.full_name` names a repository belonging to a different organization/stack, causing the handler to act on that other repository.

### Finding Description
`verify_signature` computes the verifying organization purely from payload content, before any handler-level authorization: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the per-organization `webhook_secret` and `verify_webhook_signature` HMACs the raw body against it: [3](#0-2) 

Once verification passes, `create` dispatches the full parsed payload to every handler registered for the event: [4](#0-3) 

But `Handler#stacks`/`repository_name` resolve the target repository from `repository.full_name`, a field never checked against `repository.owner.login`: [5](#0-4) 

`Repository.from_github_repo_name` then does a straight `owner/name` lookup with no cross-check to the organization that was authenticated: [6](#0-5) 

`PushHandler`, for example, uses that resolved `stacks` to trigger `sync_github` (a real write/side-effect) directly from attacker-supplied `ref`/`after` values: [7](#0-6) 

The trust binding broken: **organization that authenticated == repository that is written**. The signature only proves the byte-for-byte body was signed with organization *X*'s secret; it proves nothing about which `repository.full_name` inside that body the handlers should be allowed to touch. GitHub itself keeps these fields consistent for real deliveries, but the verification code does not enforce that — it trusts unvalidated JSON content to select the verification key and then trusts a *different* unvalidated JSON field to select the mutation target.

### Impact Explanation
Any organization/GitHub App installation configured on this multi-tenant Shipit instance can forge a payload that is correctly signed for its own organization but names an arbitrary `repository.full_name`. Depending on handler, this can:
- Force `PushHandler` to call `stack.sync_github(expected_head_sha:)` on another organization's stack — a cross-repository/cross-tenant write and potential trigger for downstream sync/deploy flow.
- Feed forged `StatusHandler`/`CheckSuiteHandler`/pull-request events that influence merge/CI gating on repositories the attacker's organization does not own.

This matches the in-scope "cross-repository writes" / "unauthorized deploy" impact category since the binding broken is exactly the one called out in scope: organization authenticated vs. repository written.

### Likelihood Explanation
Requires the attacker to control (or have configured) a legitimate GitHub organization/App installation already wired into this shared Shipit instance, i.e., knowledge of that organization's own `webhook_secret` — no Shipit session, `ApiClient` token, or GitHub repo write access to the *victim* repository is needed. In a multi-tenant deployment (the documented supported use case — multiple `Shipit.github_apps` per organization), this is a plausible unprivileged-attacker path since the attacker only needs control of their own org's webhook delivery, not the victim's.

### Recommendation
After verifying the signature, re-validate that `repository.full_name`'s owner segment matches the authenticated `repository_owner` (or `organization.login`) before dispatching to handlers, and reject the request (422) on mismatch. Alternatively, have handlers derive the repository strictly from the same field used for signature verification, not from a second, independently-controlled field of the same payload.

### Proof of Concept
1. Attacker controls/owns GitHub organization `attacker-org`, which has a legitimate GitHub App installation on this Shipit instance with a known `webhook_secret`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), and the HMAC checks out — request passes.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on `victim-org`'s stack, even though the signature never authenticated anything about `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
