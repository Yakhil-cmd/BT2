### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the affected Stack is selected using the unrelated `repository.full_name` field, allowing an org whose GitHub App secret is known to the attacker to forge writes against a different org's repositories - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate the HMAC signature against solely from `repository.owner.login` (with a fallback to `organization.login`), while every webhook handler (`Shipit::Webhooks::Handlers::Handler#repository_name` and subclasses like `PushHandler`) determines *which repository/stack to act on* from a completely different field of the same payload: `repository.full_name`. Nothing ties these two fields together, so a payload can be crafted where the org used to select the signing secret is not the org that the resulting write actually targets.

### Finding Description
The webhook signature check is: [1](#0-0) 

using [2](#0-1) 

`repository_owner` is derived purely from `repository.owner.login` (or `organization.login`) in the untrusted JSON body. `Shipit.github(organization: repository_owner)` looks up the `webhook_secret` configured for *that org name* and verifies the raw POST body's HMAC against it.

Once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers that determine the target repository from a *different* field: [3](#0-2) 

and, e.g., for pushes: [4](#0-3) 

The trust binding that Shipit's webhook design relies on is: *"the organization whose secret authenticated this HTTP request == the organization that owns the repository being mutated."* The code enforces `repository.owner.login == secret-selection key`, but performs writes based on `repository.full_name`, a sibling field in the same attacker-controlled JSON body that is never checked for consistency with `repository.owner.login`. Because Shipit explicitly supports multiple, independently configured GitHub organizations in one instance (each with its own `webhook_secret`, per `docs/setup.md` "Using Multiple Github Applications" and `config/secrets.development.shopify.yml`), an admin/owner of any one configured organization already legitimately possesses that organization's `webhook_secret` (they configured it themselves in their GitHub App settings). That person can POST directly to the public `/webhooks` endpoint (this route is not gated by a Shipit session, `ApiClient` token, or GitHub App private key — only by the raw HMAC check) with:
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` picks their own known secret and the signature validates), and
- `repository.full_name` = `"victim-org/victim-repo"` (any repository already registered as a Shipit `Repository`/`Stack` on that Shipit instance, belonging to a completely unrelated organization).

The `Handler` classes only use `repository.full_name` to look up `Repository.from_github_repo_name` and its stacks/review-stacks — they never re-check `repository.owner.login`. This lets the request act on the victim stack even though the signature only proves knowledge of the attacker's own org's secret.

### Impact Explanation
This is an unauthorized cross-organization write via a forged event on someone else's stack, satisfying the "cross-repository writes" / "unauthorized deploy, rollback or merge" Critical bucket. Concretely:
- `PushHandler` can queue `stack.sync_github(expected_head_sha: ...)` for a victim's stack via a fabricated `push` payload, causing Shipit to sync/advance commit state for a repo the attacker's org has no legitimate relationship to.
- The pull-request handlers (`LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `ClosedHandler`, `LabelCapturingHandler`) can `archive!`/`unarchive!` a victim's review stack (which triggers deprovisioning/provisioning side effects) by forging `pull_request` events with the victim's `repository.full_name`, purely on the strength of a signature computed with the attacker's own org secret.
- Depending on which handlers are registered for other events (e.g. `status`, `check_suite`), similar full_name-driven writes on victim commits/checks are possible too.

### Likelihood Explanation
Requires the attacker to be an admin of at least one GitHub organization that this specific Shipit instance has configured as a tenant (multi-org setup is a documented, supported configuration, not a misconfiguration). This is a real barrier — not "unprivileged internet attacker" in the strictest sense — but it does not require any Shipit session, `ApiClient` token, GitHub App private key, or the victim organization's cooperation, and the `/webhooks` endpoint is unauthenticated aside from this flawed per-payload-field HMAC check. Crafting the raw JSON body and its HMAC is trivial once the attacker's own `webhook_secret` is known (they set it themselves).

### Recommendation
After selecting the GitHub App/secret via `repository_owner`, verify that the same field (`repository.owner.login`, or equivalently that `repository.full_name` starts with `"#{repository_owner}/"`) is used consistently by the handlers when resolving the target `Repository`/`Stack`, e.g., by having `Handler#repository_name` accept/validate the organization from `WebhooksController` and reject payloads where `repository.full_name`'s owner segment doesn't match `repository.owner.login` used for signing. Alternatively, look up the `Repository`'s configured organization and ensure it equals the org whose secret verified the request before invoking any handler.

### Proof of Concept
1. Shipit instance is configured (per `docs/setup.md`) with two orgs: `attacker-org` (attacker is the GitHub App owner/admin, knows its `webhook_secret`) and `victim-org` (unrelated, has a `Stack` for `victim-org/victim-repo` already registered in Shipit).
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already known/pushed in victim-org/victim-repo>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, raw_body)`.
4. Attacker POSTs this to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature validates (since it was computed with that org's real secret).
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` (per `app/models/shipit/webhooks/handlers/handler.rb`) and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack, entirely unauthenticated by anything related to `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
