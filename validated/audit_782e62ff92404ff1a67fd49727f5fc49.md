### Title
`Shipit::WebhooksController#repository_owner` selects the HMAC verification key from an untrusted field independent of the field used to locate the mutated `Repository`/`Stack` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`repository_owner` (line 61) picks the organization whose `webhook_secret` is used for HMAC verification from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `Handler#repository_name` (app/models/shipit/webhooks/handlers/handler.rb:37) independently reads `payload.dig('repository','full_name')` to locate the `Repository`/`Stack` that gets mutated. Because both values come from the same attacker-controlled raw JSON body and are never cross-checked, an attacker can forge a payload that verifies against their own organization's secret while acting on a victim's repository.

### Finding Description
The binding that must hold is: `organization identified by params.dig('organization','login')` (the key used to select the HMAC secret in `verify_signature`) `== owner of params.dig('repository','full_name')` (the repository actually looked up by `Handler#repository_name` and used to build `stacks` in `handler.rb:32-38`). This equality is never asserted anywhere in `WebhooksController` or `Handler`.

Concretely, `verify_signature` (webhooks_controller.rb:24-49) calls `Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that organization's `webhook_secret`. `repository_owner` (line 61) only reads `repository.owner.login`, falling back to `organization.login` when `repository.owner.login` is absent. An attacker can send a webhook body containing:
- `"organization": {"login": "attacker-org"}` — an organization the attacker owns/controls in Shipit, so they know its `webhook_secret`.
- `"repository": {"full_name": "victim-org/victim-repo"}` — no `owner` sub-object, so `params.dig('repository','owner','login')` is `nil`.

`repository_owner` then falls back to `'attacker-org'`, and `verify_signature` validates the signature using the attacker's own known secret — which succeeds because they compute the HMAC themselves.

Once signature verification passes, `WebhooksController#create` dispatches to the matching `Handler` (e.g. `PushHandler`) with the same raw `payload`. That handler's `stacks` method (handler.rb:32-34) calls `Repository.from_github_repo_name(repository_name)`, and `repository_name` reads `payload.dig('repository','full_name')` — `'victim-org/victim-repo'` — completely independent of the `attacker-org` value used for verification. This resolves to the real victim `Repository`, and the handler proceeds to mutate the victim's `Stack` (e.g. `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every matching branch, app/models/shipit/webhooks/handlers/push_handler.rb:12-17), driven entirely by attacker-supplied `ref`/`after` values.

No existing guard prevents this: `drop_unhandled_event` only checks the event type is handled; `verify_signature` verifies the signature against a key chosen by the same forged payload; the `ExplicitParameters` schemas (e.g. `PushHandler.params`) only require `ref`/`after`, not that `repository.owner.login` matches `organization.login`; and `Handler#repository_name`/`stacks` perform no ownership cross-check against the value used for signature verification.

### Impact Explanation
An attacker who owns any organization known to Shipit (i.e., has a legitimate but unprivileged Shipit org with its own `webhook_secret`) can forge webhook events that pass signature verification under their own secret, yet cause `Repository.from_github_repo_name`/`stacks` to target an arbitrary victim repository named in `repository.full_name`. This lets the attacker trigger handler-side writes/mutations against a repository and Stack they do not own and never authenticated for — e.g. forcing `Stack#sync_github` calls, or other handler-driven state changes (team membership only in `MembershipHandler`'s case actually matches since it uses `organization.login` consistently, but any handler following `Handler#repository_name`, such as `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and the `PullRequest` handlers, is exposed). This is a cross-repository/cross-tenant authentication-bypass class of bug: the signature check authenticates "does this event come from *an* organization I trust," not "does this event come from *the organization that owns the repository named in the payload*." The blast radius spans every repository/stack in the Shipit instance and is repeatable at will by any attacker with one legitimate organization webhook secret.

### Likelihood Explanation
Preconditions: the attacker needs one Shipit-known organization to be registered with a `webhook_secret` they control (e.g., their own GitHub org, added to Shipit as any other tenant would be) — no special privilege, GitHub team membership, or Shipit session is required. The attacker crafts the raw JSON body themselves and computes the HMAC using their own known secret, then POSTs to `/webhooks` with the appropriate `X-Github-Event` header. This is a direct, cheap, and fully repeatable HTTP request against arbitrary victim `full_name` values, requiring no interaction with GitHub itself.

### Recommendation
In `WebhooksController`, verify the signature using the same repository/organization context that the dispatched `Handler` will use, or explicitly assert that the organization used for verification matches the owner of `payload.dig('repository','full_name')` before dispatching. Concretely: derive `repository_owner` solely from `payload.dig('repository','full_name')`'s owner segment (splitting `full_name`) rather than trusting a separate `organization.login` fallback, or reject payloads where `repository` is present without a consistent `owner.login` matching `organization.login`. Additionally, `Handler#repository_name` (or a shared base method) should assert that the resolved repository's owner equals the verified `repository_owner` before proceeding to mutate any `Stack`.

### Proof of Concept
Minitest under `test/controllers/shipit/webhooks_controller_test.rb` (or `test/models/shipit/webhooks/handlers_test.rb`):
1. Create two orgs/repos in fixtures: `attacker-org/attacker-repo` (attacker knows `Shipit.github(organization: 'attacker-org').webhook_secret`) and `victim-org/victim-repo` with an existing `Stack`.
2. Build payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "organization": {"login": "attacker-org"},
  "repository": {"full_name": "victim-org/victim-repo"}
}
```
3. Compute `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw JSON body.
4. POST to `/webhooks` with header `X-Github-Event: push` and the computed signature.
5. Assert response is `200`/`204` (i.e., `verify_signature` passed) — confirming `WebhooksController#repository_owner` resolved to `'attacker-org'` (equality check 1: `repository_owner == 'attacker-org'`).
6. Assert `Handler#repository_name` / `Repository.from_github_repo_name(payload.dig('repository','full_name'))` resolves to the victim's `Repository` (equality check 2: `repository_name == 'victim-org/victim-repo'`), and assert that the victim `Stack#sync_github` (or equivalent handler mutation) was invoked/enqueued — proving `attacker-org` (verification identity) ≠ owner of `victim-org/victim-repo` (mutation identity), with no code path in between that rejects the mismatch. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
