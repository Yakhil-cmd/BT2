Found the binding break: `WebhooksController#verify_signature` selects the GitHub App / webhook secret by the `organization` field the caller supplies (`repository.owner.login`, falling back to `organization.login`), but the handler that later runs (`Handler#repository_name` / `Handler#stacks`) resolves the target stack purely from `payload.dig('repository', 'full_name')` — a completely different, independently attacker-controlled field in the same JSON body. Because HMAC verification only proves the body's *bytes* were signed with the secret keyed off `repository_owner`, not that `repository.full_name` belongs to that same owner, a request signed with organization A's webhook secret can carry a `repository.full_name` pointing at organization B's repository and it will pass signature verification and be processed against B's stacks.

### Title
Webhook signature verified against `repository.owner.login`-derived secret while handlers act on an unbound `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/organization config (and therefore the HMAC secret) using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) from the untrusted payload. The signature is verified over the raw body, but nothing ties the *repository* that the handlers subsequently act on (`Handler#repository_name` = `payload.dig('repository', 'full_name')`) to that same owner. Both fields live in the same attacker-suppliable JSON body sent from a source with a valid webhook secret for any one organization Shipit is configured for.

### Finding Description [1](#0-0) 
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) . This chooses which organization's `webhook_secret` to HMAC-verify against, based on a payload field.

Once verification succeeds, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, unmodified `params` to handlers [3](#0-2) . Handlers such as `PushHandler` resolve the target `Stack`s solely via `Handler#stacks`/`#repository_name`, which reads `payload.dig('repository', 'full_name')` — an entirely separate JSON field from the one used to select the verifying secret [4](#0-3) , [5](#0-4) .

This is the same trust-binding failure shape as the reported bug: an equality that should hold (`"organization whose secret verified this payload" == "organization whose repository is mutated by this payload"`) is never actually enforced by the signature check — the check binds the secret to `repository.owner.login`, but the write-path binds effects to `repository.full_name`. A caller who is a legitimate webhook sender for organization A (i.e., knows A's `webhook_secret`, which is a config-level secret, not one requiring privileged Shipit access) can craft a payload where `repository.owner.login == "A"` (so the correct, known secret is selected and verification passes) but `repository.full_name == "B/some-repo"`. `Repository.from_github_repo_name("B/some-repo")` will then match any stack Shipit has configured for organization B, letting an org-A webhook sender enqueue `GithubSyncJob`, mutate commit statuses, trigger check-run refreshes, or manipulate merge-request/PR state (`opened`, `labeled`, `closed`, etc. handlers) for a stack that belongs to organization B, entirely outside org A's control.

### Impact Explanation
This crosses the "repository write" trust boundary described in scope: an attacker who is only authorized (has webhook credentials) for one repository/organization can cause writes (commit creation via `GithubSyncJob`, `sync_github`, deploy-spec cache invalidation, merge-request status transitions, PR-driven review-stack creation) against a different organization's stack that Shipit also serves. Depending on which handler is reached, this can enqueue an unauthorized deploy path (`stack.sync_github` → `CacheDeploySpecJob` → eventual deploy trigger flows) for a stack the attacker does not control, which matches the High-impact category "escalation ... unauthorized deploy" bucket in a multi-tenant Shipit deployment (one Shipit instance backing multiple GitHub organizations, each with its own webhook secret in `Shipit.github`).

### Likelihood Explanation
Requires Shipit to be configured with more than one organization/app (each with its own `webhook_secret`) sharing one Shipit instance — a supported, documented configuration (`Shipit.github(organization:)` explicitly takes an organization parameter). Given that, any party holding a valid webhook secret for organization A (which is inherently less privileged/trusted than Shipit repo/GitHub App admins) can trivially forge the `repository.full_name` field, since nothing in `verify_signature` or the handlers cross-checks it against `repository.owner.login`.

### Recommendation
After signature verification, re-derive the repository/organization strictly from the same field(s) used to select the verifying secret, or verify that `repository.full_name.split('/').first == repository_owner` (case-insensitively) before dispatching to handlers, and reject (422) on mismatch.

### Proof of Concept
1. Shipit is configured with two GitHub App organizations, `org-a` and `org-b`, each with a distinct `webhook_secret`, both serving stacks on the same Shipit instance.
2. An attacker (or compromised low-trust integration) who legitimately knows `org-a`'s `webhook_secret` builds a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": {"login": "org-a"},
    "full_name": "org-b/target-repo"
  }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(org-a's webhook_secret, body)`.
4. POST to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "org-a")` (from `repository.owner.login`), verifies successfully with `org-a`'s secret.
6. `PushHandler#process` resolves `stacks` via `Handler#repository_name` = `"org-b/target-repo"`, matching and syncing a stack that belongs to `org-b`, which the attacker was never authorized to affect.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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
