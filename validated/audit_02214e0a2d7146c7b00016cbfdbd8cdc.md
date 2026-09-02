Confirmed: `PushHandler#stacks` derives the target repository purely from `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb:33-38`), while `WebhooksController#verify_signature` selects the HMAC key to check based on a *different* traversal of the same JSON — `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`). These are two independent reads of the attacker-controlled payload, and only the second one is bound by the signature check; `repository.full_name` is never cross-checked against `repository.owner.login`/`organization.login`, nor against the key that validated the signature.

### Title
Webhook signature verification authenticates payload's `repository.owner.login`/`organization.login`, but handlers act on the unverified `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/`webhook_secret` to validate the HMAC using `repository.owner.login` (falling back to `organization.login`). Once the HMAC over the raw body checks out, the entire raw JSON is handed unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. `PushHandler` (and `Handler#stacks`/`#repository_name`) then resolve the target repository from a completely different field of the same payload: `repository.full_name`. Nothing enforces that `full_name` is consistent with `repository.owner.login`/`organization.login`.

### Finding Description
- Binding that should hold: `organization/owner whose secret authenticated the delivery == organization/repository whose stacks are mutated`.
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and uses it to fetch `Shipit.github(organization: repository_owner)`, whose `verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) HMACs the *entire raw body* against that org's configured `webhook_secret`.
- `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-34`) instead resolve the acted-upon `Repository` via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`.
- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) then iterates `stacks.not_archived.where(branch:)` and calls `stack.sync_github(expected_head_sha: params.after)` for every matching stack of whatever repository `full_name` names — with no re-check that this repository belongs to the organization that owns the webhook_secret which authenticated the request.
- A GitHub App owner who registers their **own** organization in Shipit's multi-org config (as shown supported in `config/secrets.development.shopify.yml`) legitimately knows their own `webhook_secret` (they choose it when creating the App) — this is not "stealing" a secret, it is the normal credential of a tenant the host application intentionally lets self-register. That tenant can craft a payload where `repository.owner.login`/`organization.login` point to their own org (satisfying the signature check with their own secret) while `repository.full_name` names a stack belonging to a completely different, victim organization also hosted on the same Shipit instance. Because `full_name` is never cross-validated against the authenticated owner, the push handler will call `sync_github`/queue `GithubSyncJob` against the victim's stacks.

### Impact Explanation
This breaks the equality "organization that authenticated the webhook == repository being written," letting one tenant on a shared Shipit instance trigger `GithubSyncJob`/`sync_github` against another tenant's stack using only their own legitimately-owned webhook credentials. This can force spurious syncs, and in principle interacts with the review-stack provisioning/pull_request pipeline for repositories the attacker does not own, i.e., unauthorized action taken against another org's stack/deploy state — matching the "unauthorized deploy" class of High-severity issues in scope, since sync jobs can drive deploy pipeline state (e.g., through continuous deployment) for a repository the attacker does not control.

### Likelihood Explanation
Requires the host application to configure more than one GitHub organization in `Shipit.github` (explicitly documented/supported multi-tenant configuration) and for the attacker to control one of those orgs' Apps (a normal, low-privilege situation for any onboarded tenant, not a "privileged account" within Shipit itself, and not requiring compromise of anyone else's secret). No session, ApiClient token, or repository write access to the victim repo is needed.

### Recommendation
In `WebhooksController`/`Handler`, derive the repository/organization used for processing (`repository.full_name`) from the *same* verified field used for signature selection, or explicitly assert `repository.full_name.split('/').first == repository_owner` (case-insensitively) before dispatching to handlers; reject the webhook otherwise.

### Proof of Concept
1. Configure Shipit with two orgs, `orga` and `orgb` (as `config/secrets.yml` supports per `config/secrets.development.shopify.yml`), where the attacker legitimately administers `orga`'s GitHub App (and thus knows `orga`'s `webhook_secret`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" },
  "organization": { "login": "orga" }
}
```
   signed with `orga`'s `webhook_secret` via `X-Hub-Signature: sha1=<hmac>`.
3. `verify_signature` resolves `repository_owner` to `"orga"` and validates successfully against `orga`'s secret [1](#0-0) .
4. `create` dispatches the same JSON to `PushHandler`, which resolves stacks via `repository.full_name == "orgb/victim-repo"` [2](#0-1)  and calls `sync_github` on `orgb`'s stacks [3](#0-2) , despite the request never being authenticated by `orgb`'s credentials.

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
