### Title
Webhook signature is verified for the payload's claimed organization, but handlers act on an unverified `repository.full_name`/commit `sha` — allowing cross-repository status forgery and sync triggering - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against using a payload field (`repository.owner.login` or `organization.login`), but the webhook handlers that subsequently mutate state (`PushHandler`, `StatusHandler`) select the target repository/commit using a *different, unverified* payload field (`repository.full_name` or a bare `sha`). Nothing ties the two together, so a valid signature for organization A does not guarantee the acted-upon repository/commit actually belongs to organization A.

### Finding Description
`verify_signature` computes the organization used for signature verification from the payload itself: [1](#0-0) [2](#0-1) 

This binds the signature check to `repository_owner` (`repository.owner.login` / `organization.login`), i.e. verification proves "this payload's bytes are authentic for organization X's configured `webhook_secret`."

Once verification passes, the actual work is dispatched purely on the raw payload: [3](#0-2) 

Handlers determine which `Stack`/`Repository` to affect using `repository.full_name`, a completely separate field from the one used for signature verification, with no cross-check that `full_name`'s owner equals `repository_owner`: [4](#0-3) 

`PushHandler` uses this unscoped lookup to enqueue a GitHub sync for any matching stack: [5](#0-4) 

`StatusHandler` is worse: it doesn't even use `repository_name`/`Handler#stacks` — it looks up commits **globally by `sha` alone**, across every stack/repository in the Shipit instance, and writes a `Status` record from attacker-controlled fields: [6](#0-5) 

The equality the design implicitly assumes but never enforces is:
`organization authenticated by verify_signature (repository_owner) == organization that owns the repository/commit acted upon by the handler (repository.full_name / commit.sha owner)`

This equality is never checked, so it can be broken.

### Impact Explanation
Any party who legitimately controls (or is granted) a GitHub App installation/organization configured in this Shipit instance — i.e., they know a valid `webhook_secret` for *their own* organization — can sign a webhook payload with that secret while setting `repository.full_name` (push event) or `sha` (status event) to reference a repository/commit that belongs to a **different**, victim organization/stack that they do not control:
- Via `PushHandler`, they can trigger `GithubSyncJob`/`stack.sync_github` for a victim stack they have no access to.
- Via `StatusHandler`, they can forge arbitrary CI `Status` records (context, state, description, target_url) against *any* commit sha already in the datastore, regardless of which stack/repository it belongs to, since `Commit.where(sha: params.sha)` is not scoped to the verified organization or even the claimed `repository.full_name`.

Since deploy gating in this engine (`required_statuses`/`hidden_statuses`/`blocking_statuses`, delegated from `Stack` to `Commit`) relies on `Status` records populated exactly through this webhook path, forging a passing CI status on a victim's commit can make that commit `deployable?` and eligible for an unauthorized deploy — a cross-organization/cross-repository write that breaks the trust boundary between "who signed the webhook" and "whose data gets written."

### Likelihood Explanation
The prerequisite is possession of a valid `webhook_secret` for *any one* organization configured on the Shipit instance (which multi-tenant / multi-org Shipit deployments commonly have, e.g. via GitHub App installed on several orgs) — not a privileged Shipit account, `ApiClient` token, or GitHub access to the victim repository. This is a normal "unprivileged attacker relative to the victim repo" scenario matching the required threat model, since the only thing needed is an unrelated org's own already-known webhook secret.

### Recommendation
In `Handler#stacks` and `StatusHandler#process`, verify that the repository/commit being acted upon actually belongs to the same organization that was used to select the verification secret in `WebhooksController#verify_signature` (e.g., compare `repository.full_name`'s owner, or the commit's `stack.repository.owner`, against `repository_owner`) before performing any lookup/mutation. Pass the verified `repository_owner` into the handler and reject/ignore events where it doesn't match the repository/commit being referenced.

### Proof of Concept
1. Attacker's own GitHub org "attacker-org" is configured in this Shipit instance with `webhook_secret = S`.
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" },
  "sha": "<victim commit sha from another org's stack>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://example.com",
  "created_at": "2026-09-02T00:00:00Z"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)` using the known secret for `attacker-org`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) — which matches the victim's commit in an entirely unrelated stack — and creates a forged `success` status on it, with no check that the commit belongs to `attacker-org`.

Note: I could not fully trace `create_status_from_github!`/`Shipit.github` internals in this pass (they weren't fully retrieved), but the core root cause — verification keyed on `repository_owner` while handlers act on `repository.full_name`/`sha` with no cross-binding check — is confirmed directly in the cited files.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
