### Title
Webhook signature verification checks the payload's `repository.owner.login` while `StatusHandler`/other handlers write to a repository/commit resolved from unrelated payload fields, letting any onboarded organization forge CI statuses (and Push syncs) for repositories that belong to a different organization - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App configured for `repository_owner`, a value pulled from `params.dig('repository','owner','login')` (or `organization.login`) [1](#0-0) [2](#0-1) . The organization that is *authenticated* by that HMAC check is never re-checked against the organization/repository that the handler actually *writes to*. `StatusHandler` in particular resolves its target purely by commit sha, with no repository scoping at all: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . Other handlers (Push, PullRequest) instead resolve the target repository from `payload.dig('repository','full_name')` via `Handler#repository_name`/`#stacks` [4](#0-3) , a field that is never cross-checked against the `repository.owner.login` used for signature verification.

### Finding Description
The trust binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login) == organization/repository actually mutated by the handler`.

This breaks down for two reasons:

1. **`verify_signature` and the handler read different sub-fields of the same attacker-controlled JSON body.** `repository_owner` comes from `repository.owner.login` [2](#0-1) , while `PushHandler`/`PullRequest` handlers resolve the affected `Stack`/`Repository` from `repository.full_name` [4](#0-3) [5](#0-4) . Nothing enforces that `full_name`'s owner segment equals `owner.login`; both are attacker-supplied strings in the same forged payload.
2. **`StatusHandler` performs no repository scoping whatsoever.** It looks up `Commit.where(sha: params.sha)` globally and calls `create_status_from_github!` on whatever commit matches, regardless of which organization/repository owns that commit [3](#0-2) .

Because Shipit supports a multi-organization configuration where each organization has its own GitHub App and `webhook_secret` (`Shipit.github(organization: repository_owner)`) [1](#0-0) [6](#0-5) , an actor who legitimately administers **their own** GitHub App/organization (`OrgA`) knows `OrgA`'s `webhook_secret` and can compute a valid `X-Hub-Signature` over an arbitrary raw payload. That actor has no Shipit session, no `ApiClient` token, and no access to `OrgB`'s (the victim organization's) credentials, yet can craft a `status` event payload where `repository.owner.login = "OrgA"` (satisfies `verify_signature`) but `sha` is a real commit sha belonging to a stack/repository tracked under `OrgB`. `StatusHandler` will happily attach an attacker-chosen CI state/description/target_url to that commit.

### Impact Explanation
Shipit's deploy pipeline gates deploy safety checks on GitHub commit statuses (e.g. required-status checks surfaced to `Stack`). Forging a `success` status for a commit belonging to a different, unrelated organization's repository lets an attacker who controls only their own onboarded org's webhook secret manipulate CI signal on a victim repository they have no access to, which can be leveraged to bypass status gating and enable an unauthorized deploy of that victim stack — a cross-repository write with no credential boundary crossed for the victim organization. This maps to the "Critical - cross-repository writes, or an unauthorized deploy" category. `PushHandler`'s reliance on the unvalidated `repository.full_name` similarly permits triggering `stack.sync_github` for a stack whose owning organization differs from the one whose secret produced the signature.

### Likelihood Explanation
Exploitability only requires the attacker to be the legitimate owner/administrator of any one organization configured on a shared multi-org Shipit instance (a realistic deployment pattern documented in `config/secrets.development.example.yml`) [6](#0-5) . No Shipit account, API token, or victim-org secret is needed — only the ability to send an HTTP POST with a self-computed HMAC using a secret the attacker legitimately possesses for their own org, and knowledge of a target commit sha (obtainable from GitHub's public API/commit history).

### Recommendation
- In `StatusHandler`, scope the `Commit` lookup to repositories owned by the verified `repository_owner`/organization (e.g., join through `Stack`/`Repository` and filter by the authenticated organization) instead of a bare `Commit.where(sha:)`.
- In `Handler#stacks`/`#repository_name`, and in `WebhooksController#verify_signature`, derive the authenticated organization and the acted-upon repository from the same canonical field (e.g., always split `repository.full_name`), and explicitly assert that the organization used to select the webhook secret matches the organization prefix of the repository being written to before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (as documented in `config/secrets.development.example.yml`) [6](#0-5) . Attacker administers `OrgA` and knows `OrgA`'s `webhook_secret`; `OrgB` hosts the victim stack/commit.
2. Attacker crafts a `status` event JSON body:
   ```json
   {
     "sha": "<victim commit sha in OrgB/repo>",
     "state": "success",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/whatever" }
   }
   ```
3. Attacker computes `X-Hub-Signature` using `OrgA`'s `webhook_secret` per `Hook::DeliverySigner`/`verify_webhook_signature` logic [7](#0-6) , and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` as `"OrgA"` [2](#0-1) , calls `Shipit.github(organization: "OrgA").verify_webhook_signature(...)`, which succeeds since the signature was computed with `OrgA`'s real secret [1](#0-0) .
5. `StatusHandler#process` then finds the `OrgB` commit purely by `sha` and applies the forged `success` status to it [3](#0-2) , despite the signature only having proven the request came from `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
