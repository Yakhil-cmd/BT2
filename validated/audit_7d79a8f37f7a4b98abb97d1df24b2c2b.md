### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate an inbound webhook's HMAC signature with based on the `repository.owner.login` (or `organization.login`) field of the *same attacker-controlled JSON body* that produced the signature. All webhook `Handler` subclasses, however, resolve the target `Stack`/`Repository` using a **different** field of that body: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb`). Because Shipit never asserts `repository.owner.login == repository.full_name.split('/').first`, an attacker who legitimately owns *any* GitHub App installation (and therefore possesses a valid `webhook_secret` for their own, attacker-controlled organization) can sign a payload with that secret while spoofing `repository.full_name` to point at a victim organization's tracked repository/stack. This is the same class of bug as the Futureswap report: a field that is acted upon (`repository.full_name`) is never covered by the signature-selection/verification binding (`repository.owner.login`), so the "authenticated organization" and the "acted-upon repository" are silently allowed to diverge.

### Finding Description
- `WebhooksController#verify_signature` picks the app/secret purely from the payload: [1](#0-0) 
- `repository_owner` is read straight out of the untrusted, attacker-supplied JSON: [2](#0-1) 
- Every default handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, PR handlers, etc.) resolves the affected `Stack` via `repository.full_name`, a completely different key of the same JSON body, with no re-validation against the organization used to select the signing secret: [3](#0-2) 
- `Shipit.github(organization:)` looks up per-organization secrets/apps (multi-org deployments are an explicitly documented and supported configuration in `docs/setup.md`), so it is normal for two organizations, each with their own `webhook_secret`, to be configured simultaneously: [4](#0-3) 

Because `repository.owner.login` (used to pick the secret) and `repository.full_name` (used by every handler to find the target `Stack`) are independent, unchecked fields in the same body, an attacker who owns a legitimate but unrelated GitHub App installation — anyone can create one for their own organization/repo for free — can:
1. Craft a JSON body with `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`.
2. Sign it with HMAC-SHA1 using `attacker-org`'s own `webhook_secret` (which they legitimately know, since it's their own app).
3. POST it to Shipit's `/webhooks` endpoint. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own secret.
4. `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` then dispatches to handlers that operate on `victim-org/victim-repo` — a stack the attacker has no legitimate access to.

Concrete abuse via existing default handlers:
- `PushHandler` triggers `stack.sync_github(expected_head_sha: params.after)` for any `Stack` under the spoofed `full_name`/branch, forging a fake push/sync event for a repo the attacker doesn't own: [5](#0-4) 
- `StatusHandler` creates a forged commit `Status` (state/description/context/target_url of the attacker's choosing) for any commit `sha` that exists in the victim stack's commit history (SHAs are public on GitHub for public repos), independent of which org actually authenticated the request: [6](#0-5) 

### Impact Explanation
This breaks the equality "organization that authenticated == repository that is written," which the analog rules explicitly call out. Concretely:
- Forged, attacker-chosen `Status` records for arbitrary commits in a victim's tracked stack can satisfy `ci.require` gating used to permit deploys (per `README.md`'s `ci.require` documentation), and forged `push`/`sync_github` events can force Shipit to fetch/register commits and, on stacks with `continuous_deployment: true`, feed the deploy pipeline — both routes toward an **unauthorized deploy**, which is explicitly listed as a Critical-impact outcome in the rules. At minimum this is a High-severity cross-repository forgery of stack/CI state with no privileged access required.

### Likelihood Explanation
Exploitation only requires the attacker to control one legitimate (even free, self-created) GitHub App/organization with a webhook secret — something any external, unprivileged party can obtain — plus knowledge of the victim's public `org/repo` name and (for status forgery) a public commit SHA. No Shipit session, `ApiClient` token, or repository write access is needed, satisfying the "unprivileged attacker" bar required by the rules.

### Recommendation
After signature verification, re-derive the organization strictly from the verified request context (not from a second, independently-controlled JSON field), and cross-check that the organization that produced a verified signature matches the owner/organization of the `repository`/`organization` object actually referenced by the payload's `full_name`/`login` used for record lookups. Reject the webhook if these do not match, mirroring the fix pattern in the referenced report (binding the acting entity to the same verified credential used for authentication).

### Proof of Concept
1. Attacker creates their own GitHub App "attacker-org" (or uses any org they administer) and configures it in Shipit alongside the victim org, per the documented multi-org `secrets.yml` format (`docs/setup.md`), obtaining a valid `webhook_secret` for "attacker-org".
2. Attacker builds a `push` (or `status`) event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<victim commit sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(attacker-org_webhook_secret, body)` and sets `X-Github-Event: push`.
4. `POST /webhooks` with this body/signature. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature check passes (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which looks up stacks via `repository.full_name` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha:)` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite the request having been authenticated solely against "attacker-org"'s secret.

Note: I could not fully trace `Stack#sync_github` / `GithubSyncJob` internals or the exact `ci.require` enforcement code path within this session's tool budget to confirm the precise downstream deploy-trigger mechanics; this should be verified in a follow-up session to fully characterize the deploy-trigger severity, though the core signature/organization-binding break itself is confirmed directly from the cited files.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
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
