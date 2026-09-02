## Analysis

The bug class in the report is a check performed on one value while a different, unguarded value is actually used for the operation (uint underflow bypasses a bound because the check target and the acted-upon value diverge). The strongest analog in this engine is a mismatch between the organization whose webhook secret is used to **authenticate** an inbound GitHub webhook and the repository that is actually **written to** by the handler that processes that webhook's payload.

`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify the signature using `repository_owner`, which is derived from `params.dig('repository', 'owner', 'login')` (or `organization.login` as a fallback) — i.e., the *owner* sub-object of the payload: [1](#0-0) [2](#0-1) 

Once the signature is accepted, the raw parsed payload is dispatched unchanged to event handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [3](#0-2) 

Every handler, however, resolves *which repository/stack to act on* from a **different** field of the same payload: `payload.dig('repository', 'full_name')`, not `repository.owner.login`: [4](#0-3) 

`Repository.from_github_repo_name` then splits that `full_name` on `/` and looks up the repo purely from that string, with no cross-check against `repository.owner.login` or the org used for signature verification: [5](#0-4) 

`PushHandler` then directly triggers a sync against whatever stacks match that repository, using attacker-controlled `after` (the desired head SHA): [6](#0-5) 

Multiple GitHub Apps/organizations can be configured (`Shipit.github(organization:)` looks up per-org config, this is the reason `repository_owner` exists at all — to select the correct app/secret to verify against). Because the signature-verification org lookup and the repository-resolution field are independent strings within the same untrusted JSON body, nothing in the code enforces that `repository.full_name`'s owner segment matches `repository.owner.login` (or `organization.login`) that was used to select the verifying secret.

**The broken binding, stated as an equality that the code fails to enforce:**
`organization used to select the webhook secret for signature verification` (`repository_owner` → `Shipit.github(organization: repository_owner)`) **≠** `repository actually written to by the handler` (`payload.dig('repository', 'full_name')` → `Repository.from_github_repo_name`).

### Before/after the attacker's payload
- Before: An attacker with legitimate GitHub App installation/webhook-secret access for their own organization ("attacker-org") can only produce webhook deliveries whose HMAC is valid for "attacker-org"'s secret.
- After: The attacker crafts a webhook body where `repository.owner.login` (or `organization.login`) is `"attacker-org"` (so `verify_signature` authenticates against attacker-org's secret and passes) but `repository.full_name` is `"victim-org/victim-repo"`. `verify_signature` passes because it only checked the owner field's secret; `PushHandler`/other handlers then resolve and mutate stacks belonging to `victim-org/victim-repo` — a cross-repository, cross-organization write (triggering `GithubSyncJob`, creating commit statuses, closing/labeling PRs, archiving/unarchiving review stacks, etc.) that the attacker was never authorized to touch.

This is exactly the "organization authenticated versus the repository written" trust-boundary break the rules call out, and it requires no Shipit session, API token, or GitHub App private key — only the ability to deliver a webhook whose signature is valid for *some* configured organization (which is achievable by any user who can register/own a webhook against an org configured in this Shipit instance, e.g. a smaller/less-trusted org sharing the same Shipit deployment as a more sensitive org).

I could not fully verify from the indexed code whether `Shipit.github(organization:)` enforces case-sensitivity/normalization consistently between the two lookups (`repository_owner` vs. `Repository#owner` in `from_github_repo_name`), nor whether the host application's `config/initializers` (out of scope per the rules) restricts webhook secrets to a single organization in typical deployments — if only one organization/webhook secret is ever configured, this analog collapses to a same-org case and would not cross a trust boundary. This is a real limitation on confidence: the vulnerability is only exploitable in multi-organization Shipit deployments (which the engine explicitly supports via `Shipit.github(organization:)` and the `GithubOrganizationUnknown` handling), and I cannot confirm from the available files whether the intended/typical deployment pattern is multi-org.

### Title
Webhook signature is verified against the payload's `repository.owner`/`organization` while handlers act on the independent `repository.full_name` field, allowing cross-organization/repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the per-organization webhook secret using `repository_owner` (`repository.owner.login` or `organization.login`), but the actual repository/stack acted upon by every `Shipit::Webhooks::Handlers::Handler` subclass is resolved from the unrelated `repository.full_name` field via `Repository.from_github_repo_name`. Nothing binds these two fields together.

### Finding Description
`verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that organization's `webhook_secret`. If valid, the entire raw payload is forwarded unmodified to handlers (`app/controllers/shipit/webhooks_controller.rb:10-15`). Handlers derive the repository to mutate purely from `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), which is passed straight into `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) — a naive string split with no equality check against `repository.owner.login`/`organization.login`. Since a webhook payload is just attacker-supplied JSON once a valid signature for *any* configured organization is produced, an attacker who owns/controls a webhook secret for one onboarded organization can set `repository.owner.login` to their own org (satisfying signature verification) while setting `repository.full_name` to a completely different, victim organization's repository (satisfying the handler's repository resolution).

### Impact Explanation
This crosses the "unauthorized deploy/rollback or cross-repository writes" bar: a forged `push` webhook drives `PushHandler#process`, which calls `stack.sync_github(expected_head_sha: params.after)` on stacks it does not own (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), effectively letting the attacker dictate the expected head SHA synced for a stack under a different organization/repository than the one whose secret authenticated the request. Other handlers (`status`, `check_suite`, PR handlers) similarly resolve their target purely off attacker-controlled `full_name`/`repository` fields, enabling forged commit statuses, PR label-driven stack archiving/unarchiving, and review-stack provisioning against arbitrary repositories in the same Shipit deployment.

### Likelihood Explanation
Exploitability depends entirely on the deployment having more than one organization/webhook-secret configured via `Shipit.github(organization:)` (the engine explicitly supports and expects this, given `repository_owner`'s existence and `GithubOrganizationUnknown` handling). In such multi-org deployments, any actor able to register a webhook delivery signed with one org's secret (e.g., an org admin of a less-trusted org sharing the instance) can trivially forge the `repository.full_name` field to target a different org's repository — no Shipit session or GitHub App private key is required.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization used to select/verify the webhook secret matches the owner segment of `repository.full_name` used for repository resolution — reject the request (422) if `repository.owner.login`/`organization.login` does not case-insensitively equal the owner portion of `repository.full_name`.

### Proof of Concept
1. Shipit instance configured with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App/webhook secret via `Shipit.github(organization:)`.
2. Attacker registers/controls a webhook delivery endpoint test for `attacker-org` and thus knows/can compute a valid `X-Hub-Signature` HMAC using `attacker-org`'s `webhook_secret`.
3. Attacker POSTs to `/webhooks` with `X-Github-Event: push`, a valid signature computed with `attacker-org`'s secret, and a body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. `verify_signature` computes `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s app, and the signature validates successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `PushHandler` resolves `stacks` from `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, `app/models/shipit/repository.rb:53-56`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `victim-org`'s stacks — a write the attacker was never authorized to trigger.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```
