## Analysis

I found a concrete analog: the webhook signature verification selects the HMAC secret using an **untrusted field from the same unverified payload** whose content is later trusted to resolve the target repository/stack — the same class of bug as the report (a value is used before/without being validated against the boundary it's supposed to enforce). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC against by reading `repository_owner`, which is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — a field taken directly from the attacker-supplied, not-yet-authenticated request body. Downstream, `Handler#stacks` resolves the target repository from a *different* field of the same untrusted payload: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together or re-validates that the repository whose secret validated the signature is the same repository the handler subsequently acts on.

Because Shipit is designed to be multi-tenant (`config/secrets.development.shopify.yml` shows multiple orgs, each with its own `webhook_secret`), any actor who legitimately knows one configured organization's `webhook_secret` (e.g., an admin of one onboarded, low-trust org, or someone who compromised only one org's GitHub App secret) can craft a payload where:
- `repository.owner.login` == the organization whose secret they know (so `verify_signature` passes, since the signature is computed over the full raw body using that org's secret and the attacker controls the whole body).
- `repository.full_name` == a **different**, more sensitive repository/stack tracked by the same Shipit instance. [5](#0-4) 

Since `PushHandler#process` (and other handlers) resolve `stacks` purely via `Repository.from_github_repo_name(repository_name)` with `repository_name` from `full_name`, a forged-but-correctly-signed-for-a-different-repo webhook can trigger `stack.sync_github(expected_head_sha: params.after)` against a repository/stack the attacker's secret was never scoped to. [6](#0-5) 

This breaks the binding: **organization whose secret authenticated the request == repository that gets written/acted upon**. This matches the report's underlying bug class — a field consumed by application logic is not covered by the same validation/trust check that was performed on a *different* field of the same untrusted structure (in Firedancer: `sz` validated only for an upper bound while used unchecked for a lower-bound-sensitive subtraction; here: `repository.owner.login` is checked against a secret, but `repository.full_name`, used for the actual write, is never cross-checked against that same secret's scope).

### Limits of what I could verify
I could not verify from the indexed code whether `sync_github`/`GithubSyncJob` perform any additional revalidation against the real GitHub API (e.g., re-fetching the commit via an authenticated per-repo GitHub App client, which would reject a SHA that doesn't exist on that repo) before making further changes — this could reduce the practical impact to triggering a spurious/failing sync job rather than a full cross-repository write. Given the "OUT OF SCOPE" rule prohibits treating third-party/host-mounting assumptions as sufficient, and I cannot confirm from `app/**`/`lib/shipit/**` alone that `sync_github` performs no independent authorization re-check that would neutralize this, I flag this as the strongest analog found but with residual uncertainty on final write impact. I would recommend a Devin session with the actual repository to trace `Stack#sync_github` and `GithubSyncJob` fully before treating this as a confirmed cross-repository write.

### Title
Webhook signature secret selection uses an unvalidated payload field disjoint from the repository field acted upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate a webhook using `repository.owner.login` (or `organization.login`) taken from the unauthenticated request body, but the webhook `Handler` base class resolves the actual repository/stack to act on using a separate field, `repository.full_name`, from that same unauthenticated body.

### Finding Description
Signature verification and repository resolution are decoupled: the secret is chosen by `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`), while the repository used for effectful action is resolved by `Handler#repository_name`/`#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) via `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`). No code cross-checks that the owner used to validate the signature is the same owner as the repository ultimately acted upon.

### Impact Explanation
A holder of any one configured organization's `webhook_secret` in a multi-org Shipit deployment can forge a signed webhook whose `repository.owner.login` matches their known org (making `verify_webhook_signature` pass) while `repository.full_name` targets a different tracked repository/stack, causing handlers such as `PushHandler` to invoke actions (e.g., `stack.sync_github`) against a stack outside the attacker's authorized scope — an unauthorized cross-repository action.

### Likelihood Explanation
Requires possession of a legitimate webhook secret for at least one organization configured in the multi-tenant `github:` secrets block; this is a lower bar than compromising the target repository/org's own secret, matching the report's theme of a privilege/trust binding being broken through a field never covered by the same check as a sibling field.

### Recommendation
After `verify_signature` succeeds, re-derive/validate that `repository.full_name`'s owner matches the `repository_owner` (or `organization.login`) that was actually used to select the verifying secret, and reject the webhook otherwise.

### Proof of Concept
1. Configure two orgs A and B in `github:` secrets (as in `config/secrets.development.shopify.yml`), with Shipit tracking a stack for `B/private-repo`.
2. As holder of org A's `webhook_secret`, craft a `push` payload: `{"repository": {"owner": {"login": "A"}, "full_name": "B/private-repo"}, "ref": "refs/heads/main", "after": "<attacker sha>"}`.
3. Sign the raw body with org A's secret and send it as `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "A")` and succeeds; `PushHandler` then resolves `Repository.from_github_repo_name("B/private-repo")` and enqueues `sync_github` for that stack.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
