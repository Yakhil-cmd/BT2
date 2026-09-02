### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the repository actually acted upon is taken from the unrelated `repository.full_name` field — allowing cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* organization's `webhook_secret` to validate a delivery against using `repository_owner`, a value read straight out of the untrusted JSON body. Every downstream handler, however, resolves the repository/stack to actually act on using a *different* field of the same untrusted body: `repository.full_name`. Nothing ties these two fields together, so a valid signature computed with one organization's secret can be replayed with a payload whose `full_name` points at a completely different organization's repository/stack.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it to pick the `GithubApp` (and its `webhook_secret`) to verify against: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` then simply HMACs the raw body with that one organization's secret: [3](#0-2) 

But every `Handler` subclass (used by `create` to dispatch the event) resolves the actual repository/stack to mutate from a *separate* field, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

This is used, for example, by `PushHandler` to queue a sync/deploy-triggering job for whatever stacks match that repository: [5](#0-4) 

and by the PR handlers to archive/unarchive review stacks, capture labels, etc., all keyed off `params.repository.full_name` via `Repository.from_github_repo_name`: [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` splits `owner/name` straight out of this field and looks the record up directly, without ever comparing it to `repository.owner.login`: [8](#0-7) 

**Binding broken:** `repository_owner` (the field the HMAC signature is verified against) ≠ `repository.full_name`'s owner (the field the write is performed against). The report's stop-loss bug is a "check function A is claimed but function B (or nothing) is actually invoked" data-validation flaw; the analog here is "the field authenticated is claimed to be the field acted upon, but they are actually two independent, attacker-controlled JSON keys."

### Impact Explanation
Each onboarded GitHub organization in a multi-tenant Shipit deployment has its own `webhook_secret`/`GithubApp` config (`Shipit.github(organization: repository_owner)`). Because signature verification only proves knowledge of the secret for the org named in `repository.owner.login`, but the mutation target is derived from the independent `repository.full_name` field in the same signed body, a party with legitimate webhook-secret knowledge for their own onboarded organization/repository can forge a payload with `repository.owner.login` set to their own org (satisfies signature check) and `repository.full_name` set to any other onboarded organization's `owner/repo` (the actual write target). This lets them enqueue `GithubSyncJob`s, archive/unarchive/provision review stacks, or otherwise trigger stack state changes belonging to a repository/organization they do not own — a cross-repository/cross-organization write.

### Likelihood Explanation
Exploitability requires only that the attacker be a legitimate GitHub webhook sender for *some* organization/repository already onboarded to the target Shipit instance (i.e., they know that org's `webhook_secret`, which is routine for any org admin who configured the Shipit webhook themselves). No Shipit session, API token, or GitHub App private key is required — only the ability to send an HTTP POST with a crafted JSON body and a correctly computed HMAC using their own org's secret.

### Recommendation
- Short term: after signature verification succeeds for `repository_owner`, assert that `repository.full_name`'s owner segment equals `repository_owner` before dispatching to any handler; reject the request otherwise.
- Long term: verify webhook signatures with a single canonical binding between "which secret authenticated this request" and "which resource the payload is permitted to reference," and add regression tests that a payload naming a different repository owner than the authenticating organization is rejected.

### Proof of Concept
1. Attacker controls organization `attacker-org`, which is a legitimate Shipit-integrated GitHub org with its own `webhook_secret` `S_attacker`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_attacker, raw_body)>` and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `S_attacker`, and the HMAC matches → request passes.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and queues `GithubSyncJob`/triggers a sync for the victim's stack, entirely outside the attacker's own organization boundary.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
