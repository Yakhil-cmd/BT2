### Title
Webhook signature is authenticated against `repository.owner.login`'s GitHub App while all event handlers act on `repository.full_name`, allowing a registered organization to forge events for a different repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')`, but every `Shipit::Webhooks::Handlers::Handler` subclass resolves the `Repository`/`Stack` that will actually be mutated using `payload.dig('repository', 'full_name')`. These are two different, independently attacker-controlled fields inside the same JSON body, and only one of them is used to pick the authenticating secret while the other decides which repository's state is written.

### Finding Description
`verify_signature` computes the GitHub App context from the payload's `repository.owner.login` (falling back to `organization.login`) and verifies the raw body against that organization's `webhook_secret`: [1](#0-0) [2](#0-1) 

`Shipit::Webhooks::Handlers::Handler` (the base class used by `PushHandler` and every `PullRequest::*Handler`) instead derives the target repository/stack strictly from `repository.full_name`: [3](#0-2) 

The same disjoint field usage repeats in every pull-request handler, e.g.: [4](#0-3) [5](#0-4) [6](#0-5) 
and in the push handler that triggers `sync_github`: [7](#0-6) 

Verification itself is a plain HMAC over the raw request body with a per-organization `webhook_secret`: [8](#0-7) 

Since Shipit supports multiple GitHub App/organization configurations (`Shipit.github(organization: ...)`, raising `GithubOrganizationUnknown` for unrecognized owners) and the HMAC only proves "this body was signed by *some* organization's secret," an attacker who legitimately controls one onboarded organization ("attacker-org", knows its `webhook_secret`) can craft a webhook payload where `repository.owner.login` = `"attacker-org"` (so `verify_signature` selects and successfully validates against attacker-org's own secret) while `repository.full_name` = `"victim-org/victim-repo"` (an unrelated repository already registered in Shipit). The signature check passes because the attacker knows the secret used to sign it, but the handler then acts on `victim-org/victim-repo`'s `Stack`/`Repository` records.

This breaks the trust binding: **organization that authenticated (via `repository.owner.login` and its secret) ≠ repository that is written (via `repository.full_name`)**.

### Impact Explanation
Depending on event type, this lets an attacker who onboarded any organization into a shared Shipit instance:
- Force `GithubSyncJob`/`sync_github` on a victim's stack via forged `push` events, using an attacker-chosen `after` SHA — a cross-repository write into state the attacker does not own [9](#0-8) .
- Archive/unarchive or otherwise mutate a victim repository's review stacks and pull request records via forged `pull_request` events resolved off `full_name` [10](#0-9) .

This is a cross-repository write performed without any credential or permission on the victim repository, matching the Critical impact bar ("cross-repository writes").

### Likelihood Explanation
Requires only that the attacker legitimately control (or be a member with webhook-configuration knowledge of) at least one organization/app already configured in `Shipit.github`, i.e., no privileged Shipit account or GitHub token is needed — just knowledge of their own org's `webhook_secret`, which any admin of an onboarded organization holds. No `ApiClient` token, session, or GitHub App private key of the victim is required.

### Recommendation
Verify that `repository.owner.login` (used to select the signing secret) matches the owner portion of `repository.full_name` (used to resolve the target `Repository`/`Stack`) before dispatching to any handler, or resolve the handler's target repository consistently from the same organization context that was used to authenticate the request.

### Proof of Concept
1. Attacker owns/administers organization `attacker-org`, which is a legitimately configured GitHub App organization in this Shipit instance (`Shipit.github(organization: 'attacker-org')` returns valid config with known `webhook_secret`).
2. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s `webhook_secret` over the raw body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` (from `repository_owner`) and successfully verifies the signature against attacker's own secret [1](#0-0) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `stack.sync_github(expected_head_sha: '<attacker-chosen-sha>')` on the victim's stack [9](#0-8) [3](#0-2) , mutating a repository the attacker never authenticated as owning.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
