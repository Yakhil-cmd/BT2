## Analysis

The relevant equality this engine must maintain is: **the GitHub organization whose credentials were used to authenticate a webhook == the organization/repository that webhook is allowed to mutate.** Across V2's bug is a payload field (`repaymentChainId`) that drives a consequential action without being covered by any validation tied to the entity that's supposed to control it. The structural analog here is `WebhooksController#repository_owner`, which is read from the **unverified** request body and used to pick *which* secret to check the signature against, while a **different, independently attacker-controlled** field of the same JSON body (`repository.full_name`) is later used by every `Handler` subclass to decide which `Stack`/`Repository` gets mutated.

### Root cause

`app/controllers/shipit/webhooks_controller.rb` selects the verification key from the payload itself before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` unconditionally accepts the request when no `webhook_secret` is configured for that organization — a state explicitly documented as supported ("Webhook secret (optional)"): [3](#0-2) [4](#0-3) 

Every webhook `Handler` then resolves its write target from a **separate** payload field, `repository.full_name`, which is never cross-checked against `repository_owner`: [5](#0-4) 

Concrete state-mutating consumers of that field include stack archival/unarchival driven entirely by attacker-suppliable `pull_request` and `action`/`labels` content: [6](#0-5) [7](#0-6) [8](#0-7) 

### Before/after the attack

- **Before**: `verify_signature` binds trust to `repository_owner` (the claimed org), and handlers act on `repository.full_name` (the claimed repo) — these two fields are supposed to be consistent, but nothing enforces it.
- **After**: an unauthenticated caller sends a `pull_request`/`push` webhook where `repository.owner.login`/`organization.login` names any org (in single-org deployments this argument is even ignored, per `lib/shipit.rb`'s `Shipit.github`), while `repository.full_name` names an unrelated victim repository/stack. If that org's `webhook_secret` is unset (a documented, supported configuration), `verify_webhook_signature` returns `true` for arbitrary bytes, and the request proceeds to archive/unarchive review stacks or trigger GitHub resyncs for a repository that has nothing to do with the credential that "authenticated" the request.

### Title
Webhook authenticity is bound to an unverified organization field while writes are keyed off a different, uncorrelated repository field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` chooses which GitHub App/secret to validate a webhook against using `repository_owner`, a value read straight out of the unauthenticated JSON body. Every `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the `Repository`/`Stack` to mutate from a different field of that same unauthenticated body, `repository.full_name` (`Handler#repository_name`). Because `verify_webhook_signature` returns `true` unconditionally whenever the resolved organization has no `webhook_secret` configured (a state the setup docs describe as an accepted, optional configuration), an attacker only needs the "authenticating" org field to resolve to an org with no secret configured (or, in single-app deployments, any value at all, since the org argument is not used to pick a different secret) in order to have full, unauthenticated control over the completely independent `repository.full_name` field that actually selects which stack is written to.

### Finding Description
`verify_signature` performs `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, where `repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')` — both attacker-supplied, unauthenticated values [9](#0-8) . `GithubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank [3](#0-2) , and the setup guide documents the secret as optional [4](#0-3) .

Once verification passes (or is bypassed), `Handler#stacks`/`#repository_name` resolves the mutation target purely from `payload.dig('repository','full_name')` [5](#0-4) , with no cross-check that this repository belongs to the organization that was used to select/pass the signature check. Downstream handlers use this to perform real writes: `PullRequest::ClosedHandler#process` calls `review_stack.archive!` [10](#0-9) , `Labeled/UnlabeledHandler` archive or unarchive review stacks based on attacker-controlled `pull_request.labels` [7](#0-6) , and `PushHandler#process` triggers a GitHub resync job for any matching stack [11](#0-10) . None of these consult `repository_owner`, so the field that gated authentication and the field that gates the write are unrelated.

### Impact Explanation
This breaks the equality `organization that authenticated == repository that is written`, one of the specifically in-scope trust bindings. Concretely, it allows unauthenticated cross-repository writes: an attacker can archive/unarchive review-stack deployments, or force resynchronization/deploy-pipeline state changes, for a `Stack` belonging to a repository/org that never authorized the request — satisfying the "cross-repository writes" Critical-impact criterion.

### Likelihood Explanation
Exploitability depends on deployment configuration: it is guaranteed whenever any configured GitHub organization has an unset `webhook_secret` (an explicitly documented, supported option), or in the common single-app configuration where `Shipit.github(organization:)` does not vary the secret by the claimed organization at all. No credentials, session, or API token are required — only a POST to the public `/webhooks` endpoint with a crafted `X-Github-Event` header and JSON body.

### Recommendation
Bind signature verification to the same repository identity the handlers act on: derive both the signing-secret lookup and the write target from a single, consistently-scoped field (e.g. always use `repository.full_name`'s owner, never fall back independently), and reject requests where `repository.owner.login`/`organization.login` does not match the owner embedded in `repository.full_name`. Additionally, treat an unset `webhook_secret` as "reject all webhooks for this org" rather than "accept any signature," or require a `webhook_secret` to be mandatory.

### Proof of Concept
1. Configure (or observe) a Shipit organization/app entry with no `webhook_secret` set (supported per `docs/setup.md`).
2. POST to `/webhooks` with `X-Github-Event: pull_request` and no valid `X-Hub-Signature`, body:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": { "id": 1, "number": 1, "url": "...", "title": "x", "state": "closed",
                     "additions": 1, "deletions": 1, "merged": true,
                     "head": {"sha": "abc", "ref": "feature"},
                     "user": {"login": "attacker"}, "assignees": [], "labels": [] },
  "repository": { "full_name": "victim-org/victim-repo",
                   "owner": { "login": "org-with-no-secret" } },
  "sender": { "login": "attacker" }
}
```
3. `verify_signature` resolves `repository_owner` to `"org-with-no-secret"`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the missing/invalid signature.
4. `Webhooks.for_event('pull_request')` dispatches to `PullRequest::ClosedHandler`, which resolves `repository` from `repository.full_name = "victim-org/victim-repo"` — an org completely unrelated to the one that "authenticated" the request — and calls `review_stack.archive!`, mutating a stack the attacker never had credentials for.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L28-30)
```markdown
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-93)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

          def pull_request_state
            pull_request.state
          end

          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
