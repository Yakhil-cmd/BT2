### Title
Webhook organization used for signature verification is not bound to the repository the payload actually targets, enabling cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) to validate a webhook against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). The actual event handlers, however, resolve the `Stack`/`Repository` to act on using a completely different field, `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb`). These two fields are never checked for consistency, so the "organization whose secret authenticated the request" and "the repository whose Stack gets written to" are two independently attacker-controlled values inside the same unsigned-until-verified JSON body.

### Finding Description
`Shipit.github(organization: repository_owner)` is only organization-aware when the engine is configured with **multiple** GitHub Apps (the documented "Using Multiple GitHub Applications" setup, `docs/setup.md`). In that mode, each organization has its own, independently configured `webhook_secret`, which is explicitly documented as **optional** ("Webhook secret (optional)", `docs/setup.md`): [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when no secret is configured for that organization: [3](#0-2) 

Meanwhile, every handler ignores `repository.owner.login` entirely and derives the target `Stack`/`Repository` purely from `repository.full_name`: [4](#0-3) [5](#0-4) 

Equality that should hold but does not:
`organization_that_authenticated (repository.owner.login, used by verify_signature)` == `organization_owning_repository.full_name (used by all Handlers to select Stacks)`

Because these two fields live in the same unauthenticated JSON blob and are read independently, an attacker who knows that any one onboarded organization in a multi-app Shipit deployment has no `webhook_secret` configured (a supported, documented, non-default-but-legal state) can send `POST /webhooks` with:
- `X-Github-Event`: `push`, `pull_request`, `status`, or `check_suite`
- `repository.owner.login` = the org with no secret (or `organization.login` if no `repository` sub-object is present for that event type) → `verify_webhook_signature` returns `true` unconditionally, no signature required.
- `repository.full_name` = `"<TargetOrg>/<target-repo>"`, a completely different, secured organization that has real Stacks configured.

`verify_signature` passes (secret-less org matched), and the handler subsequently resolves and acts on Stacks belonging to `TargetOrg`, which the attacker never authenticated against.

### Impact Explanation
This breaks a trust boundary equivalent to "an organization that authenticated versus the repository that is written" explicitly called out as an in-scope analog class. Concretely reachable actions include:
- `PushHandler#process` calling `stack.sync_github` on `TargetOrg`'s stacks, driving GitHub sync/CI-status ingestion outside `TargetOrg`'s control (`app/models/shipit/webhooks/handlers/push_handler.rb`).
- `StatusHandler`/`CheckSuiteHandler` injecting forged commit statuses/check runs, which feed directly into `MergeRequest#all_status_checks_passed?`/`any_status_checks_failed?` (`app/models/shipit/merge_request.rb`) — these gate the merge queue's automatic `merge!` and continuous-deployment triggers, so forged statuses on `TargetOrg`'s commits can unblock unauthorized automatic merges/deploys.
- PullRequest handlers archiving/unarchiving review stacks for `TargetOrg`'s repositories.

### Likelihood Explanation
Requires: (1) a Shipit instance running the documented multi-organization GitHub App configuration, and (2) at least one onboarded organization configured without a `webhook_secret` (explicitly optional per `docs/setup.md`). No credential, token, or session of any kind is required from the attacker — the request is fully anonymous. Likelihood is Low-to-Medium and entirely dependent on this specific, but supported and plausible, operator configuration.

### Recommendation
Bind the two identities together: derive the organization used for `verify_webhook_signature` from the same field the handlers use to resolve the target repository/stack (`repository.full_name`'s owner segment), and reject the webhook if `repository.owner.login`/`organization.login` do not match the owner embedded in `repository.full_name`. Additionally, consider making `webhook_secret` mandatory for every organization in multi-app configurations, since an absent secret degrades verification to an unauthenticated bypass for that org.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `SecretlessOrg` (no `webhook_secret`) and `TargetOrg` (has stacks, has a secret).
2. Send:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<a real commit sha in TargetOrg/target-repo>",
  "repository": {
    "owner": { "login": "SecretlessOrg" },
    "full_name": "TargetOrg/target-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "SecretlessOrg")`; `verify_webhook_signature` returns `true` immediately since `webhook_secret` is blank — no `X-Hub-Signature` needed.
4. `PushHandler` resolves `Repository.from_github_repo_name("TargetOrg/target-repo")` and calls `stack.sync_github`, acting on `TargetOrg`'s stack despite the request never having been authenticated for `TargetOrg`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
