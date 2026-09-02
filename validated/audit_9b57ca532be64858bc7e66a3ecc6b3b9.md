Confirmed: `Repository.from_github_repo_name` looks up purely by the `owner`/`name` parsed from `payload.dig('repository', 'full_name')` [1](#0-0) , with no cross-check against `repository.owner.login`, which is the field `WebhooksController#verify_signature` uses to select which org's `webhook_secret` validates the HMAC [2](#0-1) . `ReopenedHandler#repository` and `#stack` derive scope entirely from `params.repository.full_name`, independent of `repository_owner` [3](#0-2) .

### Title
Signature-org / target-repo binding is unchecked, letting attacker-org-signed webhooks unarchive/mutate a victim org's stack - (File: app/controllers/shipit/webhooks_controller.rb / app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository.owner.login` from the JSON body, while `ReopenedHandler` (and the other PR handlers) resolve the target `Repository`/`Stack` using `repository.full_name`, also from the attacker-supplied body. Since Shipit never checks that these two fields are consistent, an attacker who owns/administers any organization onboarded to the same Shipit instance (and therefore knows that org's `webhook_secret`, which they set on their own GitHub webhook) can sign a payload where `repository.owner.login` = their own org but `repository.full_name` = `"victim-org/victim-repo"`.

### Finding Description
The broken binding: the code implicitly assumes `payload.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first`, but nothing enforces this equality.

- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [2](#0-1) . This only proves the request was signed with the secret configured for whatever org name is placed in `repository.owner.login`.
- `Handler#stacks`/`ReopenedHandler#repository` resolve scope via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, which parses `owner, name = full_name.split('/')` and does a direct `find_by(owner:, name:)` lookup [1](#0-0) [4](#0-3) .
- Exploit: attacker administers `attacker-org/some-repo` (legitimately onboarded to this Shipit instance, so they know `attacker-org`'s `webhook_secret` because they configured it on their own GitHub webhook). They POST to `/webhooks` with header `X-Github-Event: pull_request` and a JSON body where `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, with `action: "reopened"` and a valid `pull_request` sub-object, signed with `attacker-org`'s secret.
- `verify_signature` succeeds because it only checks the signature against `attacker-org`'s secret, which matches. `drop_unhandled_event`/`ExplicitParameters` schema only validate structure/presence of fields, not cross-field consistency between `owner.login` and `full_name`. `ReopenedHandler#process` then calls `stack.unarchive!` on a `ReviewStack` scoped to `victim-org/victim-repo`'s repository, resurrecting/mutating a PR-driven stack belonging to the victim organization, and — depending on `provisioning_behavior` — can also auto-provision/queue tasks (`assert_pending_provision` in the existing test shows `unarchive!`/provisioning enqueues deploy-relevant task state) [5](#0-4) .
- None of the existing guards catch this: `verify_signature` never compares `repository.owner.login` to `repository.full_name`'s owner segment; `ExplicitParameters` only requires `repository.full_name` to be a `String` [6](#0-5) ; `Repository.from_github_repo_name` does no ownership/tenant check tying it back to the verified signer.

### Impact Explanation
This is a payload for one repository/organization (attacker's, whose secret validated the signature) mutating another organization's stack (`victim-org/victim-repo`'s review stack), matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attacker can repeatedly unarchive closed PR-review stacks, and depending on the victim repository's `provisioning_behavior` (`allow_all`, etc.), can also drive `ReviewStackAdapter` to enqueue provisioning/deploy tasks against the victim's stack — none of which the attacker owns or has any permission over. This is repeatable against any repository/org onboarded to the same Shipit instance simply by varying `repository.full_name` in the JSON body, as long as the attacker retains their own org's `webhook_secret`. The same root-cause divergence (`owner.login` vs `full_name`) affects all other PR handlers using `Handler#stacks`/`from_github_repo_name` (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, etc.), widening blast radius across the whole webhook surface, not just `ReopenedHandler`.

### Likelihood Explanation
Preconditions: the attacker must be an administrator of at least one organization/repository already onboarded to the target Shipit instance with review stacks enabled (so they legitimately know that org's `webhook_secret`, since GitHub webhook secrets are chosen/known by whoever configures the webhook). No Shipit session, API token, or GitHub App private key is needed. Given that, the attack is a single crafted HTTP POST to the public `/webhooks` endpoint with no live GitHub interaction required, fully repeatable, and requires no privileged Shipit role — satisfying the described attacker capability of "verified under their own org's webhook_secret."

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), validate that `payload.dig('repository','owner','login')` matches the owner segment of `payload.dig('repository','full_name')` before dispatching to any handler; reject the webhook (422) on mismatch. Alternatively, derive `repository_owner` solely from `full_name`'s owner segment so the same field is used consistently for both signature-org selection and repository/stack resolution.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Set up two repositories/stacks: `shopify/shipit-engine` (attacker-controlled org "attacker-org" is stubbed as valid signer) and a victim repository `victim-org/victim-repo` with an archived `ReviewStack` tied to PR number N.
2. Build a `pull_request` `reopened` payload JSON with `repository.owner.login = "attacker-org"`, `repository.full_name = "victim-org/victim-repo"`, `pull_request.number = N`, and required nested fields per `ExplicitParameters` schema.
3. Stub `Shipit.github(organization: "attacker-org").verify_webhook_signature` to return `true` (simulating attacker knowing their own org's secret), and assert `Shipit.github(organization: "victim-org")` is never consulted for verification.
4. POST to `/webhooks` with `X-Github-Event: pull_request` and this body.
5. Assert equality-before: `victim_stack.archived? == true` before the request.
6. Assert equality-after: `victim_stack.reload.archived? == false` (or `Shipit::PullRequest` row for `victim-org/victim-repo` was mutated) after the request — proving mutation occurred despite the signature only being verified for `attacker-org`.
7. Contrast with expected behavior: assert the test fails (i.e., the vulnerability is confirmed) unless a fix enforces `repository.owner.login == full_name.split('/').first` before dispatch, in which case the response should be `422` and `victim_stack.reload.archived?` should remain `true`.

### Citations

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb (L242-247)
```ruby
          def assert_pending_provision(stack)
            stack.reload

            assert(stack.awaiting_provision?, "Stack #{stack.environment} should be in the provisioning queue")
            assert(stack.deprovisioned?, "Stack #{stack.environment} should be pending provision")
          end
```
