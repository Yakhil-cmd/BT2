### Title
Webhook signature is verified against the org derived from `repository.owner.login`, but handlers act on the org/repo derived from `repository.full_name` in the same unverified payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `repository_owner`, a value read straight out of the *unverified* JSON body. All downstream event handlers, however, resolve the repository/stack to act on using a *different* field of that same unverified body: `repository.full_name` (`Handler#repository_name`). Because the field used to select the verification key is never bound to the field used to select the write target, the two can be made to disagree.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and uses it to fetch the `GitHubApp` (and its `webhook_secret`) that verifies `X-Hub-Signature`:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 

Once verification passes, the raw JSON (unchanged) is dispatched to handlers such as `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and the `PullRequest::*` handlers, all of which resolve the target repository/stack using a *different* JSON key:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`Shipit.github(organization: config)` is looked up per-organization in multi-org deployments, each with its own `webhook_secret`:
```yaml
github:
  somegithuborg:
    webhook_secret: ...
  someothergithuborg:
    webhook_secret: ...
``` [4](#0-3) 

Because `repository.owner.login` and `repository.full_name` are two independent JSON fields inside the same HMAC-signed body, and the HMAC only proves "this body was signed by *some* webhook secret possessed by whichever party crafted `repository.owner.login`" - not "the events inside this body pertain to the repo named in `repository.owner.login`" - an attacker who legitimately controls (or has otherwise obtained delivery credentials for) `orgA`'s webhook secret can sign a payload whose `repository.owner.login` = `orgA` (so verification passes using orgA's secret) while `repository.full_name` = `orgB/some-repo` (a completely different, unrelated organization/repository also hosted by the same Shipit instance). The signature check has no knowledge of, and does not cover, the mismatch between these two fields.

The binding that should hold is:
```
verified_organization(secret used to accept signature) == organization_whose_repository_is_acted_upon(handler logic)
```
This equality is never enforced; `repository_owner` (verification input) and `repository_name`/`Repository.from_github_repo_name` (action input) are read from independent, attacker-controlled fields of the same unverified payload.

### Impact Explanation
This is a cross-repository/cross-organization write primitive: any handler action reachable via the webhook endpoint is executed for `orgB`'s stacks even though the signing secret belongs to `orgA`. Concretely:
- `PushHandler` enqueues `GithubSyncJob` for stacks under the forged `repository.full_name`, causing Shipit to fetch/append commits and recompute deploy specs for a stack the attacker does not own [5](#0-4) .
- `StatusHandler` writes fabricated CI/commit statuses (`create_status_from_github!`) onto commits shared by sha across stacks, which is one of the gating conditions Shipit uses to decide whether a commit is deployable [6](#0-5) .
- `PullRequest::*` handlers (opened/closed/reopened/labeled/unlabeled) create, archive, or unarchive review stacks belonging to `orgB`'s repository based purely on the forged `repository.full_name` [7](#0-6) .

This matches the "an organization that authenticated versus the repository that is written" trust binding break, and results in unauthorized cross-organization state mutation on stacks/review-stacks the attacker does not control.

### Likelihood Explanation
Exploitation requires the attacker to already possess (or be able to produce) a valid `X-Hub-Signature` for *some* organization configured on the instance - i.e., they must be a legitimate GitHub App installation/webhook sender for at least one org hosted by the Shipit instance (this is a realistic scenario for any multi-tenant/shared Shipit deployment serving several orgs, as explicitly documented in `config/secrets.development.shopify.yml`). Given that, forging the `repository.owner.login` vs `repository.full_name` mismatch requires no further privilege - it is a pure JSON payload manipulation, no Shipit session, API token, or GitHub write access to the victim org needed.

### Recommendation
After verifying the signature, re-derive `repository_owner`/organization strictly from the same field the handlers use to select the target repository (`repository.full_name`'s owner segment, or equivalently normalize on one canonical field), and reject the request (422) if `repository.owner.login` does not match the owner segment of `repository.full_name`. Alternatively, bind the verified organization to the request environment and have `Handler#stacks`/`Repository.from_github_repo_name` refuse to resolve a repository owned by a different organization than the one whose secret verified the signature.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with distinct `webhook_secret` values, both hosting stacks (as in `config/secrets.development.shopify.yml`).
2. As the legitimate webhook sender for `orgA` (or anyone in possession of `orgA`'s `webhook_secret`), craft a `push` event body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Sign the raw body with `orgA`'s `webhook_secret` to produce `X-Hub-Signature`, and POST to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, fetches `orgA`'s `GitHubApp`, and the signature validates successfully [2](#0-1) .
5. `PushHandler` resolves `repository_name = "orgB/victim-repo"` and enqueues `GithubSyncJob`/mutates stacks belonging to `orgB`, an organization the attacker never authenticated against [3](#0-2) [8](#0-7) .

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
