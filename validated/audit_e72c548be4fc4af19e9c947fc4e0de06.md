### Title
Webhook Organization Used for Signature Verification Is Decoupled From the Repository the Event Actually Acts On - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on a value read directly out of the still-unverified JSON body (`repository.owner.login`, falling back to `organization.login`). The event handlers, however, resolve the *actual* repository/stack the event operates on from a completely independent field of that same unverified body (`repository.full_name`). Nothing ties these two values together. If any organization configured in a multi-org Shipit install has no `webhook_secret` set (a state explicitly supported and documented as "optional"), `GitHubApp#verify_webhook_signature` short-circuits to `true` for any payload claiming that organization, letting an unauthenticated attacker submit an arbitrary payload whose `repository.full_name` points at a *different*, "protected" organization's stack.

### Finding Description
- `WebhooksController#verify_signature` picks the GitHub App/org to authenticate against using attacker-controlled JSON, before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` trivially returns `true` when the resolved organization has no `webhook_secret` configured, which is an explicitly supported, documented configuration ("Webhook secret (optional)"): [3](#0-2) [4](#0-3) 

- Once verification "passes," the actual event dispatch and repository/stack resolution use a *different* field of the same unverified body — `repository.full_name` — with no cross-check against the organization that was actually authenticated: [5](#0-4) 

- This lets an attacker craft: `repository.owner.login = "org-with-no-secret"` (or `organization.login`, satisfying `repository_owner`) to pass verification trivially, while setting `repository.full_name = "victim-org/victim-repo"` to control which stack the handler operates on. Handlers such as `PushHandler` and `StatusHandler` act directly on that stack/commit: [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization authenticated by verify_signature == organization that owns the repository the dispatched handler mutates`
but in fact the second half is taken from an independent, never-reverified JSON field, so the equality is not enforced anywhere in the engine.

### Impact Explanation
`StatusHandler#process` calls `commit.create_status_from_github!(params)` for any commit matching an attacker-supplied `sha`, letting the attacker forge a passing CI status ("success") on any commit in the target stack's repository. Shipit's blocking-status / merge-queue safety feature relies on these statuses to gate deploys and merges; forging a passing status on an otherwise-failing or malicious commit can result in that commit being deployed or merged — an **unauthorized deploy/merge**, which is explicitly a Critical-severity outcome per the assessment criteria. `PushHandler#process` similarly lets the attacker trigger a `sync_github` with an attacker-chosen `expected_head_sha` against an arbitrary stack, independent of the org whose secret (or lack thereof) satisfied verification.

### Likelihood Explanation
Exploitation requires no GitHub credentials, no `webhook_secret`, no `ApiClient` token, and no privileged Shipit account — only that the Shipit deployment (a documented multi-organization setup, see `test/dummy/config/secrets_double_github_app.yml`) has at least one configured organization with `webhook_secret` left blank, which the setup guide lists as optional and thus a normal, supported configuration rather than a misuse of the engine. The `/webhooks` endpoint is unauthenticated by design (it's meant to receive GitHub's calls), so any external party can POST directly to it.

### Recommendation
Do not let the organization used for authentication be derived independently from the field the handlers use to select the target repository/stack. After `verify_signature` succeeds, re-derive `repository_owner`/organization strictly from `repository.full_name`'s owner segment (the same field `Handler#repository_name` uses) and require it to match the organization whose secret validated the signature. Additionally, consider requiring `webhook_secret` to be present for all configured organizations (or refusing events for organizations lacking one) rather than treating an absent secret as an implicit bypass.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, e.g. `OrgA` (no `webhook_secret` set) and `OrgB` (has `webhook_secret` set, hosting the real target repo/stack), similar to `test/dummy/config/secrets_double_github_app.yml`.
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` resolves `repository_owner` = `OrgA`, calls `Shipit.github(organization: "OrgA")`, whose `verify_webhook_signature` returns `true` unconditionally because `OrgA` has no `webhook_secret`.
4. `StatusHandler` then processes the event against `OrgB/victim-repo` (via `repository.full_name`), creating a forged "success" status for the given commit — independent of `OrgB`'s actual, unrelated `webhook_secret`. [8](#0-7) [3](#0-2) [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-63)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-42)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class Handler
        class << self
          attr_reader :param_parser

          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
