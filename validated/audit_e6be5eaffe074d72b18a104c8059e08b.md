### Title
Webhook signature verified against a different organization than the repository the payload acts on, allowing cross-organization stack writes - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
Shipit supports multi-organization GitHub App configuration, where each configured organization has its own `webhook_secret` [1](#0-0) . Webhook signature verification is keyed off `repository.owner.login` (or `organization.login`) taken from the incoming JSON payload [2](#0-1) [3](#0-2) , but the handler that actually locates and mutates the `Stack`/`Repository` uses a completely separate field from the same attacker-controlled payload: `repository.full_name` [4](#0-3) . These two fields are never cross-checked against each other, so the organization whose secret authenticated the request is not bound to the repository the handler writes to.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp`/secret to validate the HMAC against using:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

This is passed into `Shipit.github(organization: repository_owner)`, which looks up a per-organization config (and therefore a per-organization `webhook_secret`) from `secrets.github` [1](#0-0) . Signature verification only proves that the HMAC in `X-Hub-Signature` matches this organization's secret and the raw body [5](#0-4) ; it does not constrain any other field inside that body.

Once the request passes verification, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the parsed JSON to handlers [6](#0-5) . Every handler resolves which `Repository`/`Stack` to act on via:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`Repository.from_github_repo_name` splits `full_name` on `/` and does a plain `find_by(owner:, name:)` lookup with no relation to `repository.owner.login` [7](#0-6) . Handlers such as `PushHandler`, `CheckSuiteHandler`, and the `PullRequest::*` handlers (`OpenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `AssignedHandler`, `EditedHandler`) all resolve their target `Repository`/`Stack` the same way, from `repository.full_name` in the JSON body [8](#0-7) [9](#0-8) .

The exploitable binding break is: **the organization whose secret authenticated the request (`repository.owner.login` / `organization.login`) is never equated with the organization whose repository is written to (`repository.full_name`)**. An attacker who is a legitimate, unprivileged owner/admin of a GitHub organization `A` that (a) has installed the Shipit GitHub App and (b) is configured in Shipit's `secrets.github` with its own `webhook_secret`, can POST directly to the public `/webhooks` endpoint with:
```json
{
  "repository": { "owner": { "login": "A" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
signed with organization `A`'s own `webhook_secret` (which the attacker legitimately possesses because they administer their own org/app installation). `verify_signature` computes `repository_owner == "A"`, fetches `A`'s `GitHubApp`, and the HMAC validates successfully since the attacker controls that secret. The dispatched handler, however, resolves the target repository purely from `full_name`, i.e. `victim-org/victim-repo`, entirely disconnected from the authenticated organization `A`.

This mirrors the analog described by the report's binding class: "an organization that authenticated versus the repository that is written" — exactly the mismatch present here, since Shipit checks org `A`'s signature but writes to `victim-org`'s stack.

### Impact Explanation
Depending on the handler triggered, this allows cross-organization writes without any credential belonging to the victim organization:
- `PushHandler` can force `stack.sync_github(expected_head_sha:)` on the victim's tracked branch with an attacker-chosen SHA [10](#0-9) , potentially causing Shipit to fetch/deploy an attacker-influenced commit reference on the victim's stack.
- `PullRequest::LabeledHandler`/`UnlabeledHandler` can archive/unarchive victim review stacks [11](#0-10) .
- `PullRequest::OpenedHandler`/`ReopenedHandler` can provision or unarchive victim review stacks [12](#0-11) .

This is a cross-repository/cross-organization write triggered by an attacker who only controls their own organization's webhook secret — matching the "cross-repository writes" / "unauthorized deploy" Critical/High impact bar.

### Likelihood Explanation
Requires the attacker to legitimately administer at least one GitHub organization that is itself configured/onboarded into the same multi-tenant Shipit instance (a realistic scenario for shared/hosted Shipit deployments serving multiple orgs), and knowledge of the victim's `owner/name` full_name (which is often public information, e.g., visible in the Shipit UI or GitHub itself). No access to the victim's secret, session, or GitHub credentials is required — only the attacker's own organization's `webhook_secret`, which they legitimately possess. This is plausible but conditioned on multi-organization deployment; single-organization deployments (`github_default_organization` nil) are not affected the same way since there is only one secret in that mode [13](#0-12) .

### Recommendation
In `Handler#repository_name` (and everywhere `Repository.from_github_repo_name` is invoked from webhook payloads), assert that the `owner` segment of `repository.full_name` equals the `repository.owner.login` (or `organization.login`) that was used to select the signing organization in `verify_signature`, rejecting the webhook if they diverge. Alternatively, pass the authenticated organization identity down into the handler pipeline and scope `Repository.from_github_repo_name` lookups to that organization instead of trusting the unauthenticated `full_name` field independently.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `attacker-org` (with `webhook_secret: S_A`) and `victim-org` (with its own stack/repo tracked in Shipit).
2. As the (unprivileged, non-Shipit) admin of `attacker-org`'s GitHub App/webhook config, compute `X-Hub-Signature: sha1=HMAC(S_A, body)` for the following body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `POST /webhooks` with header `X-Github-Event: push` and the signature above.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the signature validates (attacker controls `S_A`) — `app/controllers/shipit/webhooks_controller.rb:24-49`.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` from the same JSON body, entirely independent of the organization used for authentication — `app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56` — and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack.

### Citations

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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
