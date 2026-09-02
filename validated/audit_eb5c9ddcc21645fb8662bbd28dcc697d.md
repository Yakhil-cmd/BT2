I now have enough to substantiate the finding. Note that the important caveat is the `StatusHandler` finding `Commit.where(sha: params.sha)` — this is scoped by SHA globally, not by resolved repository, meaning statuses aren't even cross-checked to belong to the right stack. This confirms the identity/binding break spans across handlers.

### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login`, not to the `repository.full_name` the handlers actually act on, allowing cross-repository forged GitHub events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an incoming webhook against using `repository_owner`, itself read from the untrusted JSON payload. Once the signature check passes, the entire raw payload is dispatched to handlers that resolve the target `Stack`/`Repository`/`Commit` from a *different* field of the same payload (`repository.full_name`, or in `StatusHandler`, `sha` alone) without ever re-checking that this target actually belongs to the organization whose secret was used to authenticate the request.

### Finding Description
`verify_signature` computes:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This binds the HMAC check to whatever organization the attacker names in `repository.owner.login`. The handlers, however, use an entirely different field — `repository.full_name` — to decide which `Repository`/`Stack` gets mutated:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`StatusHandler` is even looser — it resolves target commits purely by SHA, with no repository scoping at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`GitHubApp#verify_webhook_signature` also short-circuits to `true` whenever the resolved organization has no `webhook_secret` configured:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

`webhook_secret` is explicitly documented/scaffolded as an optional, commonly-nil value (`webhook_secret: # nil`) in both the single-org and multi-org example configs, and Shipit officially supports multiple, independently-configured GitHub organizations sharing one deployment. [5](#0-4) [6](#0-5) 

The binding that should hold is: **`organization authenticated by the signature == organization of the repository being written`**. Before the fix (i.e., as currently implemented), the engine only verifies **`organization named in repository.owner.login == secret used`**, and separately, handlers write to **whatever repository `repository.full_name` (or bare `sha`) names** — these two are never compared. Any attacker who can produce (or avoid needing) a valid signature for *any one* configured organization can freely set `repository.full_name` to reference a completely different, unrelated tracked repository/stack, and that stack will process the forged event as if GitHub itself sent it — mirroring the reported bug class where a mapping (`isOwner`) is checked/updated for one identity but never re-validated against the actual set of addresses/objects being acted upon.

### Impact Explanation
An attacker who obtains a valid signature for one configured organization (most simply, any organization whose `webhook_secret` is left blank — an explicitly documented, valid configuration state) can forge:
- `push` events causing `GithubSyncJob` to run against an arbitrary tracked stack [7](#0-6) 
- `status` events injecting fake CI success/failure statuses on any commit by SHA, which can enable `stack.schedule_merges` and unblock continuous-deployment gating, i.e. an **unauthorized deploy** [8](#0-7) [9](#0-8) 
- `pull_request` events that archive/unarchive/create review stacks for repositories the attacker does not control [10](#0-9) 

This crosses a real trust boundary (unauthenticated write into another organization's deployment pipeline / spoofed CI-driven deploy), matching the "unauthorized deploy" / "cross-repository writes" High/Critical impact bucket.

### Likelihood Explanation
Exploitability depends on the operator's multi-org configuration: it is trivial (no secret knowledge needed at all) if any configured organization has a blank `webhook_secret` — which is the value shown in the shipped example configs — and otherwise requires knowledge of just one organization's webhook secret to pivot writes into any other organization's stacks. Given Shipit explicitly supports and documents multi-tenant, multi-org deployments, this is a realistic misconfiguration-adjacent but code-level gap, not a hypothetical one.

### Recommendation
In `Shipit::Webhooks::Handlers::Handler` (and `StatusHandler` specifically), cross-check that the repository/stack being mutated actually belongs to the same organization that was used to select/verify the webhook signature — i.e., pass the verified `repository_owner` down into handler dispatch and reject/ignore any payload whose `repository.full_name` owner segment (or, for `StatusHandler`, the resolved commit's stack's repository owner) does not match. Additionally, consider disallowing/requiring non-blank `webhook_secret` per organization at boot time, since `return true unless webhook_secret` unconditionally disables authentication for that organization.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgTrusted` (has stacks worth attacking) and `OrgAttacker` (has `webhook_secret: nil`, per the documented default).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha of a commit on a stack under OrgTrusted with pending CI>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgAttacker/anything" }
}
```
3. `repository_owner` resolves to `OrgAttacker`; `Shipit.github(organization: 'OrgAttacker').verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank, regardless of `X-Hub-Signature`.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a fabricated `success` status on `OrgTrusted`'s commit, which can unblock `ci.require` gating and trigger `stack.schedule_merges` / continuous deployment — all without ever presenting a valid signature for `OrgTrusted`. [1](#0-0) [11](#0-10)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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

**File:** config/secrets.development.example.yml (L1-16)
```yaml
host: 'localhost:3000'
redis_url: 'redis://127.0.0.1:6379/0'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app
# Can be obtained there: https://github.com/settings/apps
# Set the "Authorization callback URL" as `<host>/github/auth/github/callback`

github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/status.rb (L36-44)
```ruby
    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
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
