### Title
Cross-tenant Status forgery: `StatusHandler#process` matches commits by SHA only, ignoring the payload's repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no scoping to the repository named in the webhook payload, while `WebhooksController#verify_signature` only proves that the caller knows the webhook secret for the organization *named in the attacker-controlled payload*, not that they are authorized for the specific commit's stack. Because Shipit supports independent per-organization `webhook_secret`s [1](#0-0) , an attacker who legitimately owns/administers one registered organization's Shipit webhook can forge a `status` event whose `repository.owner.login` matches their own org (so signature verification passes) but whose `sha` matches a commit belonging to a completely different tenant's stack, causing that commit's CI status to be created/mutated cross-tenant.

### Finding Description
The claimed binding is: `verify_signature(payload) == true` should imply `payload.repository.full_name == commit.stack.repository.full_name` for every commit mutated by the handler. Tracing the code shows this is false.

`WebhooksController#verify_signature` derives the org purely from attacker-supplied JSON and picks the GitHub app config for that org: [2](#0-1) [3](#0-2) 

`Shipit.github` resolves a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per organization when Shipit is configured for multiple GitHub orgs, which is a documented, normal configuration [4](#0-3) [1](#0-0) . `verify_webhook_signature` only checks the HMAC against that org's own secret [5](#0-4) . So a signature that verifies proves only "the sender knows secret for org X", where X is attacker-controlled in the payload — it says nothing about which commit/stack is being targeted.

`StatusHandler` then ignores the payload's `repository` field entirely and mutates by SHA alone: [6](#0-5) 

Contrast this with the base `Handler` class, which does provide a repository-scoping helper (`stacks`, scoped via `Repository.from_github_repo_name(repository_name)`) that other handlers such as `OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler` correctly use to scope their side effects to the repository named in the payload [7](#0-6) [8](#0-7) . `StatusHandler` never calls `stacks` or filters by `repository_name`; the `sha` column is only unique per `stack_id` (see the `index_commits_on_stack_id_and_sha` migration), so the same SHA value can legitimately exist as separate `Commit` rows belonging to unrelated stacks/tenants, and `Commit.where(sha: params.sha)` will match all of them regardless of which org's secret signed the request.

`Commit#create_status_from_github!` and `Status.replicate_from_github!` perform no additional authorization; they just persist state/description/target_url for whatever commit was matched [9](#0-8) [10](#0-9) . There is no `Shipit.github_teams`, `current_user`, or `require_permission!` invocation anywhere in this call path, and none is needed for legitimate operation since the webhook path is meant to be authenticated purely by the per-org signature — but that signature check is not bound to the resource being mutated.

**Attacker's exact request:** POST `/webhooks` with header `X-Github-Event: status`, `X-Hub-Signature: sha1=<hmac(attacker_org_webhook_secret, body)>`, and JSON body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/attacker-repo"},
  "sha": "<victim commit sha>",
  "state": "success",
  "description": "forged",
  "context": "ci/attacker",
  "created_at": "2026-01-01T00:00:00Z"
}
```
`verify_signature` succeeds because `repository_owner` resolves to `attacker-org`, for which the attacker legitimately knows the webhook secret. `StatusHandler.call` then finds and mutates `Commit` rows in the victim's stack matching that `sha`, with zero cross-checking against `attacker-org`.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler` only validates types/presence of `sha`/`state`, not repository ownership; there is no `force_github_authentication`, `User#authorized?`, or `require_permission!` in the webhook path at all (webhooks are intentionally unauthenticated-by-session and rely solely on signature verification, which as shown is not resource-scoped).

### Impact Explanation
An attacker who administers any one Shipit-registered GitHub organization/repository (a normal, low-privilege action) can forge CI status updates (`success`/`failure`/`pending`/`error`, arbitrary `description`/`target_url`/`context`) for commits belonging to any other tenant's stack in the same Shipit instance, provided they know or can guess the target commit's SHA. `Commit#deployable?` depends on status success (`success? && !blocked?`) [11](#0-10) , so forged `success` statuses can make an otherwise CI-failing/pending commit appear deployable, and forged statuses also trigger `deployable_status`/`commit_status` webhooks and enqueue `ProcessMergeRequestsJob`, both of which can influence merge-queue and deploy behavior for the victim tenant. This is a cross-tenant write with no ownership check — matching "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy" in the Critical impact category.

### Likelihood Explanation
Preconditions are low-cost and match the stated attacker capability set: the attacker only needs to be the legitimate administrator of one repository/org that is already registered in Shipit with its own webhook (a normal onboarding action, and multi-org GitHub-app configuration is an explicitly documented and supported Shipit deployment pattern). The only additional requirement is knowledge of the victim commit's 40-character SHA, which is often public (public repos, PR pages, CI logs, git history) or guessable in small numeric ranges for internal setups. No GitHub, Shipit, or third-party secret beyond the attacker's own webhook secret is required. The attack is trivially repeatable against any known SHA in any stack on the same Shipit instance.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository declared (and cryptographically bound) in the payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before matching by `sha`, mirroring the pattern already used in `OpenedHandler`/`ClosedHandler`/`LabeledHandler`. Additionally consider requiring `repository.full_name` in the `StatusHandler` params schema so it cannot be omitted, and validate that the resolved commit's `stack.repository` matches that name.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "a status payload naming attacker's own repo still mutates a victim stack's commit matched only by sha" do
          victim_commit = shipit_commits(:first) # belongs to a different stack/repo than "attacker-org/attacker-repo"

          payload = {
            "repository" => { "owner" => { "login" => "attacker-org" }, "full_name" => "attacker-org/attacker-repo" },
            "sha" => victim_commit.sha,
            "state" => "success",
            "description" => "forged by attacker",
            "context" => "ci/attacker",
            "created_at" => Time.now.utc.iso8601
          }

          # binding under test: verify_signature only proves knowledge of attacker-org's secret,
          # never that attacker-org == victim_commit.stack.repository.full_name
          assert_not_equal payload["repository"]["full_name"], victim_commit.stack.repository.full_name

          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(payload)
          end

          assert_equal 'success', victim_commit.reload.state
          assert_equal 'forged by attacker', victim_commit.statuses.last.description
          # Shipit.github_teams / any permission check is never consulted in this path
        end
      end
    end
  end
end
```
This demonstrates the two sides of the binding diverge: signature validity is tied to `attacker-org`'s secret while the mutated resource belongs to an unrelated stack/repository, with no `Shipit.github_teams`/`require_permission!` check anywhere on the path.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
