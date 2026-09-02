### Title
Webhook `status` event handler writes CI status onto commits of any stack regardless of which organization's signature authenticated the request - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using the `repository.owner.login` value taken from the *same untrusted payload* being verified, and Shipit explicitly supports configuring one independent GitHub App (and `webhook_secret`) per organization for multi-tenant installations. Once the signature check passes, `Shipit::Webhooks::Handlers::StatusHandler#process` looks up the target `Commit` **globally by `sha`, with no repository/organization scoping at all**, unlike every other handler (`CheckSuiteHandler`, `PushHandler`, `PullRequest::*`) which resolve `Repository.from_github_repo_name(...)` before touching any data. This breaks the binding "organization that authenticated == repository that is written": a payload validly signed with Organization B's webhook secret can write an attacker-chosen CI `state`/`context`/`target_url` onto a commit belonging to Organization A's stack, as long as the `sha` in the forged payload matches a commit that exists anywhere in the installation.

### Finding Description
- `WebhooksController#verify_signature` picks the GitHub App/secret via `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository', 'owner', 'login')` — a field taken from the raw JSON body itself: [1](#0-0) [2](#0-1) 
- Shipit's own documentation and secrets schema explicitly support one GitHub App (and one independent `webhook_secret`) per organization, for exactly the "multiple orgs on one Shipit instance" deployment model: [3](#0-2) [4](#0-3) 
- All the other webhook handlers correctly re-derive the target stack/repository from the signed payload before acting, via `Handler#stacks`, which looks up `Repository.from_github_repo_name(repository_name)`: [5](#0-4) [6](#0-5) 
- `StatusHandler`, registered for the `status` GitHub event, does **not** do this. It parses only `sha`/`state`/`context`/etc. and finds commits with `Commit.where(sha: params.sha)` — a query unscoped by repository, stack, or organization — then writes the attacker-supplied status onto every matching commit: [7](#0-6) [8](#0-7) 
- `sha` is only guaranteed unique per stack, not globally, confirming this is a real cross-stack/cross-organization write path by design of the schema: [9](#0-8) 
- `Commit#create_status_from_github!` persists the forged status directly and can flip commit state, triggering downstream effects such as continuous deployment: [10](#0-9) [11](#0-10) 

The binding broken, stated as an equality that should hold but does not:
`organization that signed/authenticated the webhook == organization/repository whose commit status gets written`.
Before the attack: only Organization B's own installed GitHub App can produce a validly-signed webhook for Organization B, and only Organization A's commits should be affected by Organization A's CI. After: `StatusHandler` allows Organization B's validly-signed `status` webhook to overwrite CI state on Organization A's commit as long as the `sha` matches.

### Impact Explanation
A forged `status` event with `state: success` (and a `context` matching a stack's `required_statuses`/`blocking_statuses`) can:
- Make an undeployed commit `deployable?` (`success? && !blocked?`) on a victim stack it doesn't belong to. [12](#0-11) 
- Trigger `ContinuousDeliveryJob` for stacks with continuous deployment enabled, causing an **unauthorized deploy**. [11](#0-10) 
- Satisfy merge-queue CI requirements (`reject_unless_mergeable!`), enabling an **unauthorized merge**. [13](#0-12) 

This matches the Critical bucket: "an unauthorized deploy, rollback, or merge."

### Likelihood Explanation
This requires the attacker to control (or have admin rights over) a GitHub organization/App that is legitimately configured as one tenant of a multi-organization Shipit instance — a scenario the engine's own documentation explicitly recommends and supports (`docs/setup.md`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`). Such an attacker holds no privilege whatsoever over the victim organization's repository, Shipit account, or `Shipit.github_teams`, yet needs only a target commit `sha` that already exists in the victim stack (commonly public — e.g. visible via the Shipit UI/API, PR pages, or GitHub itself for public repos) and a `context` value that can be guessed or observed from the victim stack's `shipit.yml`/UI. No GitHub App private key, `webhook_secret` of the target org, or any Shipit session/API token is needed.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the repository resolved from the payload (as `Handler#stacks` already does for every other handler), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the global `Commit.where(sha: params.sha)`. More generally, `WebhooksController#verify_signature` should not trust the payload-derived `repository_owner`/`repository.full_name` for anything beyond secret selection unless every handler subsequently re-validates that the same repository is the one being mutated.

### Proof of Concept
1. Deploy Shipit configured with two independent GitHub Apps/organizations, `OrgA` and `OrgB`, as documented in `docs/setup.md` ("Using Multiple Github Applications").
2. Attacker controls `OrgB`'s GitHub App and knows its own `webhook_secret` (legitimately, as the org's owner).
3. Attacker identifies a commit `sha` belonging to `OrgA`'s protected/production stack (e.g. a public commit sha visible on `OrgA`'s GitHub repo or Shipit's own commit history page) and a required CI `context` for that stack (from `shipit.yml`/stack settings page).
4. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, `repository.owner.login: "OrgB"`, and a valid `X-Hub-Signature` computed with `OrgB`'s `webhook_secret`, but body:
```json
{
  "sha": "<OrgA-target-commit-sha>",
  "state": "success",
  "context": "<OrgA-required-context>",
  "repository": {"owner": {"login": "OrgB"}}
}
```
5. `WebhooksController#verify_signature` validates successfully against `OrgB`'s secret (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, which matches `OrgA`'s commit and creates a `success` status on it, unaffected by the fact the signature only proved `OrgB` authenticity (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`).
7. If `OrgA`'s stack has continuous deployment enabled or the commit becomes the head of a pending merge request, this triggers an unauthorized deploy/merge on `OrgA`'s stack.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
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

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```

**File:** test/models/merge_request_test.rb (L186-203)
```ruby
    test "#reject_unless_mergeable! rejects the PR if it has a failing CI status" do
      @pr.head.statuses.create!(stack: @pr.stack, state: 'failure', context: 'ci/circle')

      refute_predicate @pr, :all_status_checks_passed?
      assert_predicate @pr, :any_status_checks_failed?
      assert_equal true, @pr.reject_unless_mergeable!
      assert_predicate @pr, :rejected?
      assert_equal 'ci_failing', @pr.rejection_reason
    end

    test "#reject_unless_mergeable! does not reject the PR if it has a pending CI status" do
      @pr.head.statuses.create!(stack: @pr.stack, state: 'pending', context: 'ci/circle')

      refute_predicate @pr, :all_status_checks_passed?
      refute_predicate @pr, :any_status_checks_failed?
      assert_equal false, @pr.reject_unless_mergeable!
      refute_predicate @pr, :rejected?
    end
```
