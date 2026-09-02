## Analysis

The reported Basket bug is a **trust-binding break**: a value the contract *authenticates* (the caller's identity during `approveUnderlying`) is not the same value the contract *acts on* after re-entry (attacker rewrites `auction`/`factory` and its own token entry). The reachable analog in Shipit is a webhook handler that authenticates one field of a payload but writes state keyed on a completely different, unscoped field of the same attacker-supplied payload.

`WebhooksController#verify_signature` selects **which** GitHub App/webhook secret to validate against using the organization named inside the untrusted JSON body itself: [1](#0-0) [2](#0-1) 

Shipit explicitly supports multi-tenant configuration where **each GitHub organization has its own independent `webhook_secret`**, each of which a tenant admin creates and knows when setting up their own GitHub App: [3](#0-2) 

So the signature only proves "the sender knows *organization X's* secret" — it says nothing about the rest of the payload. `Shipit::Webhooks::Handlers::StatusHandler`, however, ignores the repository/organization entirely and updates commit status **purely by commit SHA, globally across every stack in the installation**: [4](#0-3) 

Note it does not call the base `Handler#stacks`/`repository_name` scoping that other handlers (`PushHandler`, `PullRequest` handlers) use: [5](#0-4) [6](#0-5) 

A status written this way flows straight into deployability and continuous-deployment logic: [7](#0-6) [8](#0-7) [9](#0-8) 

Test coverage confirms a `success` status transition alone triggers a new deploy under continuous deployment: [10](#0-9) 

### Title
Cross-organization commit-status forgery via SHA-only matching bypasses per-organization webhook authentication - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook by looking up the `webhook_secret` for the organization named in `payload['repository']['owner']['login']` (or `payload['organization']['login']`), a field fully controlled by whoever sends the request. In Shipit's supported multi-organization configuration, each org has its own independently-known `webhook_secret`. `StatusHandler#process`, however, does not scope its effect to that authenticated organization/repository at all — it matches `Commit.where(sha: params.sha)` across the entire database and writes a GitHub-reported CI status onto any commit sharing that SHA, on any stack, in any organization.

### Finding Description
The binding that should hold is:
`organization whose signature was verified == organization/repository whose state is mutated`

Before the attack: the equality holds implicitly because Shipit was designed for a single organization's webhook secret to authorize actions related to that organization's repositories.

After the introduction of multi-org support (`docs/setup.md`), the equality breaks: `verify_signature` derives the authenticating organization from the *payload*, and different organizations legitimately have *different, independently-obtainable* secrets [11](#0-10) . An operator or admin of Org A (who legitimately knows Org A's `webhook_secret`, exactly as a "publisher" legitimately creates a Basket proposal) can sign an arbitrary JSON body with Org A's secret while setting `repository.owner.login` to Org A (so `verify_signature` picks and matches Org A's secret) but setting the `status` event's `sha` field to the SHA of a commit tracked under a completely different stack/organization B, whose SHAs are typically public via GitHub itself.

`StatusHandler` performs no check that the commit's `stack.repository` belongs to the organization that was actually authenticated: [12](#0-11) 

This is analogous to the Basket bug: `approveUnderlying` trusts that "the caller who was allowed in" is the same actor whose state is subsequently modified, but the reentrant callback substitutes different values (`auction`, `factory`) before the outer call resumes. Here, the "value substituted" is the organization scope: verification is keyed on `repository.owner.login`, mutation is keyed on `sha` alone, with no re-check that the two agree.

### Impact Explanation
A forged `success` status can satisfy `Commit#deployable?` (`success? && !blocked?`) for a victim stack in a different organization [9](#0-8) , and `Status#schedule_continuous_delivery` will trigger an actual deploy if that stack has continuous deployment enabled [7](#0-6) , or unblock merge-queue processing via `ProcessMergeRequestsJob`. This is an unauthorized deploy triggered purely by cross-tenant webhook forgery, matching the Critical-tier "unauthorized deploy" impact category.

### Likelihood Explanation
Requires only that the Shipit deployment is configured for multiple GitHub organizations (a documented, supported configuration) and that the attacker administers/controls the GitHub App for at least one of those organizations (so they legitimately know that org's `webhook_secret`) — no privileged access to the victim organization, no `ApiClient` token, and no compromise of Shipit itself is needed. The victim commit's SHA is typically discoverable from the victim's public GitHub repository or Shipit UI.

### Recommendation
In `StatusHandler` (and any other handler that doesn't already scope via `Handler#stacks`), restrict the commit lookup to stacks belonging to the same repository/organization that was authenticated by `verify_signature`, e.g. join through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and verify its `owner` equals the organization used to select the webhook secret, rejecting the event otherwise.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` (attacker-controlled GitHub App/installation) and `orgB` (victim, tracked stack with `continuous_deployment: true` and a required CI `context`).
2. Attacker obtains the SHA of a pending commit on `orgB`'s tracked branch (public repo or Shipit UI).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
```json
{
  "sha": "<orgB-commit-sha>",
  "state": "success",
  "context": "<orgB-required-context>",
  "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/some-repo"}
}
```
4. `X-Hub-Signature` is computed with `orgA`'s own known `webhook_secret`.
5. `verify_signature` resolves `Shipit.github(organization: "orgA")` and validates successfully.
6. `StatusHandler#process` executes `Commit.where(sha: "<orgB-commit-sha>")`, finds the commit under `orgB`'s stack, and calls `create_status_from_github!`, marking it `success` regardless of `orgA`/`orgB` mismatch, potentially triggering a deploy on `orgB`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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
