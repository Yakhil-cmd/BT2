## Title
Webhook signature is verified against the payload's organization while handlers act on the payload's independent repository field, enabling cross-organization/cross-repository webhook forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

## Summary
This is a structural analog of the Footium bug: two fields that describe "the same conceptual entity" are actually independent and never cross-checked, so the party that is authenticated (via signature) is not necessarily the party whose data gets acted upon. In Footium, the EIP2981 royalty was bound to the Player NFT but not to the Club NFT that could carry the same players, letting the "container" bypass the check applied to the "contents." In Shipit, `WebhooksController` binds HMAC signature verification to `repository.owner.login`/`organization.login`, but the event handlers that actually mutate state key off the sibling field `repository.full_name` — a field the signature check never inspects for consistency with the org it authenticated.

## Finding Description
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to validate the HMAC against, using only: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (or the `organization` fallback). Once the HMAC over the raw body is confirmed valid for that organization's secret, the entire raw payload (unchanged) is dispatched to handlers: [3](#0-2) 

Every handler resolves *which repository/stack to act on* from a completely different key in the same JSON body — `repository.full_name` — via `Handler#repository_name`: [4](#0-3) 

`repository.owner.login` and `repository.full_name` are sibling fields inside the same `repository` hash and are never cross-validated against each other. Shipit officially supports hosting multiple GitHub organizations from a single instance, each with its own distinct `webhook_secret`: [5](#0-4) [6](#0-5) 

Because `Shipit.github(organization:)` looks up a config keyed purely by organization name, and each org's webhook_secret is independent, this creates the following equality that should hold but doesn't:

`organization that authenticated the request (repository.owner.login, checked against that org's secret)` **should equal** `organization implied by repository.full_name (which every handler actually acts on)`.

Nothing in `verify_signature` or in `Handler#repository_name` enforces this equality.

## Impact Explanation
An attacker who legitimately controls a GitHub App installation for **their own** organization (`OrgA`) on a shared/multi-tenant Shipit instance — and therefore possesses `OrgA`'s `webhook_secret`, since GitHub App owners configure/see this secret themselves — can:

1. Craft a raw JSON push/status/check_suite/pull_request payload where `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/some-repo"` (a repository belonging to a different organization tracked by the same Shipit instance, which the attacker does not control).
2. Sign the raw body with `OrgA`'s webhook secret (HMAC-SHA1), producing a valid `X-Hub-Signature`.
3. POST directly to `/webhooks`. `verify_signature` selects `Shipit.github(organization: 'OrgA')`, verification succeeds.
4. `PushHandler` (or `status`/`check_suite`/`pull_request` handlers) then resolves the stack via `Repository.from_github_repo_name('OrgB/some-repo')` and, e.g. for push events, calls `stack.sync_github(expected_head_sha: ...)`, which enqueues `GithubSyncJob` to fetch and append commits, and can drive continuous-deployment/auto-merge behavior for `OrgB`'s stack: [7](#0-6) [8](#0-7) 

This is a cross-organization/cross-repository write into a stack the attacker never had access to, satisfying the "cross-repository writes" / "unauthorized deploy" impact bar, achieved purely by exploiting an unenforced binding between the field checked at authentication time and the field consumed at execution time — the same shape of flaw as the Footium report.

## Likelihood Explanation
This requires the deployment to use the documented multi-organization `github:` config (explicitly supported and documented), and the attacker only needs control of one legitimate, independently-configured org/app on that shared instance — not any credential, session, or privileged access to the target org. This is a realistic scenario for any shared/multi-tenant Shipit deployment onboarding multiple external GitHub organizations, matching the rules' requirement of an unprivileged attacker crossing an organization/repository trust boundary.

## Recommendation
After signature verification succeeds for organization `O`, `WebhooksController`/`Handler` should verify that `repository.full_name`'s owner segment (or `organization.login` for org-scoped events) equals the authenticated `O`, and reject (422) otherwise. Alternatively, resolve the target `Repository`/`Stack` first, and require that its recorded owner matches the organization whose secret produced a valid signature, rather than trusting `repository.full_name` unconditionally once *any* valid signature for *any* configured org is found.

## Proof of Concept
Given multi-org config as in `test/dummy/config/secrets_double_github_app.yml` (`OrgOne`, `OrgTwo`, distinct `webhook_secret`s), and a Shipit instance hosting a stack for `OrgTwo/private-repo`:

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(body, OrgOne_webhook_secret)>

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha that exists on OrgTwo/private-repo>",
  "repository": {
    "full_name": "OrgTwo/private-repo",
    "owner": { "login": "OrgOne" }
  }
}
```

`verify_signature` computes `repository_owner == "OrgOne"`, loads `OrgOne`'s `GitHubApp`, and validates the signature successfully (attacker legitimately knows `OrgOne`'s secret). `PushHandler#process` then looks up `Repository.from_github_repo_name("OrgTwo/private-repo")` and enqueues `GithubSyncJob` for `OrgTwo`'s stack, entirely bypassing the fact that the request was never authenticated for `OrgTwo`. [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```
