This confirms the vulnerability path is real and concrete. In a multi-organization Shipit configuration (as documented in `docs/setup.md` and `config/secrets.development.example.yml`), each organization has its own `github.<org>.webhook_secret`. The signature check in `WebhooksController#verify_signature` selects which secret to verify against based on `repository_owner`, derived from the payload itself (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`), and then calls `Shipit.github(organization: repository_owner)` to fetch that org's `GitHubApp` and verify the signature.### Title
Webhook signature verification binds trust to the payload's `repository.owner.login` while all handlers act on the payload's `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to check the HMAC signature against using an *attacker-controlled* field (`repository.owner.login` or `organization.login`), while every webhook handler resolves the repository/stack to act on using a *different* attacker-controlled field (`repository.full_name`). Nothing ties these two fields together, so a party holding a valid webhook secret for one configured organization can forge a signed payload whose `repository.full_name` points at a stack belonging to a different, unrelated organization.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`, the signature check is: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the untrusted JSON body (`params.dig('repository','owner','login')`), and is used to pick which organization's `GitHubApp` (and thus which `webhook_secret`) to verify the signature against, via `Shipit.github(organization: repository_owner)`: [3](#0-2) 

Shipit explicitly supports multiple organizations, each with its own independent `webhook_secret` in `secrets.yml`: [4](#0-3) 

Once the signature is accepted, every default handler (`PushHandler`, pull-request handlers, etc.) resolves the target repository/stack from a *separate* field of the same payload, `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`: [5](#0-4) 

and `Repository.from_github_repo_name`: [6](#0-5) 

`PushHandler` then triggers `stack.sync_github`, which enqueues `GithubSyncJob` to fetch commits and write `Commit` records for that stack: [7](#0-6) [8](#0-7) 

**The broken binding**: signature verification authenticates `payload.repository.owner.login == "org-that-signed-this"`, but the actual write target is selected by `payload.repository.full_name`, which can be set to any `owner/name` string, including one belonging to a stack configured under a *different* organization/app config. The controller never checks that `repository.full_name`'s owner segment matches `repository.owner.login`/`repository_owner`, i.e. it never enforces:

```
repository_owner (used to select verifying secret) == owner segment of repository.full_name (used to select the mutated Repository/Stack)
```

This is the "organization that authenticated versus the repository that is written" analog called out in the task rules — directly analogous to the `withdraw`/`staker` bug where one field (shares/caller) drives a state update while a different, related field (`staker`) that should have been checked/updated is not.

### Impact Explanation
Any party who is an admin of one organization onboarded into a shared, multi-organization Shipit instance (i.e., who legitimately possesses that org's `webhook_secret`, obtained by configuring a GitHub App webhook for their own org) can:
- Sign an arbitrary JSON body with their own org's secret.
- Set `repository.owner.login` to their own org (so `verify_signature` succeeds using their own app's secret) while setting `repository.full_name` to `victim-org/victim-repo`.
- Have the `push` handler trigger `GithubSyncJob` against the victim stack, causing Shipit to fetch commits from the victim's GitHub repo using the *victim organization's* GitHub App credentials/token (`stack.github_api`, resolved via `Repository#github_app` → `Shipit.github(organization: owner)`) and write `Commit` records into the victim's stack, potentially triggering continuous deployment/merges for commits the attacker names as `expected_head_sha`.

This is a cross-repository/cross-tenant write achieved purely by forging a webhook payload field that the app never validates against the field it used for authentication — this crosses the "cross-repository writes" / "unauthorized deploy" impact bar for a Critical/High finding in a multi-org deployment, without needing an `ApiClient` token, a Shipit session, or GitHub App private keys for the victim org.

### Likelihood Explanation
Likelihood is Low–Medium: this only manifests in the multi-organization configuration schema (`github.<org>.webhook_secret`, documented and supported), which is optional but explicitly supported by the engine. It also requires the attacker to be an admin/maintainer of one of the *other* organizations sharing the same Shipit instance — a party who is "unprivileged" with respect to the target org/repo but has full control of their own org's app config. No repository write access, Shipit session, or victim-org credentials are needed.

### Recommendation
In `WebhooksController#verify_signature`, after determining `repository_owner`, verify that it matches the owner segment of `params.dig('repository', 'full_name')` (and of `params.dig('organization', 'login')` when used as fallback) before dispatching to handlers, rejecting (422) any payload where these disagree. Alternatively, resolve the repository the handlers will act on and look up its configured owner, then verify the signature using that resolved owner rather than trusting the raw payload field.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (per the documented multi-org schema), and register/track a stack for `victim-org/victim-repo`.
2. As an admin of `attacker-org`'s GitHub App, construct a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Sign this body with `attacker-org`'s `webhook_secret` (`sha1=` HMAC per `Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` logic) and POST it to `/webhooks` with `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature using `attacker-org`'s secret.
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")`, finds the victim's stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, enqueuing `GithubSyncJob` against the victim's stack using the victim organization's own configured GitHub App token — all authorized purely by the attacker's own org's webhook secret.

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

**File:** lib/shipit.rb (L170-181)
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
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
