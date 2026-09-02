Confirmed: Shipit supports multi-tenant GitHub App configuration, where each organization has its own independent `webhook_secret` selected via `Shipit.github_app_config(organization)` [1](#0-0) . This makes the finding concrete and exploitable when more than one organization is configured on the same Shipit instance.

### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, while handlers act on the unrelated `repository.full_name` field, allowing cross-tenant repository/stack spoofing - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `params.dig('repository','owner','login')` (falling back to `organization.login`) [2](#0-1) . Once the signature is accepted, the same raw JSON body is dispatched to event handlers, which instead key off `payload.dig('repository','full_name')` to resolve the `Repository`/`Stack` to act on [3](#0-2) , or off `params.organization.login` to resolve the `Team` for membership events [4](#0-3) . Because signature verification and target-resource resolution read from *different* JSON fields of the same attacker-controlled payload, an operator of one legitimate, low-privilege organization onboarded to a shared/multi-tenant Shipit instance can forge a payload that authenticates as their own org (whose `webhook_secret` they legitimately know) while causing the handler to act on a different organization's repository/stack/team.

### Finding Description
`Shipit.github(organization:)` looks up per-organization GitHub App configuration (`app_id`, `installation_id`, `webhook_secret`, etc.) via `github_app_config(organization)`, explicitly supporting multiple, independently configured GitHub organizations on one Shipit deployment [1](#0-0) .

For every inbound webhook, `WebhooksController#verify_signature` determines *whose* secret to verify the signature against purely from the request body itself:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

This is the binding that should hold as an equality: *the organization whose secret authenticated the payload* == *the organization/repository the payload causes Shipit to write to*. However, after the `X-Hub-Signature` check passes, the raw, attacker-crafted JSON is handed unmodified to handlers, which read an entirely separate field to decide what to mutate:
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to find the `Repository`/`Stack` scope for push, pull_request and check_suite events [3](#0-2) , feeding `Repository.from_github_repo_name`, which does a straight owner/name lookup with no relation to `repository.owner.login` [6](#0-5) .
- `MembershipHandler#find_or_create_team!` reads `params.organization.login` to create/attach a `Team`, and separately grants membership based on `params.member.login` [4](#0-3) .

Nothing in `verify_signature` or in `Handler` cross-checks that `repository.owner.login` (the field the HMAC-authenticating organization is derived from) is consistent with `repository.full_name` (or `organization.login` for membership) used downstream. Since the whole JSON body is attacker-supplied plaintext prior to signing (an attacker with a legitimate GitHub App installation on their own organization, tenant A, can freely construct any JSON and sign it with tenant A's own known `webhook_secret`), they can set:
```json
{
  "repository": { "owner": { "login": "tenant-a" }, "full_name": "tenant-b/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
`repository_owner` resolves to `tenant-a`, whose secret they control, so `verify_webhook_signature` passes [7](#0-6) . `PushHandler` then resolves `stacks` via `full_name = "tenant-b/victim-repo"` and calls `stack.sync_github(expected_head_sha:)` on tenant B's stack, enqueuing `GithubSyncJob` for a stack the attacker does not own [8](#0-7) , [9](#0-8) . This same divergence lets a `membership` webhook signed by one organization's secret create/modify a `Team` for a different `organization.login`, and add an arbitrary `member.login` to that team via `find_or_create_by_login!`, potentially escalating that GitHub identity into `Shipit.github_teams` authorization used by `User#authorized?` [10](#0-9) .

### Impact Explanation
This meets the High-impact bar: "escalation into `Shipit.github_teams` authorization" — a forged, self-signed `membership` webhook can attach an arbitrary GitHub login to a `Team` object tied to a *different* organization than the one whose secret authenticated the request, which is exactly the team lookup used by `Authentication#force_github_authentication` / `User#authorized?` to grant application access [11](#0-10) , [10](#0-9) . It also permits triggering `GithubSyncJob`/stack state changes on repositories/stacks belonging to organizations the attacker does not control, which is an unauthorized cross-tenant write to another repository's Shipit state.

### Likelihood Explanation
Requires a Shipit deployment configured with **more than one** GitHub organization (the multi-org config path in `github_app_config`) and requires the attacker to control at least one legitimate, low-privilege organization/webhook-secret on that shared instance — a realistic scenario for a shared/hosted Shipit deployment serving multiple teams or organizations. No GitHub write access to the victim's repository, no Shipit session, and no API token are needed; only knowledge of one's own webhook secret (which any org's GitHub App owner has) is required.

### Recommendation
Cross-validate the field used to select the verifying organization against the field(s) handlers use to resolve the target resource before dispatch — e.g., in `WebhooksController#verify_signature`/`create`, require that `params.dig('repository','full_name')`'s owner segment and `params.dig('organization','login')` match `repository_owner` exactly, rejecting the webhook otherwise. Alternatively, have handlers resolve target repositories/organizations strictly from the same field that was used for signature verification, not from independently attacker-controlled fields in the same payload.

### Proof of Concept
1. Configure Shipit with two organizations, `tenant-a` and `tenant-b`, each with a distinct `webhook_secret` (multi-org config as read by `github_app_config`).
2. As the operator of `tenant-a`'s GitHub App (attacker), craft a raw JSON body:
   ```json
   {"ref":"refs/heads/main","after":"deadbeef...","repository":{"owner":{"login":"tenant-a"},"full_name":"tenant-b/victim-repo"}}
   ```
3. Sign it with `tenant-a`'s known `webhook_secret` using the same HMAC-SHA1 scheme as `verify_webhook_signature` and send it to `POST /webhooks` with header `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner == "tenant-a"`, fetches `Shipit.github(organization: "tenant-a")`, and the signature validates successfully [12](#0-11) .
5. `PushHandler#stacks` resolves via `Repository.from_github_repo_name("tenant-b/victim-repo")`, matching tenant B's actual `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha:)`, enqueuing `GithubSyncJob` against tenant B's stack despite the signature only proving control of tenant A's secret [13](#0-12) .

(Note: I could not find explicit test-suite coverage exercising cross-org `owner.login`/`full_name` mismatch scenarios in the indexed `test/` files, so real-world exploitability should be confirmed by an engineer standing up a two-organization config and reproducing the request end-to-end.)

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L15-43)
```ruby
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
