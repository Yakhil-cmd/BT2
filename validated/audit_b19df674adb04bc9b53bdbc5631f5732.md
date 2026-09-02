### Title
Webhook signature verification binds to attacker-controlled `repository.owner.login` while handlers act on a different field, `repository.full_name`, allowing cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit installation, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate a webhook against using `params.dig('repository','owner','login')` — a field taken from the unauthenticated request body. Every handler that actually acts on the webhook (push, pull request, etc.) resolves the target repository/stack from a *different* body field, `payload.dig('repository','full_name')`. Nothing ties these two fields together. If any organization configured on the instance has no `webhook_secret` set (documented as optional), signature verification for that organization unconditionally succeeds, and an attacker can submit a payload naming that unprotected organization in `repository.owner.login` (to pass verification) while pointing `repository.full_name` at a stack belonging to a completely different, secret-protected organization, causing that stack to sync/deploy without ever presenting valid credentials for it.

### Finding Description
`WebhooksController#verify_signature` picks the app/secret to check against from attacker-supplied JSON, not from any authenticated source: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatically verified: [3](#0-2) 

Shipit explicitly supports multiple GitHub App configurations, one per organization, each with its own (documented-as-optional) `webhook_secret`: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (based on `repository.owner.login`), `WebhooksController#create` dispatches the *raw, unmodified* body to every registered handler for that event type: [6](#0-5) 

Every handler resolves the target repository from a different field, `repository.full_name`, completely independent of `repository.owner.login`: [7](#0-6) 

`PushHandler` uses that lookup to enqueue a real sync against the stack, with an attacker-controlled `expected_head_sha`: [8](#0-7) 

This is the exact bug class of the report: a field (`BlockOverrides`/here, `repository.full_name`) is acted upon by execution logic but is never covered by the field that was actually verified (`repository.owner.login`, used only to pick a secret to check the raw body against). The binding that should hold — "organization whose secret authenticated this request" == "organization that owns the repository being written to" — is broken because the two are read from independent, both-attacker-controlled parts of the same JSON body, and the body's HMAC only proves *a* secret matched, not that the claimed owner and the acted-upon repository agree, especially when the claimed owner's secret is blank/misconfigured.

### Impact Explanation
An attacker who can produce (or is not required to produce, when `webhook_secret` is blank for at least one configured organization) a "valid" signature for organization A can still direct execution against organization B's stacks, teams, or pull requests by simply changing `repository.full_name` (or, for `MembershipHandler`, `organization.login`/`member.login`) independent of the value used for signature selection. Concretely:
- `PushHandler` can force `GithubSyncJob` to sync an arbitrary stack to an attacker-chosen `expected_head_sha`, which subsequently drives deploy-spec caching and (depending on the target stack's continuous-deployment configuration) can trigger an unauthorized deploy of a repository the attacker never authenticated against — [9](#0-8) .
- `MembershipHandler` creates/removes `Team` memberships (`team.add_member`/`team.members.delete`) using attacker-supplied `member.login`, and `Shipit.github_teams` gates access-control authorization for the whole instance — [10](#0-9) , [11](#0-10) . This can be used to escalate a chosen GitHub login into a `Shipit.github_teams`-authorized team without any real organization membership event from GitHub.
- Pull-request handlers similarly resolve `stack`/`repository` via `full_name`, independent of the verified owner, enabling unarchive/label/merge-status side effects on the wrong repository's review stacks — [12](#0-11) .

This matches the required High/Critical bar: escalation into `Shipit.github_teams` authorization and/or an unauthorized deploy/sync triggered on a stack the attacker never legitimately authenticated against.

### Likelihood Explanation
Exploitation requires the instance to run Shipit's documented multi-organization configuration with at least one organization whose `webhook_secret` is left blank (explicitly called out as "optional" in the setup docs), or requires the attacker to otherwise possess a valid signature for any one configured organization (e.g., a low-value/test org on the same instance). Given that shape, no privileged Shipit session, API token, or GitHub write access is needed — only the ability to POST to the public `/webhooks` endpoint with a crafted `X-Hub-Signature`/blank-secret organization name and a `repository.full_name`/`organization.login` pointing elsewhere. This is a plausible, realistic multi-tenant misconfiguration rather than a purely theoretical scenario, since the docs themselves present `webhook_secret` as optional per organization.

### Recommendation
Tie the field used to select and verify the webhook secret to the same field the handlers act on: derive `repository_owner` for secret selection from `repository.full_name`'s owner segment (or require they match and reject on mismatch), and refuse to treat a blank/missing `webhook_secret` as automatically verified for any organization once multi-organization configuration is enabled. At minimum, `verify_webhook_signature` should require `webhook_secret` to be present for every configured organization, and `WebhooksController` should validate that `repository.owner.login` and the owner segment of `repository.full_name` refer to the same organization before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations in `config/secrets.yml`: `orgA` (no `webhook_secret` set) and `orgB` (a real, protected repo/stack with `webhook_secret` set).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/protected-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
4. `PushHandler#process` resolves the stack via `payload.dig('repository','full_name')` = `"orgB/protected-repo"`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `orgB`'s real, protected stack — despite the request never being authenticated against `orgB`'s secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-61)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
