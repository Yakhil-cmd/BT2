## Title
Webhook signature verification uses `repository.owner.login`/`organization.login` to select the GitHub App secret, while the actual event dispatch trusts `repository.full_name` — allowing cross-organization webhook forgery when any configured org has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which configured GitHub App (and thus which `webhook_secret`) to validate the incoming payload's HMAC against, based on `repository_owner` — a field derived from `repository.owner.login` (falling back to `organization.login`) inside the **unverified** JSON body. Every other part of the pipeline (`create`, and all `Shipit::Webhooks::Handlers::Handler` subclasses) instead trusts `repository.full_name` to decide which `Repository`/`Stack`/`Team` to act on. Because `webhook_secret` is explicitly documented as optional per-organization, an attacker only needs one configured Shipit organization with no `webhook_secret` set to bypass signature verification entirely for a payload whose `repository.full_name` (or `organization.login` for membership events) points at a *different*, secured organization/repository.

### Finding Description
`verify_signature` computes the org used to select the `GitHub App`/secret purely from the request body, without any relation to the org that is actually acted upon later: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config, and `GitHubApp#verify_webhook_signature` short-circuits to `true` when that organization's `webhook_secret` is blank: [3](#0-2) [4](#0-3) 

The setup documentation explicitly states `webhook_secret` is optional, and the multi-org example configuration confirms multiple independent GitHub Apps (each potentially with distinct or absent secrets) can be registered simultaneously: [5](#0-4) 

After `verify_signature` passes (bypassed, in this scenario, because the *selected* org has no secret), `create` parses the same raw body and dispatches to event handlers using the full payload — none of which re-check `repository.owner.login` against `repository.full_name`, or otherwise re-derive the org used for verification: [6](#0-5) 

Handlers resolve the target `Repository`/`Stack` purely via `repository.full_name`: [7](#0-6) [8](#0-7) 

The `push` handler triggers `Stack#sync_github`, which enqueues `GithubSyncJob`, which fetches commits from GitHub, creates `Commit` records, and — if `continuous_deployment` is enabled on the target stack — subsequently triggers an actual automated deploy via `Stack#trigger_continuous_delivery`/`ContinuousDeliveryJob`: [9](#0-8) [10](#0-9) [11](#0-10) 

The `membership` handler similarly trusts `organization.login` from the same unverified payload to create/attach `Team` records tied to `Shipit.github_teams` OAuth authorization: [12](#0-11) 

This is the same bug class as the reference report: a value is used to satisfy an authorization/verification check (`incentiveVault.withdrawTokens(pool, token, …)` using the wrong `token`), while a *different, similar* value is the one actually consumed downstream. Here the binding broken is:

`organization used to select the webhook-signature-verifying secret` ≠ `repository/organization actually written to by the event handler`

Before the attacker's request: signature verification and event dispatch both nominally refer to "the org the payload is about," and are assumed equal. After a crafted request: `repository_owner` (verification key) can be set to an org with no `webhook_secret`, while `repository.full_name`/`organization.login` (dispatch key) points to an unrelated, secured org/stack — breaking the equality the code implicitly assumes.

### Impact Explanation
An unauthenticated network attacker who can reach `/webhooks` (no session, no API token, no webhook secret needed — they exploit the *absence* of a secret on one org to attack a *different* org) can:
- Forge `push` webhooks for any repository/stack registered under a securely-configured organization, causing `GithubSyncJob` to run and, for stacks with `continuous_deployment` enabled, trigger an **unauthorized deploy** (Critical impact per the rules: "unauthorized deploy, rollback or merge").
- Forge `membership` events naming an arbitrary GitHub `organization.login`/team, creating/populating `Shipit::Team` records that back `Shipit.github_teams` authorization checks used elsewhere in the app (High impact per the rules: "escalation into `Shipit.github_teams` authorization").
- Forge other events (`status`, `check_suite`, `pull_request` archive/unarchive) against arbitrary tracked repositories, corrupting commit/stack state.

The severity is amplified specifically in Shipit's supported multi-organization deployment mode, which the project's own documentation recommends for anyone deploying from more than one GitHub org.

### Likelihood Explanation
Likelihood is not trivial but realistic: it requires the Shipit operator to have configured at least one organization in the multi-org `github:` block without a `webhook_secret` (explicitly supported/optional per `docs/setup.md`), while other organizations are configured with secrets and hold real, sensitive stacks. Given webhook secrets are optional and easy to omit (e.g., during setup, staging orgs, or low-priority test orgs added to the same Shipit instance), this is a plausible operational configuration, and exploitation requires nothing more than an unauthenticated HTTP POST — no credentials of any kind.

### Recommendation
Do not let the organization/app selection used for HMAC verification diverge from the identity actually acted upon:
- Derive the org used both for `Shipit.github(organization:)` (secret selection) and for locating the target `Repository`/`Stack`/`Team` from the *same*, single field, and verify they are consistent before dispatch.
- Alternatively, verify the signature against every configured GitHub App/secret that could plausibly own the payload (or require `webhook_secret` to be mandatory for all configured organizations, rejecting configs that omit it), so that a missing secret on one org can never bypass verification for another.
- Add an explicit check in `WebhooksController#create` (or in `Handler#stacks`) confirming that `repository.owner.login` (used for verification) matches the owner portion of `repository.full_name` (used for dispatch) before processing.

### Proof of Concept
Given a Shipit instance configured with multiple GitHub Apps as documented (`docs/setup.md`), e.g.:
```yaml
github:
  unsecured-org:      # webhook_secret intentionally left blank
    app_id: ...
    installation_id: ...
    webhook_secret:
  secured-org:        # real webhook_secret configured, hosts sensitive stacks
    app_id: ...
    installation_id: ...
    webhook_secret: "s3cr3t"
```

1. Attacker sends, with no signature or an arbitrary bogus `X-Hub-Signature`:
```
POST /webhooks
X-Github-Event: push

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha claimed to exist>",
  "repository": {
    "full_name": "secured-org/victim-repo",
    "owner": { "login": "unsecured-org" }
  }
}
```
2. `verify_signature` calls `Shipit.github(organization: "unsecured-org")`; `verify_webhook_signature` returns `true` immediately because `webhook_secret` is blank for `unsecured-org`. [4](#0-3) 
3. `create` proceeds, `PushHandler` resolves `Repository.from_github_repo_name("secured-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` for the real, secured stack — despite the request never having been validated against `secured-org`'s actual `webhook_secret`. [13](#0-12) 
4. If the targeted stack has `continuous_deployment` enabled, this leads to an automated deploy being enqueued once `GithubSyncJob` completes, entirely under attacker control of timing/frequency.

### Citations

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

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
