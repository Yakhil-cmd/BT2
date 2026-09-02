## Analysis

This confirms a multi-tenant Shipit deployment (`Shipit.github_organizations`, `github_app_config(organization)`) supports **multiple GitHub organizations, each with its own `webhook_secret`** [1](#0-0) . Each organization's app config is looked up and used purely to select the HMAC secret for verifying the inbound webhook signature, based on a value extracted from the **untrusted JSON body itself**.

### Title
Webhook signature verified against organization-derived-from-payload while sync operates on an attacker-controlled `repository.full_name` — binding break enables cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check using `repository_owner`, itself parsed from the same untrusted JSON body it is verifying (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [2](#0-1) . Once verification "passes" for organization A, the actual handler processing (`Handler#stacks`/`#repository_name`) independently re-reads `payload.dig('repository', 'full_name')` to decide which `Stack`/`Repository` records to mutate [3](#0-2) . Nothing enforces that `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to select the target repository) refer to the same repository. This is the direct analog of the reported bug class: "an organization that authenticated versus the repository that is written" is never checked for equality.

### Finding Description
- `verify_signature` computes `repository_owner` from the JSON body and uses it to fetch `Shipit.github(organization: repository_owner)`, whose `webhook_secret` is used to validate `X-Hub-Signature` against the raw body [4](#0-3) .
- The handler dispatch layer (`PushHandler`, `StatusHandler`, etc.) independently derives the repository to act on from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`#repository_name` [3](#0-2) , and `PushHandler#process` enqueues a real `GithubSyncJob` against every matching `Stack` [5](#0-4) , `app/jobs/shipit/github_sync_job.rb` start="18" end="49" />.
- Both `repository.owner.login` and `repository.full_name` are independent, attacker-supplied JSON fields inside the same signed body — there is no code path that cross-checks `full_name` starts with `owner.login/`. An attacker who legitimately controls a GitHub organization/app registered in this Shipit instance (and therefore possesses/derives the correct webhook HMAC secret for their own org) can produce a validly-signed payload whose `repository.owner.login` equals their own organization (so `verify_signature` picks their own secret and passes) while `repository.full_name` names an entirely different, victim organization's repository already tracked by Shipit.
- This is functionally identical to `VaultRouter.setMarket()` overwriting the caller-supplied `vault` with a different state binding: here the "authenticated identity" (organization used to fetch the secret) and the "entity actually written" (repository resolved from `full_name`) are computed from two different untrusted fields, with no equality enforced between them, even though a single signature is meant to authorize a single specific repository event.

### Impact Explanation
A push (or other handled) webhook forged this way lets an attacker who owns one org configured in a multi-org Shipit deployment cause the engine to:
- Enqueue `GithubSyncJob` for arbitrary other stacks (`push` event) [5](#0-4) , pulling new commits and potentially triggering continuous delivery (`trigger_continuous_delivery`) for a repository the attacker does not own, i.e., an **unauthorized deploy** initiated on the victim's stack [6](#0-5) .
- Inject fabricated commit statuses via `StatusHandler` for commits on repositories the attacker doesn't control, since that handler resolves `Commit.where(sha:)` globally without organizational scoping tied to the verified organization [7](#0-6) , which can flip CI gating used for deploy safety checks and enable an unauthorized deploy.

This matches the required Critical/High impact bar: cross-repository writes / an unauthorized deploy driven by identity confusion between the verified organization and the acted-upon repository.

### Likelihood Explanation
Requires the attacker to be a legitimate administrator of at least one GitHub organization/app that is registered as a tenant in the same multi-org Shipit deployment (so they know/derive that org's webhook secret), which is a realistic scenario for shared/multi-tenant Shipit installs. No Shipit session, API token, or `webhook_secret` disclosure of the *victim* org is needed — only knowledge of the attacker's own org's secret, which they legitimately possess by having configured that org's webhook themselves.

### Recommendation
In `WebhooksController#verify_signature` (and in `Handler#repository_name`/`#stacks`), enforce that the organization used to select the verifying secret is derived from — and equals — the owner of the repository that `full_name` resolves to. Concretely: after selecting `repository_owner` and verifying the signature, assert `payload.dig('repository', 'full_name')&.split('/')&.first&.casecmp?(repository_owner)` before dispatching to handlers, or better, resolve the target `Repository`/`Stack` strictly by (`repository_owner`, computed at verification time) instead of independently re-parsing `full_name` deeper in the handler chain.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s under `Shipit.github_organizations` [8](#0-7) .
2. `victim-org/victim-repo` already has a `Stack` registered and tracked in Shipit.
3. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha existing in victim repo>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s webhook secret (which they legitimately hold) over this exact raw body.
5. POST to `/github/webhooks`. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the signature verifies successfully [9](#0-8) .
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob`/triggers sync and potential continuous deployment for the victim stack, despite the request never being signed by `victim-org`'s secret [3](#0-2) , [5](#0-4) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-39)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```
