### Title
`StatusHandler` binds webhook signature verification to `repository.owner.login` but applies the resulting status write globally by commit SHA - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` is used to validate an incoming webhook based on the `repository.owner.login` (or `organization.login`) field of the payload. Once verified, `Shipit::Webhooks::Handlers::StatusHandler#process` looks up the target `Commit` purely by `sha`, with no scoping to the repository/organization that was used to authenticate the request. This is the same class of bug as the reported `NodeRegistryData.updateNode` issue: the entity that authenticates a signed action (`repository.owner.login` → the GitHub App/org whose secret validated the signature) is not the same entity the code actually acts on (`Commit.where(sha: params.sha)` across the whole install), breaking the equality "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` resolves the verifying key entirely from attacker-controlled payload data: [1](#0-0) [2](#0-1) [3](#0-2) 

`repository_owner` is read straight out of the JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), and `Shipit.github(organization: repository_owner)` selects the `GitHubApp` (and its `webhook_secret`) used for `verify_webhook_signature`: [4](#0-3) 

In a multi-tenant deployment (documented in `docs/setup.md` "Using Multiple GitHub Applications", and modeled by `test/dummy/config/secrets_double_github_app.yml`), several GitHub organizations each get their own `webhook_secret` under one Shipit instance: [5](#0-4) [6](#0-5) 

The signature check merely proves "this body was signed by *some org's* configured secret." It never re-derives or constrains which repository/stack the payload is allowed to mutate. The generic `Handler` base class does scope most handlers by `repository.full_name`: [7](#0-6) 

But `StatusHandler`, which processes GitHub `status` events, does not use `repository_name`/`stacks` at all — it matches commits **only by `sha`**, globally across every stack/repository tracked by the Shipit instance: [8](#0-7) 

So the "signer" (the org whose `webhook_secret` validated the HMAC) and the "entity acted upon" (any `Commit` in the database with a matching `sha`, regardless of which stack/org it belongs to) are two different bindings — exactly the discrepancy the report describes between `owner`/`signer` in `NodeRegistryData.updateNode`.

Creating a `Status` record feeds directly into deploy-gating logic. `Commit#add_status` fires `stack.schedule_merges` on success and can make the commit `deployable?`: [9](#0-8) 

and `Deploy#schedule_continuous_delivery`/`Stack#trigger_continuous_delivery` will trigger an actual deploy job once a commit's statuses satisfy `required_statuses`: [10](#0-9) [11](#0-10) 

### Impact Explanation
An attacker who legitimately administers one GitHub organization/app onboarded to a shared, multi-tenant Shipit instance (per the documented multi-org config) can use that org's own known `webhook_secret` to forge a `status` event naming *their own* org in `repository.owner.login` (passing signature verification) while setting `sha`/`context`/`state` to target a commit belonging to a completely different, victim organization's repository/stack. Because `StatusHandler` never checks that the sha actually belongs to a repository owned by the authenticating org, the forged status is applied to the victim's commit. This can:
- Falsely satisfy `ci.require`/blocking status checks (`deploy_spec.rb#required_statuses`), making an otherwise CI-failing commit `deployable?`.
- Trigger `stack.schedule_merges` and, if `continuous_deployment` is enabled on the victim stack, an unauthorized automatic deploy via `ContinuousDeliveryJob`.

This matches the "High/Critical — unauthorized deploy" impact bucket in scope.

### Likelihood Explanation
Requires the target Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration) and requires the attacker to control one of those onboarded orgs' webhook secret (or have that org's `webhook_secret` left unset, in which case `verify_webhook_signature` returns `true` unconditionally — see `lib/shipit/github_app.rb:77`). No Shipit session, API token, or repository write access on the victim org is needed — only the ability to know/hold the webhook secret of any other org configured on the same instance and to know (or guess/observe) a target commit SHA. This is a realistic scenario for shared internal Shipit deployments serving multiple teams/orgs, which is exactly the deployment pattern the engine documents and ships test fixtures for.

### Recommendation
`StatusHandler` (and any other handler that doesn't already scope through `Handler#stacks`) must verify that the commit(s) being updated belong to a repository owned by the organization that was used to validate the webhook signature, not just match by `sha` globally. Concretely, `StatusHandler#process` should intersect `Commit.where(sha: params.sha)` with commits whose `stack.repository` matches `payload.dig('repository', 'full_name')` (as the base `Handler` already does for other events), and that repository's owning organization should be checked against the organization resolved during `verify_signature`. More generally, the webhook signature verification result should carry the resolved organization forward and every handler should reject payloads whose `repository`/`organization` fields don't match the org that validated the signature.

### Proof of Concept
1. Shipit is configured with two orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org config).
2. Attacker knows `attacker-org`'s `webhook_secret` (they administer that org's GitHub App) and knows the SHA of a commit tracked in a `victim-org` stack (e.g., seen in a public PR/status page).
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" } },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
signed with `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully using the attacker's own known secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (no org/repo filter), and calls `create_status_from_github!`, creating a `success` `Status` for `victim-org`'s commit.
6. If `victim-org`'s stack requires `ci/required-check` and has `continuous_deployment: true`, this fabricated status can trigger an unauthorized deploy of code that never actually passed CI.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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

**File:** app/models/shipit/deploy.rb (L271-299)
```ruby

    def update_release_status
      return unless stack.release_status?

      case status
      when 'pending'
        append_release_status('pending', "A deploy was triggered on #{stack.environment}")
      when 'failed', 'error', 'timedout'
        append_release_status('error', "The deploy on #{stack.environment} did not succeed (#{status})")
      when 'aborted', 'aborting'
        append_release_status('failure', "The deploy on #{stack.environment} was canceled")
      when 'validating'
        unless stack.release_status_delay.zero?
          append_release_status(
            'pending',
            "The deploy on #{stack.environment} succeeded"
          )
        end

        if stack.release_status_delay.positive?
          MarkDeployHealthyJob.set(wait: stack.release_status_delay)
                              .perform_later(self)
        end
      when 'success'
        if stack.release_status_delay.zero?
          append_release_status('success', "The deploy on #{stack.environment} succeeded")
        end
      end
    end
```
