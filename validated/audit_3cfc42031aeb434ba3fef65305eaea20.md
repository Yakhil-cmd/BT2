Confirmed vulnerability: in the multi-organization webhook configuration, the secret used to authenticate the webhook is selected from the payload's `repository.owner.login`/`organization.login` field, but the payload data actually acted upon (`repository.full_name`) is a *separate, unverified field* that is never compared against the field that determined the signing key.

### Title
Webhook processing trusts `repository.full_name` for repo/stack resolution while signature verification is keyed on a different, unchecked `repository.owner.login` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the still-unverified JSON body. `Shipit::Webhooks::Handlers::Handler#stacks`, used by `PushHandler`, `CheckSuiteHandler`, and (via `Repository.from_github_repo_name`) other handlers, resolves the target `Repository`/`Stack` using a *different* field of the same payload: `repository.full_name`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`Shipit.github(organization:)` looks up per-organization config (`app_id`, `webhook_secret`, etc.) via `github_app_config(organization)`, keyed purely off the organization string extracted from the unverified request body (`repository_owner`). [4](#0-3) [3](#0-2) 

Once `GitHubApp#verify_webhook_signature` succeeds using *that* organization's secret, the controller proceeds to re-parse the same raw body and dispatch it to event handlers unmodified. [5](#0-4) 

Handlers such as `PushHandler` and `CheckSuiteHandler` resolve the target Stack purely from `repository.full_name` via `Repository.from_github_repo_name`, with no re-validation that the repo's owner matches the organization whose secret authenticated the request. [2](#0-1) [6](#0-5) 

Because the HMAC covers the entire raw body, a request cannot be "half-forged" from outside — but an operator/attacker who legitimately controls a Shipit-configured organization (e.g. a low-privileged GitHub org admin able to configure their own org's `webhook_secret` in Shipit, or anyone who has obtained that one organization's `webhook_secret` from any leak/misconfig) can freely construct a payload where `repository.owner.login` = their own organization (selecting the secret they know) while `repository.full_name` = `"other-org/other-repo"` pointing at a stack belonging to an entirely different, unrelated organization tracked by the same Shipit instance. The signature will verify successfully (it's a valid HMAC for the raw body under the attacker's own known secret), and the handler will still act on the victim organization's Stack because it only consults `repository.full_name`.

This is the exact binding-break called out by the rules: "an organization that authenticated versus the repository that is written." The equality that should hold — `organization_that_signed(payload) == owner(repository.full_name)` — is never checked anywhere in `WebhooksController` or `Handler`.

### Impact Explanation
An attacker who controls the webhook secret for any one organization configured in a multi-org Shipit deployment can inject `push`, `check_suite`, or `status`-equivalent events targeting stacks that belong to a completely different, unrelated organization. Concretely with `PushHandler`, this lets the attacker trigger `stack.sync_github(expected_head_sha:)` for a victim org's Stack with an attacker-chosen `after` SHA, and with `CheckSuiteHandler` trigger `schedule_refresh_check_runs!` for arbitrary commits in a victim stack. Depending on downstream trust in synced revisions/CI state, this can influence which commits are considered deployable in the victim's stack — an unauthorized cross-organization write into deploy-relevant state, without ever needing the victim's own webhook secret, GitHub App credentials, or repository access.

### Likelihood Explanation
Requires the attacker to control (or have leaked to them) the `webhook_secret` for *any* single organization onboarded to a multi-org Shipit instance — a materially lower bar than compromising the target organization's own secret or GitHub App keys. In any deployment onboarding multiple, mutually-untrusting GitHub organizations (the documented supported configuration in `secrets.*.yml`), this is directly exploitable.

### Recommendation
In `WebhooksController#verify_signature` (or immediately in `create`), after successfully verifying the signature for `repository_owner`, additionally assert that the owner portion of `repository.full_name` (or `organization.login`) equals the `repository_owner`/organization that supplied the matching secret, and reject (422) on mismatch. Alternatively, have `Handler#stacks`/`Repository.from_github_repo_name` reject payloads whose repository owner doesn't match the authenticated organization passed down from the controller.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `orgA` (attacker-controlled, secret known to attacker) and `orgB` (victim, tracked stack `orgB/victim-repo`).
2. Attacker builds a `push` webhook JSON body:
   - `repository.owner.login = "orgA"`
   - `repository.full_name = "orgB/victim-repo"`
   - `ref = "refs/heads/<victim-branch>"`, `after = "<attacker-chosen-sha>"`
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POSTs to `/github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")` and verifies successfully against `orgA`'s secret. [7](#0-6) 
5. `create` dispatches to `PushHandler`, which calls `stacks` → `Repository.from_github_repo_name("orgB/victim-repo")` → resolves and syncs `orgB`'s stack, with no check that `orgB != orgA`. [2](#0-1)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
