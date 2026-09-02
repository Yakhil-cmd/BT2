### Title
Webhook signature is verified against the org selected by `repository.owner.login`, but the acted-upon repository is selected by the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against using `repository.owner.login` from the JSON body, while every event handler (`PushHandler`, `PullRequest::*Handler`, `Handler#stacks`) resolves the *target* repository/stack using a completely different field in the same body, `repository.full_name`, via `Repository.from_github_repo_name`. In a Shipit deployment configured for multiple GitHub organizations (the multi-org config schema explicitly supported by `Shipit.github`/`Shipit.github_app_config`), these two fields are never cross-checked for consistency.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
``` [1](#0-0) 

`Shipit.github(organization:)` looks up a per-organization config block (`app_id`, `webhook_secret`, `private_key`, ...) keyed by the organization name, as shown in the documented multi-org secrets layout:
```yaml
github:
  somegithuborg:
    webhook_secret: ...
  someothergithuborg:
    webhook_secret: ...
``` [2](#0-1) 
and the resolver code: [3](#0-2) 

Once the signature check passes (using the secret belonging to `repository.owner.login`), the raw JSON body is dispatched to handlers, none of which reuse `repository.owner.login`. They instead pull the *target* repository from `repository.full_name`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end

def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [4](#0-3) 
`Repository.from_github_repo_name` simply splits `owner/name` out of that string and does a DB lookup, with no relation back to the organization that authenticated the request: [5](#0-4) 

`PushHandler` (the most consequential handler, triggering `stack.sync_github`) and every `PullRequest::*Handler` (`OpenedHandler`, `ReopenedHandler`, `LabelCapturingHandler`, `LabeledHandler`, etc.) resolve their target repository the same way, via `params.repository.full_name`: [6](#0-5) [7](#0-6) 

**The broken binding**: the code implicitly assumes
`org used to select the verifying secret (repository.owner.login) == owner encoded inside repository.full_name (the value the handlers act on)`.
Nothing in `WebhooksController` or `Handler` enforces this equality. Both values are just string fields inside the JSON body that any organization with its own valid `webhook_secret` can set independently of each other.

### Impact Explanation
In a Shipit instance onboarding more than one GitHub organization (each with its own GitHub App and `webhook_secret`, which is the documented/supported multi-tenant configuration), an attacker who legitimately controls one onboarded organization ("attacker-org", with its own valid `webhook_secret` obtained by creating/installing their own GitHub App as documented in `docs/setup.md`) can:
1. Craft a raw webhook body where `repository.owner.login = "attacker-org"` (so `verify_signature` fetches and validates against attacker-org's own secret and passes) but `repository.full_name = "victim-org/victim-repo"`.
2. Sign the body with attacker-org's own `webhook_secret` (which they legitimately possess) — `verify_signature` succeeds.
3. `Shipit::Webhooks.for_event(event)` dispatches to e.g. `PushHandler`, which resolves the target `Stack` via `repository.full_name`, landing on `victim-org/victim-repo`'s stacks and calling `stack.sync_github(expected_head_sha: params.after)` on a repository the attacker never controls or was authorized to trigger events on.
4. Similarly, `PullRequest::OpenedHandler`/`LabeledHandler`/`LabelCapturingHandler` can be made to archive/unarchive review stacks, add PR labels, or provision/deprovision review environments belonging to the victim org, purely because the attacker forged the `full_name` field while satisfying signature validation with their own organization's secret.

This breaks the trust boundary between "organization that authenticated the webhook" and "repository that gets written to," letting a legitimate-but-unprivileged tenant of a multi-org Shipit deployment trigger unauthorized syncs/deploys-related side effects (sync_github, review-stack archive/unarchive/provision) against a repository/stack they do not own, without ever needing the victim's `webhook_secret`, an `ApiClient` token, or a GitHub session.

### Likelihood Explanation
Requires a Shipit deployment configured with more than one organization in `secrets.github` (an explicitly documented and coded configuration path — `Shipit.github_app_config`/`TOP_LEVEL_GH_KEYS` distinguish single-org vs. multi-org schemas). Given that condition, exploitation only requires the attacker to be able to sign a webhook with their own organization's secret and POST it to the shared `/webhooks` endpoint — no other privilege is needed. This is a moderate-likelihood, high-impact class of bug specific to multi-tenant Shipit setups.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, after signature validation, enforce that the organization used to select the verifying secret matches the owner encoded in every repository/organization field the handler will subsequently use (e.g., reject or re-derive `repository.full_name`'s owner against `repository_owner`, or better, have `Repository.from_github_repo_name` (or the `Handler` base class) require the resolved repository's `owner` to equal the verified `repository_owner`/`organization` context passed down from the controller instead of re-parsing an unauthenticated-adjacent field.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `attacker-org` (webhook_secret known to attacker) and `victim-org` (has an existing stack for `victim-org/victim-repo`).
2. Attacker builds a push-event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against attacker-org's own secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack — an action the attacker was never authorized to trigger, achieved purely by mismatching the two unrelated payload fields.

### Citations

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
