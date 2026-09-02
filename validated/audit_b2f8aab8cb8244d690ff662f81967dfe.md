Based on my investigation, this confirms the multi-org config supports `Shipit.github(organization:)`, each keyed by organization name with its own `webhook_secret` under `secrets.github[organization]`. This confirms the vulnerability I identified in `WebhooksController`.

### Title
Webhook signature verification selects the verifying organization's secret from the unverified request body, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on a field taken directly from the untrusted, not-yet-verified JSON body (`repository.owner.login` or `organization.login`), rather than from anything cryptographically tied to the request. This mirrors the reported bug class: a check ("is this webhook authentic") is performed using a value that itself has not passed the very check it is meant to gate — i.e., the payload field acted upon (`repository_owner`) is never covered by the verified signature at the time it is used to select the verification key.

### Finding Description
`verify_signature` computes `repository_owner` straight from `params` (the parsed JSON body) before any signature check occurs: [1](#0-0) [2](#0-1) 

It then uses that attacker-controlled value to fetch the corresponding `GitHubApp` instance and its `webhook_secret`: [3](#0-2) 

In a multi-organization Shipit deployment (`secrets.github` keyed by organization, each with its own `webhook_secret`, per `github_app_config`), an attacker only needs to know (or guess/leak) the `webhook_secret` for **any single organization** configured on the instance. They can then submit a webhook whose `repository.owner.login` names that organization (satisfying `verify_webhook_signature` using that organization's secret) while the rest of the payload's `repository.full_name` / commit data references a **different organization's repository**. Handlers such as `PushHandler` resolve the target `Stack` independently, using `repository.full_name` from the same unverified payload: [4](#0-3) [5](#0-4) 

Because the field used to select the verification secret (`repository.owner.login`) and the field used to select the acted-upon resource (`repository.full_name`) are two independently attacker-supplied fields in the same unverified body, an attacker who only holds the webhook secret of a low-value/low-trust org onboarded to the same Shipit instance can forge signed-looking webhooks that are processed as if they originated from a different organization's repository — since nothing binds the signature check to the resource the handlers subsequently act on.

### Impact Explanation
This breaks the binding "organization authenticated versus the repository that is written." An attacker controlling one organization's webhook secret (e.g., their own onboarded low-trust org, or a leaked secret for one tenant) can forge webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) that are attributed to arbitrary other repositories/stacks configured on the same Shipit instance, triggering `sync_github`, merge-queue processing, review-stack provisioning/archival, team/user creation, and status updates for stacks they do not own. This is a cross-organization/cross-repository trust violation, matching the High-severity criteria (escalation of authorization boundaries via forged trusted signals) since it lets a single-org secret holder inject events scoped to unrelated repositories.

### Likelihood Explanation
This only manifests for deployments using the multi-organization `secrets.github` schema (one `GitHubApp`/webhook secret per organization) rather than the single global app config — the "backward compatibility" default path in `Shipit.github`. For such multi-tenant setups, the attack requires knowledge of one org's webhook secret, which is plausible for an org admin/member of any one onboarded organization, i.e., no privileged Shipit credentials, no GitHub App private key, and no repository write access are required — only being a legitimate (but otherwise unprivileged relative to the target repo) participant able to view/generate one organization's webhook secret.

### Recommendation
Do not select the verification key from unverified payload data. Either:
- Bind webhook routes to the specific organization/installation via the URL (e.g., `/webhooks/:organization`) validated against a signed/allowlisted identifier, or
- After verifying the signature with a candidate organization's secret, cross-check that the payload's `repository.full_name` / `installation.id` actually belongs to that same organization (using GitHub's own installation ID rather than the attacker-supplied `login` string) before dispatching to handlers, or
- If using GitHub Apps, verify using the `installation.id` from the payload matched against the configured installation ID for that organization (a fixed, non-attacker-guessable value from `secrets.github`), rejecting mismatches, similar to how `getMakerAmount`/`getTakerAmount` in the original report should be validated before being trusted/executed.

### Proof of Concept
1. Deploy Shipit with multi-org config: `secrets.github` containing `orgA` (attacker-controlled/known secret) and `orgB` (victim, target Stack/Repository configured in Shipit).
2. Attacker crafts a JSON push payload:
   - `repository.owner.login = "orgA"`
   - `repository.full_name = "orgB/victim-repo"`
   - `ref = "refs/heads/main"`, `after = "<arbitrary sha>"`
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(orgA_webhook_secret, raw_body)>`.
4. POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner` = `"orgA"`, fetches `Shipit.github(organization: "orgA")`, and verifies successfully against the attacker-known `orgA` secret.
6. `PushHandler#process` runs using `payload.dig('repository','full_name')` = `"orgB/victim-repo"`, triggering `stack.sync_github` for the victim's stack — despite the attacker never possessing `orgB`'s webhook secret. [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-64)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
