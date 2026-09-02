## Title
Webhook signature verification selects the signing organization from an unverified payload field that differs from the field used to resolve the target repository, enabling cross-tenant/cross-repository forged events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which organization's `webhook_secret` to check the HMAC signature against by reading `repository.owner.login` straight out of the unauthenticated JSON body, *before* the signature has been verified. Every downstream webhook `Handler` instead resolves the actual `Repository`/`Stack` to act on using a different field from the same body, `repository.full_name`. In a multi-organization Shipit deployment these two fields are never cross-checked against each other, so a party who legitimately possesses the `webhook_secret` for one onboarded organization can forge a payload that signs as that organization but targets a `Repository` belonging to a completely different organization configured on the same Shipit instance.

### Finding Description
`Shipit.github(organization:)` supports multiple organizations, each with its own `webhook_secret`, keyed under `secrets.github` [1](#0-0) . The webhook signature check derives the organization to use purely from the incoming, not-yet-verified body:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Once the signature validates, `create` hands the same raw JSON to every registered `Handler` for the event [3](#0-2) . Handlers never look at `repository.owner.login` again; they resolve the target repository from a different field, `repository.full_name`:

```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

and `Repository.from_github_repo_name` looks the record up purely by that string, independent of which secret verified the request: [5](#0-4) 

The equality the engine implicitly assumes — `organization that signed the payload == organization/repository that gets acted upon` — is never enforced. `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled strings inside the same forged JSON body; nothing ties them together before the signature check selects which secret to trust.

### Impact Explanation
In a multi-org Shipit install, the admin who set up the GitHub App for Organization A necessarily knows Organization A's `webhook_secret` (they chose it when creating the app, per `docs/setup.md`). Using only that secret, they can sign an arbitrary payload with `repository.owner.login = "orgA"` (so `verify_signature` fetches and matches Organization A's secret) while setting `repository.full_name = "orgB/private-repo"`. Handlers such as `PushHandler` will then resolve Organization B's real `Stack` and trigger `stack.sync_github(expected_head_sha:)`, feeding an attacker-chosen `after` SHA into Organization B's stack without ever authenticating against Organization B's secret [6](#0-5) . Similar cross-tenant writes are reachable through the `status`, `check_suite`, and `pull_request` handlers, all of which key off `repository.full_name` for record lookup while trust was established solely on `repository.owner.login`. This is a cross-repository write across organizational trust boundaries using credentials scoped to a different organization.

### Likelihood Explanation
Requires only knowledge of one onboarded organization's `webhook_secret`, which is set independently per organization and is not treated as a globally trusted secret; any tenant admin who configured their own GitHub App for the shared Shipit instance holds it. No GitHub App private key, `ApiClient` token, or Shipit session is needed, and the `/webhooks` endpoint is unauthenticated by design (`skip_before_action :verify_authenticity_token`) [7](#0-6) .

### Recommendation
After verifying the HMAC signature, re-derive the organization strictly from the field(s) actually used for record resolution (`repository.full_name`'s owner segment, or `organization.login`) and reject the request if it does not match the organization whose secret validated the signature. Do not let an unverified body field select which secret validates that same body.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret`s, both with stacks onboarded.
2. As the admin of `orgA` (who legitimately knows `orgA`'s `webhook_secret`), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/private-repo" }
   }
   ```
3. Sign the raw body with `orgA`'s `webhook_secret` and send it to `POST /webhooks` with `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")` and validates the signature successfully [8](#0-7) .
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("orgB/private-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `orgB`'s stack, even though the request was only ever authenticated with `orgA`'s secret [6](#0-5) .

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

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
