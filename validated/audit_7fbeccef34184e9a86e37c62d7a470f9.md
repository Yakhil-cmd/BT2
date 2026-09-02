### Title
Webhook signature verification keyed on `repository.owner.login` while event handlers act on the unrelated `repository.full_name` field allows cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')`, but every event handler resolves the target repository/stack from the independent `repository.full_name` field of the same JSON body. In multi-organization deployments these two fields are never cross-checked against each other, so a party who legitimately controls one onboarded organization's webhook secret can forge a payload that authenticates as their own org while acting on any other tracked repository.

### Finding Description
`Shipit::WebhooksController#verify_signature` does: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end
...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`Shipit.github(organization:)` looks up a per-organization secret only when the app is configured in multi-tenant mode (`github_default_organization` present); otherwise it silently ignores the argument: [4](#0-3) 

Once the signature check passes, `WebhooksController#create` dispatches the full, attacker-supplied payload to the matching handlers: [5](#0-4) 

Every handler resolves the affected repository from a *different* field, `repository.full_name`, via `Handler#repository_name`/`#stacks`: [6](#0-5) 

For example, `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for every non-archived stack matching the branch of that repository, and `StatusHandler` writes a `Commit` status (used as a CI gate for deploys) for any commit with the given SHA, independent of which repository the signature was verified against: [7](#0-6) [8](#0-7) 

The broken binding is:
`organization whose secret authenticated the request` (`repository.owner.login`) `≠` `repository/stack that the handler mutates` (`repository.full_name`).

Before the attacker's request: only requests carrying a valid HMAC for organization X's configured secret can affect data belonging to organization X's repositories.
After a crafted request: an entity that legitimately knows organization X's own webhook secret (they administer the GitHub App that produced it, which is not a privileged Shipit credential) sets `repository.owner.login = "X"` to select the verifying secret, but sets `repository.full_name = "Y/target-repo"` (any other tracked repository, e.g. organization Y) so that the handler acts on Y's stacks/commits — a cross-repository/cross-organization write that the HMAC binding was supposed to prevent.

### Impact Explanation
This breaks a cross-repository trust boundary explicitly called Critical in scope: "cross-repository writes" / "unauthorized deploy". A `status` event lets the attacker inject a fake `success` `Commit` status for any SHA belonging to an unrelated repository/organization tracked by the same Shipit instance, which is used to satisfy CI-required checks and can unblock/trigger an unauthorized deploy of that unrelated stack. A `push` event lets them force `sync_github` against another organization's stacks. This is reachable by an unprivileged party relative to the *target* organization — they only need control over the webhook secret of some *other* organization already onboarded to the same multi-tenant Shipit instance, not any Shipit session, API token, or the target org's GitHub credentials.

### Likelihood Explanation
This only applies to multi-tenant Shipit deployments configured with the `github_organizations`/per-org secrets schema (`Shipit.github_app_config`), which the engine explicitly supports. In that configuration, any onboarded low-trust organization administrator, who legitimately possesses their own GitHub App's webhook secret, can immediately construct a valid HTTP request without any additional access — likelihood is high for that deployment shape and zero for the (also supported) single-tenant/global-secret shape, since in that mode the same single secret is used for verification regardless of the field's value, making the fields consistent by construction.

### Recommendation
After verifying the HMAC, re-derive the organization from `repository.full_name` (or `organization.login` for org-scoped events) and confirm it matches the organization whose secret validated the signature (i.e., `repository_owner` used for `Shipit.github(organization:)` must equal the owner segment of `repository.full_name` that handlers will use). Reject the webhook with 422 if they diverge, in both `WebhooksController#verify_signature` and centrally inside `Handler#repository_name`/`#stacks` as a defense-in-depth check.

### Proof of Concept
1. Shipit instance is configured in multi-tenant mode with per-organization webhook secrets, e.g. organizations `orgA` and `orgB` are both onboarded (`Shipit.github_organizations` includes both), each with their own GitHub App and webhook secret (`lib/shipit.rb:190-200`).
2. Attacker administers `orgA`'s own GitHub App and therefore knows `orgA`'s webhook secret (this is not a Shipit credential — it belongs to their own org's GitHub App settings).
3. Attacker crafts a `status` webhook JSON body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" },
  "sha": "<sha belonging to an orgB commit>",
  "state": "success"
}
```
4. Attacker computes `X-Hub-Signature` using `orgA`'s known webhook secret over this exact raw body, matching `Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`).
5. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, loads `orgA`'s `GitHubApp`, and successfully verifies the signature against `orgA`'s secret (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `create` dispatches the payload to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — a commit that actually belongs to `orgB/target-repo` — and calls `create_status_from_github!`, writing a forged `success` status for organization B's commit despite the request being authenticated only against organization A's secret (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`).

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
