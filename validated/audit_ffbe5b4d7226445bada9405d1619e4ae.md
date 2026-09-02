Based on my investigation, this repository's webhook trust model contains a binding break analogous to the reported issue: a payload field is used to select the cryptographic secret that authenticates a request, but a *different* payload field is used to determine which resource (repository/stack) the request acts upon, and the two are never cross-checked.

### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but events act on the repository named in `repository.full_name` with no cross-check - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate an inbound webhook using `repository_owner`, which is read straight out of the (not-yet-verified) JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0) [2](#0-1) 

Every event handler, however, resolves the target `Stack`(s) using an entirely different field of the same body, `repository.full_name`, via `Handler#repository_name`/`#stacks`. [3](#0-2) 

In the documented "multiple GitHub Applications" deployment mode, each organization gets its own `webhook_secret` looked up by `Shipit.github(organization: repository_owner)` / `Shipit.github_app_config`. [4](#0-3) 

### Finding Description
The equality that should hold is: `organization whose secret authenticated the request == organization that owns the repository the handler acts on`. Nothing in `verify_signature` or in `Handler#stacks` enforces this. The signature check only proves "this body was HMAC-signed with OrgA's `webhook_secret`"; it says nothing about which `repository.full_name` value appears inside that signed body. Since `repository.owner.login` and `repository.full_name` are two independent JSON keys that a legitimate GitHub webhook for OrgA would always keep consistent, but which the shipit-engine code never cross-validates, any party who can produce a validly-signed body for OrgA (e.g., an OrgA admin who configured `webhook_secret` on their own GitHub App, or anyone who obtains OrgA's secret through any means short of full server compromise) can set `repository.owner.login` to `"OrgA"` (so the correct, weaker secret is used for verification) while setting `repository.full_name` to `"OrgB/some-repo"` so the event is dispatched against a stack that belongs to a completely different, unrelated organization/tenant hosted on the same shipit-engine instance. [5](#0-4) [6](#0-5) 

This is structurally the same bug class as the report: `addPool` trusted the `_gauge` argument was consistent with the pool/token it was paired with and never verified that binding, letting the caller supply an address that satisfies the "found" check but is unrelated/degenerate. Here, `verify_signature` trusts that `repository.owner.login` (used to pick the secret) is consistent with `repository.full_name` (used to pick the acted-upon repository), and never verifies that binding either.

### Impact Explanation
Cross-repository/cross-organization writes are possible: an attacker who controls OrgA's webhook secret can trigger `push`/`status`/`check_suite`/`pull_request`/`membership` handling for `Stack`s that belong to OrgB. Depending on handler, this can enqueue `GithubSyncJob`/`RefreshCheckRunsJob`, create/delete `Team`/`Membership` records, or mutate `PullRequest`/`ReviewStack` state (archive/unarchive, provisioning) for a repository the attacker does not own or have any legitimate relationship to - this matches the "cross-repository writes" Critical impact category.

### Likelihood Explanation
Exploitation requires the attacker to already possess a valid `webhook_secret` for *some* organization configured on the instance (their own, in the documented multi-organization setup). This is lower privilege than a Shipit `ApiClient` token or a GitHub App private key, and is exactly the kind of "org admin configures their own webhook_secret" scenario the multi-tenant configuration in `docs/setup.md` and `lib/shipit.rb#github_app_config` explicitly supports. Because the mismatch is never checked, likelihood is high once any one org's secret is known to the attacker.

### Recommendation
In `Handler#stacks`, verify that the resolved repository's owner matches the organization whose secret authenticated the request (i.e., compare `repository_name`'s owner segment against the `organization`/`repository.owner.login` value that `WebhooksController#verify_signature` used), and reject the event if they differ. Alternatively, pass the verified organization down into each handler and scope `Repository.from_github_repo_name` lookups to that organization.

### Proof of Concept
1. Configure shipit-engine in multi-org mode with `OrgA` and `OrgB` both onboarded (`lib/shipit.rb#github_app_config`).
2. As the administrator of the OrgA GitHub App, obtain/know OrgA's `webhook_secret` (self-configured, not privileged relative to Shipit).
3. Craft a JSON body for a `push` event where `repository.owner.login == "OrgA"` (or `organization.login == "OrgA"`) but `repository.full_name == "OrgB/target-repo"`.
4. Sign the raw body with OrgA's `webhook_secret` and send it to `POST /webhooks` with header `X-Github-Event: push` and the resulting `X-Hub-Signature`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature. [1](#0-0) 
6. `PushHandler`/`Handler#stacks` resolves stacks via `repository.full_name` = `"OrgB/target-repo"`, and the event is processed against OrgB's stack even though verification never validated anything about OrgB. [3](#0-2) 

Note: I was not able to fully inspect `push_handler.rb` and `membership_handler.rb` contents in this session (only grep match locations, not full file bodies, were returned before the iteration budget ended), so the exact side effects per handler (e.g., precisely which fields of `Stack`/`Team` get mutated) should be re-verified by reading those files directly before treating the PoC as fully validated.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-42)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class Handler
        class << self
          attr_reader :param_parser

          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
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
