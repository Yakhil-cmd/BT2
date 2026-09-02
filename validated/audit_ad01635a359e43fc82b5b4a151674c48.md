### Title
Cross-organization webhook forgery via mismatched signature-verification scope and payload-processing scope - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
Shipit supports multi-tenant configuration where each GitHub organization has its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to verify the incoming HMAC signature against using `repository_owner`, taken from the untrusted JSON body itself (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`) [2](#0-1) [3](#0-2) . Once the signature is accepted, every event handler (e.g. `PushHandler`) resolves which `Repository`/`Stack` to act on using a *different* field from that same payload, `payload.dig('repository', 'full_name')`, via `Handler#repository_name`/`#stacks` [4](#0-3) [5](#0-4) .

### Finding Description
The equality this engine relies on is: `organization whose secret authenticated the request == organization owning the repository the handler writes to`. Nothing in the code enforces that binding; the two lookups read independent JSON keys from the same attacker-controlled raw body:

- Verification key: `repository.owner.login` (or `organization.login`) → selects `GitHubApp` config/secret via `Shipit.github(organization: repository_owner)` [6](#0-5) .
- Processing key: `repository.full_name` → selects the `Repository`/`Stack` that is mutated by the handler [7](#0-6) .

`HMAC-SHA1` covers the raw POST body, so an attacker cannot forge a signature for an organization whose secret they do not know. However, in a multi-org deployment, an attacker who legitimately controls (or can configure a webhook against) one onboarded organization, call it `orgA`, knows `orgA`'s `webhook_secret` (they can extract it from their own repo's configured webhook delivery mechanism, or it may be provisioned to org owners as part of the GitHub App installation flow). Nothing stops that attacker from crafting a custom payload where `repository.owner.login` (and `organization.login`) is set to `"orgA"` — so `verify_signature` computes the HMAC using `orgA`'s secret, which validates — while `repository.full_name` is set to `"orgB/some-repo"`, a repository that belongs to a completely different, unrelated organization `orgB` tracked by the same Shipit instance. `Handler#stacks` will resolve `orgB`'s real `Stack` and the handler will act on it (e.g. `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` [8](#0-7) ), even though the request was never authenticated with `orgB`'s secret.

### Impact Explanation
This crosses the "organization that authenticated vs. repository that is written" trust boundary explicitly called out for this bug class. Depending on which webhook event/handler is targeted, an attacker holding only one organization's webhook secret could trigger unauthorized state changes on stacks belonging to a different organization inside the same Shipit installation — e.g. forcing a `push` event that triggers `GithubSyncJob` (potentially advancing `undeployed_commits`/deploy candidates), forging `status`/`check_suite` events that flip commit statuses used for deployability decisions, or manipulating pull_request-driven review-stack provisioning/archival for `orgB`'s repositories. These are cross-tenant, cross-repository writes achieved without possessing the victim organization's credentials.

### Likelihood Explanation
Exploitability is gated on the attacker already possessing a valid `webhook_secret` for at least one organization configured in the same multi-tenant Shipit deployment — this is realistic in shared/multi-tenant deployments where different teams or orgs configure their own GitHub App/webhook secrets independently but are hosted on one Shipit instance, since nothing in the webhook path pins the verified secret's organization to the target repository's actual owner.

### Recommendation
After computing `verified`, additionally assert that the organization/owner used to select the signing secret actually matches (or is a permitted owner of) the repository named in `payload.dig('repository', 'full_name')` before dispatching to handlers — i.e., derive `repository_owner` from `full_name`'s prefix (or cross-check `full_name.split('/').first == repository_owner`), rejecting mismatches with a 422, rather than trusting `owner.login`/`organization.login` and `full_name` as independent, unverified inputs.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret`, per `lib/shipit.rb#github_app_config` [9](#0-8) .
2. As an actor with legitimate access to `orgA`'s webhook secret, craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(orgA_webhook_secret, body)>` and POST to the webhooks endpoint.
4. `verify_signature` resolves `Shipit.github(organization: "orgA")` and validates successfully [10](#0-9) .
5. `PushHandler` is invoked with the same payload; `Handler#repository_name` returns `"orgB/target-repo"`, resolving `orgB`'s real stacks and triggering `stack.sync_github` on them [4](#0-3) [8](#0-7) , despite the request never being authenticated with `orgB`'s secret.

Note: I could not fully verify from the indexed code whether any additional cross-check exists elsewhere in the request pipeline (e.g. in `Shipit::Webhooks.for_event`) that might constrain this before dispatch; a full review with direct file access (e.g. via a Devin session) would be needed to confirm there is no such mitigating check outside the indexed snippets.

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
