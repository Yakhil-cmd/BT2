### Title
Webhook signature verification is bound to a payload-controlled `repository_owner`, not to the repository the handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read directly from the unauthenticated JSON body. The event handlers, however, resolve the `Stack`/`Repository` to mutate using a *different* field of the same body, `repository.full_name`. Nothing ties these two fields together, so a request that is correctly signed for organization A can still be routed to act on a repository belonging to organization B, in multi-organization Shipit deployments.

### Finding Description
`verify_signature` derives the signing organization purely from attacker-controlled JSON, then verifies the raw body against that organization's secret: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` just does an HMAC compare against whatever `webhook_secret` was configured for the organization that was looked up: [3](#0-2) 

Multi-organization installations configure a distinct `webhook_secret` per organization key, and `Shipit.github(organization:)` picks the app/secret purely from that string: [4](#0-3) 

After the signature check passes, `Shipit::Webhooks.for_event(event)` handlers are invoked with the *same* raw JSON body, and every handler resolves its target stacks from `repository.full_name`, independent of `repository.owner.login`/`organization.login` used for signature selection: [5](#0-4) 

For example, `PushHandler` uses that repository-name-derived `stacks` scope to trigger a real sync/deploy pipeline action (`stack.sync_github`) using attacker-chosen `ref`/`after` values: [6](#0-5) 

The equality that should hold but is broken is:
`organization authenticated by verify_signature (repository_owner field)` == `organization/repository the handler mutates (repository.full_name field)`

Because both fields are independently attacker-supplied in the same unauthenticated JSON body, and only one of them is covered by the signature check that selects *which* secret to compare against (not that the two fields agree), an attacker who legitimately possesses the `webhook_secret` for **any one** configured organization in the deployment can sign a payload where `repository.owner.login`/`organization.login` = their own org (so `verify_signature` picks and validates against a secret they know) while `repository.full_name` names a stack/repository under an entirely different, unrelated organization also hosted on the same Shipit instance. That forged, signature-passing event is then dispatched to handlers (`push`, `pull_request`, `commit_status`, `deployable_status`, `merge_status`, `merge`, `membership`, etc., per the `EVENTS` list) which act on the victim organization's stacks: [7](#0-6) 

### Impact Explanation
This is a cross-organization authentication-boundary break: possessing a valid webhook credential for organization A is sufficient to inject spoofed, "verified" GitHub events for repositories/stacks belonging to organization B in the same Shipit deployment. Depending on which handler is targeted, this can drive real state changes on a stack the attacker does not own — e.g. forcing `GithubSyncJob` to run against arbitrary stacks via `PushHandler`, or feeding forged `pull_request`/`commit_status`/`deployable_status`/`merge_status` events into handlers that influence merge/deploy readiness state for another organization's stacks. This falls under the "unauthorized deploy/merge" / cross-repository-write class of impact called out in the rules, since the effective authorization boundary between organizations in a multi-org Shipit setup is not enforced end-to-end.

### Likelihood Explanation
Requires the attacker to hold a legitimate `webhook_secret` for at least one organization configured in a multi-organization Shipit deployment (e.g., they administer their own org's GitHub App pointed at the shared instance), which is a realistic, low-privilege precondition in shared/multi-tenant Shipit setups. No access to any other organization's secret, `GITHUB_TOKEN`, session, or `ApiClient` token is needed. Likelihood is moderate: it only applies to deployments using the multi-organization `github:` config schema, not the single-app schema.

### Recommendation
In `WebhooksController#verify_signature`, after determining the organization from `repository_owner`/`organization.login`, cross-check that this organization actually owns the repository named in `repository.full_name` (or, more robustly, derive the signing organization from the resolved `Repository`/`Stack` record rather than trusting the raw payload field), rejecting the webhook if they disagree — mirroring how `LenderActions.removeQuoteToken()` was hardened to check the state it actually mutates (`Deposits.treeSum`) rather than trusting an unchecked intermediate.

### Proof of Concept
1. Deployment configures two organizations, `orgA` and `orgB`, each with its own `webhook_secret` under `secrets.github`.
2. Attacker legitimately controls `orgA`'s GitHub App/webhook and thus knows `orgA`'s `webhook_secret`.
3. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "orgB/victim-repo", "owner": { "login": "orgA" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_secret, body)` and sends it with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner` as `"orgA"` (from `params.dig('repository','owner','login')`), fetches `orgA`'s `GitHubApp`, and the HMAC verifies successfully.
6. `Shipit::Webhooks.for_event('push')` handlers run with the same body; `PushHandler`/`Handler#stacks` resolves stacks via `repository.full_name` = `"orgB/victim-repo"`, and `stack.sync_github` is invoked for a stack the attacker has no relationship with, purely on the strength of a secret belonging to an unrelated organization.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
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

**File:** app/models/shipit/hook.rb (L70-82)
```ruby
    EVENTS = %w[
      stack
      review_stack
      task
      deploy
      rollback
      lock
      commit_status
      deployable_status
      merge_status
      merge
      pull_request
    ].freeze
```
