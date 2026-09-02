### Title
Webhook signature verification key is selected from a payload field (`repository.owner.login`/`organization.login`) that is never cross-checked against the field actually used to select the target repository/stack (`repository.full_name`) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/secret to validate the inbound webhook against based on `repository.owner.login` (or `organization.login`) read straight out of the unauthenticated JSON body, then hands the whole body to per-event `Handler` subclasses which resolve the actual `Repository`/`Stack` to act on using a *different* field of the same body: `repository.full_name`. Nothing binds these two fields together, so a valid HMAC computed with one organization's `webhook_secret` can carry a `repository.full_name` belonging to a completely different, unrelated organization/repository configured on the same Shipit instance.

### Finding Description
`verify_signature` derives the verification key from a self-declared, unauthenticated field of the payload and never checks it against the field the rest of the pipeline actually acts on: [1](#0-0) [2](#0-1) 

`repository_owner` is used solely to pick `Shipit.github(organization: repository_owner)`, i.e. which of the (potentially multiple) configured GitHub Apps' `webhook_secret` is used to validate `X-Hub-Signature`: [3](#0-2) [4](#0-3) 

This multi-organization configuration, where each org has its own distinct `webhook_secret`, is a first-class, documented deployment mode: [5](#0-4) 

Once the HMAC check passes for whichever organization `repository_owner` names, the raw parsed JSON is dispatched unchanged to the event handlers. Every handler resolves its target repository/stack from `repository.full_name`, a **different** JSON field that was never compared to `repository_owner`: [6](#0-5) [7](#0-6) 

Binding that should hold but does not:
`organization_whose_secret_validated_signature(repository.owner.login) == organization_of(repository.full_name_used_by_handler)`

Before the request reaches `create`, only the signature over the raw bytes is checked; the byte-for-byte content is otherwise fully attacker-controlled, including which two fields agree with each other.

### Impact Explanation
An operator running Shipit for multiple GitHub organizations (as explicitly supported by the multi-org secrets schema) gives every organization owner/administrator on the instance a legitimate `webhook_secret` for *their own* org. Because `verify_signature` only proves "this body was signed by the org named in `repository.owner.login`" and never proves "the `repository.full_name` this body claims to act on belongs to that same org," any org owner (an unprivileged party with respect to every *other* org on the shared Shipit instance) can:

1. Compute a valid `X-Hub-Signature` using their own org's `webhook_secret`.
2. Set `repository.owner.login` to their own org (so `verify_signature` picks their own secret and passes) while setting `repository.full_name` to `victim-org/target-repo`.
3. Have the `push` handler run `stack.sync_github(expected_head_sha: params.after)` against the victim org's stacks, or trigger `status`/`check_suite`/`membership` handling for a repo/org they do not control.

This crosses the "organization that authenticated versus the repository that is written" boundary called out in scope, and can manifest as unauthorized state changes on stacks belonging to a different, unrelated organization on the same Shipit deployment (e.g. forged sync/status/check-run updates that influence deploy/merge gating for a victim repository) without the attacker ever possessing the victim organization's credentials.

### Likelihood Explanation
Likelihood is limited to deployments that configure more than one GitHub organization (the documented multi-org schema), and requires the attacker to be an admin of at least one of the configured GitHub Apps in order to have a legitimate `webhook_secret` — but critically not the victim org's secret. Given multi-tenant Shipit installations are an explicitly supported and documented configuration, and the mismatch is unconditional (no code path cross-validates the two fields), exploitation is straightforward once an attacker has any one org's secret on the shared instance.

### Recommendation
In `WebhooksController#verify_signature` / `Shipit::Webhooks::Handlers::Handler`, after signature verification succeeds, re-derive `repository.owner.login`/`organization.login` again from the payload and assert it matches the owner segment of `repository.full_name` before dispatching to any handler; reject the webhook (422) on mismatch. Alternatively, bind the handler's `Repository`/`Stack` resolution to the same organization identifier that selected the verification key, rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `config/secrets.development.shopify.yml`), both with stacks tracked in Shipit.
2. As the (unprivileged w.r.t. `OrgB`) owner of `OrgA`'s GitHub App, craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=HMAC_SHA1(OrgA_webhook_secret, body)` and POST to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "OrgA")` (from `repository.owner.login`), verifies the signature successfully against `OrgA`'s secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: <attacker-chosen sha>)` on stacks belonging to `OrgB`, despite the attacker never possessing `OrgB`'s webhook secret.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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
