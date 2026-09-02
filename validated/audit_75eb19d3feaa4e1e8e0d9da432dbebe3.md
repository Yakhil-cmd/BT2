## Title
Cross-organization webhook forgery via mismatched authentication/target repository fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub app (and thus the `webhook_secret` used for HMAC verification) using `repository_owner`, which is read from the top-level `repository.owner.login` (or `organization.login`) field of the **unauthenticated** JSON body. [1](#0-0)  Every downstream `Handler`, however, resolves the actual `Stack`/`Repository` to act on using a *different* field of the same payload: `repository.full_name`. [2](#0-1)  Because these two fields are never cross-checked, an attacker can pick which organization's key is used to "authenticate" the request independently of which organization's stack the request actually mutates.

### Finding Description
Shipit supports multiple GitHub App configurations, one per organization, each with its own `webhook_secret`. [3](#0-2)  `Shipit.github(organization:)` looks up the config for the named org and builds a `GitHubApp` for it. [4](#0-3)  Crucially, `GitHubApp#verify_webhook_signature` has a bypass: `return true unless webhook_secret`. [5](#0-4)  Any organization configured without a `webhook_secret` (a supported, documented configuration, see the commented-out `webhook_secret: # nil` examples in `secrets.development.example.yml` and `secrets.development.shopify.yml`) trivially satisfies signature verification for *any* body/signature pair. [6](#0-5) 

The controller picks which org's app (and secret) to use for verification purely from attacker-controlled JSON:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [7](#0-6) 

After `verify_signature` passes, `create` dispatches the *whole* parsed payload to handlers. [8](#0-7)  Handlers ignore `repository.owner.login` entirely and instead resolve the target stack from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

This is the same class of defect as CVE-2019-11043: a field that a security check assumes/derives one value from (`PATH_INFO`/`repository.owner.login`) can be set independently of the field actually consumed downstream (the write pointer computation/`repository.full_name`), because the two are never bound together. Here the broken equality is:
`organization used to select verifying webhook_secret` ⧣ `organization owning the repository actually written to`.

Concretely, if Shipit is configured with two orgs — `OrgWithSecret` (has a `webhook_secret`) and `OrgNoSecret` (no `webhook_secret`, e.g. freshly added, or an org deliberately left unconfigured) — an attacker with no credentials can POST to `/github/webhooks` a body such as:
```json
{
  "repository": { "owner": { "login": "OrgNoSecret" }, "full_name": "OrgWithSecret/target-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
with header `X-Github-Event: push` and an arbitrary/garbage `X-Hub-Signature`. `verify_signature` resolves `Shipit.github(organization: "OrgNoSecret")`, whose `verify_webhook_signature` returns `true` unconditionally because that org's `webhook_secret` is blank — regardless of the actual signature. The request is accepted, and `PushHandler` then looks up stacks for `OrgWithSecret/target-repo` and runs `stack.sync_github(expected_head_sha: ...)` against `OrgWithSecret`'s protected stack. [9](#0-8) 

### Impact Explanation
This allows an unprivileged, unauthenticated network attacker to forge webhook events for a completely different (and properly-secured) organization's repositories, as long as *any* org known to the Shipit instance lacks a webhook secret. Depending on which event/handler is abused this can:
- Force out-of-band GitHub syncs (`push`) against a target org's stack.
- Forge `status`/`check_suite` events, potentially manipulating the commit statuses Shipit uses to gate `deployable?`/CI requirements (`ci.require`), which can enable an unauthorized deploy on the target repository — matching the "Critical: unauthorized deploy" bucket in scope.
- Forge `membership`/`pull_request` events affecting `Team`/`Membership`/`ReviewStack` records tied to the target org.

This is a genuine authentication-bypass / cross-repository-write class issue: the request never had valid proof of possession of the target org's `webhook_secret`, yet it is allowed to mutate the target org's state.

### Likelihood Explanation
Exploitability strictly depends on the deployment having at least one configured GitHub organization with a blank/absent `webhook_secret` while other organizations are properly secured — a configuration explicitly documented and shown as valid in `config/secrets.development.shopify.yml` and the multi-org example in `docs/setup.md`. In such (not uncommon, e.g. staging/newly-onboarded org) multi-tenant setups, exploitation requires zero credentials and a single crafted HTTP POST, making likelihood High whenever the precondition holds. If every configured org has a non-blank secret, this specific analog is not exploitable, but the missing binding between the auth-selection field and the target field is a structural weakness regardless.

### Recommendation
Bind webhook signature verification to the same repository/organization that will actually be acted upon:
- Verify the signature against the org derived from `repository.full_name` (i.e., the actual owning org of the target repository), not a separately-trusted `repository.owner.login`/`organization.login` field.
- Alternatively/also, require and enforce that every configured GitHub organization has a non-blank `webhook_secret` (remove the `return true unless webhook_secret` bypass, or make it opt-in with an explicit, loudly-logged flag), so that a single unsecured org config cannot be used as a skeleton key for others.
- Reject webhooks where `repository.owner.login`/`organization.login` and the owner segment of `repository.full_name` disagree.

### Proof of Concept
Preconditions: multi-org Shipit config with `OrgNoSecret` (no `webhook_secret`) and `OrgWithSecret` (has `webhook_secret`), each with at least one stack.

```
POST /github/webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=deadbeef

{
  "repository": {
    "owner": { "login": "OrgNoSecret" },
    "full_name": "OrgWithSecret/target-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-of-target-repo>"
}
```
- `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgNoSecret")` and `verify_webhook_signature` returns `true` unconditionally (no secret configured), so the request is accepted (no 422).
- `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgWithSecret/target-repo")` and triggers `stack.sync_github(expected_head_sha: ...)` on the target org's stack — despite the request never being validated against `OrgWithSecret`'s secret.

Note: I could not fully inspect `app/models/shipit/webhooks/handlers/status_handler.rb` and `check_suite_handler.rb` within the tool-call budget to confirm the exact downstream effect on `deployable?`/CI gating; this is called out as an unverified extension of impact and should be confirmed by a background agent with full repository access.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
