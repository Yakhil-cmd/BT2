### Title
Webhook signature check authenticates the payload's claimed organization but not the repository handlers actually write to - cross-tenant forged webhook events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a webhook against based on `repository_owner`, a value read directly out of the *unauthenticated* JSON payload (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1)  In a multi-organization Shipit deployment (`Shipit.github(organization:)` supports a keyed `github:` config per org, as documented in `config/secrets.development.shopify.yml`), each org has its own independent `webhook_secret`. [3](#0-2)  Because the signature is only checked against whichever org's secret matches the attacker-controlled `repository_owner` field of the same payload, an attacker who legitimately controls a webhook for **one** organization configured on the Shipit instance (org A, and thus knows org A's `webhook_secret`) can sign a completely different, self-authored payload whose `repository.full_name` (used later by handlers such as `PushHandler`) targets a repository/stack belonging to a different, unrelated organization (org B) also hosted on the same Shipit instance.

### Finding Description
The equality that should hold is:

`organization whose webhook_secret authenticated the request == organization that owns the repository the handler acts on`

`verify_signature` breaks this by deriving the "authenticating organization" from an unauthenticated field inside the very payload being verified, then handing the *entire* unauthenticated JSON (re-parsed via `JSON.parse(request.raw_post)`) to the handler pipeline in `create`. [4](#0-3)  The signature itself only proves "this byte stream was HMAC-signed with *some* configured org's secret" — it does not prove that the org whose secret was used is actually the owner of the `repository.full_name` referenced inside that same byte stream, because the attacker fully controls all fields of the payload before signing it. `Shipit::Webhooks.for_event('push')` dispatches to `Handlers::PushHandler`, which locates and mutates `Stack` records purely by `branch`/`ref` scoped to `stacks` resolved from the (attacker-supplied) repository context, with no re-check that the repository belongs to the org that supplied the valid signature. [5](#0-4) 

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding explicitly called out in scope. An attacker who is a legitimate (even low-privilege) webhook operator for one tenant org configured on a shared Shipit instance can forge push/pull_request/status/check_suite/membership events for stacks belonging to a completely different tenant org they have no access to, since `verify_signature` never re-validates that the authenticating org and the acted-upon repository's org are the same. Depending on the handler this can trigger unauthorized `GithubSyncJob` runs, fabricate commit `status`/`check_suite` results that gate deploy/merge decisions, or fabricate `membership`/team changes — i.e., cross-repository/cross-tenant writes and potential unauthorized deploy gating, matching the High/Critical "cross-repository writes" impact class.

### Likelihood Explanation
Requires the attacker to control (or be able to trigger) a webhook delivery for one org configured in the same Shipit deployment (`secrets.github` multi-org schema), which is a realistic multi-tenant setup shown in `config/secrets.development.shopify.yml`. No GitHub App private key, `ApiClient` token, or Shipit session is needed — only knowledge of/ability to trigger delivery under one tenant's already-configured `webhook_secret`, then crafting a raw POST with a `repository.full_name`/`repository.owner.login` mismatch.

### Recommendation
After computing `repository_owner` for signature selection, re-validate that the `repository.full_name`'s owner matches `repository_owner`/the org whose secret validated the signature before dispatching to handlers; alternatively, resolve the target `Stack`/`Repository` first and verify the signature using the secret tied to *that* repository's actual configured organization rather than a value taken from the unauthenticated payload.

### Proof of Concept
1. Configure Shipit with two orgs, `org-a` and `org-b`, each with distinct `webhook_secret` values (as in `config/secrets.development.shopify.yml`). [6](#0-5) 
2. As an attacker with legitimate webhook access to `org-a` (knows `org-a`'s `webhook_secret`), craft a `push` event JSON body where `repository.owner.login = "org-a"` (so `verify_signature` selects `org-a`'s secret) but `repository.full_name = "org-b/target-repo"` and `ref`/`after` point at a stack belonging to `org-b`.
3. Sign the raw body with `org-a`'s `webhook_secret` using `sha1=` HMAC and send it to `POST /github/webhooks` with `X-Hub-Signature` and `X-Github-Event: push`.
4. `verify_signature` passes because the signature matches `org-a`'s secret and `repository_owner` in the payload is `org-a`. [1](#0-0) 
5. `create` re-parses the raw body and dispatches to `PushHandler`, which acts on stacks matching the attacker-chosen `branch`/repo context under `org-b`, even though only `org-a`'s secret was proven valid. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
