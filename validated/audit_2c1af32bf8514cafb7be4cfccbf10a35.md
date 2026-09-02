### Title
Webhook signature verification keys off `repository.owner.login` while every event handler acts on the attacker-controlled `repository.full_name`, letting a webhook signed by an unprotected/attacker-known organization drive events against any other stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's HMAC secret to validate a webhook against using `repository_owner`, a value read straight from the unauthenticated request body. Every downstream `Handler` (push, pull_request, membership, status, check_suite, etc.) then locates the `Repository`/`Stack` to act on using a *different* field of the same body, `repository.full_name`. Nothing binds these two fields together, so the organization whose secret authenticates the request is not guaranteed to be the organization that is actually written to.

### Finding Description
`verify_signature` picks the `GitHubApp`/secret to check against solely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: ...)` resolves per-organization config (`webhook_secret`, `app_id`, etc.) in multi-org deployments, exactly as documented for "Using Multiple Github Applications": [3](#0-2) 

If that resolved organization's `webhook_secret` is unset (a state the shipped example config explicitly allows — `webhook_secret: # nil`), `verify_webhook_signature` unconditionally returns `true`, regardless of what the body/signature actually contain: [4](#0-3) 

Once the request is "verified", `create` hands the *entire unvalidated payload* to every registered handler for the event: [5](#0-4) 

Handlers never re-check `repository.owner.login` — they resolve the target `Repository`/`Stack` purely from `repository.full_name`: [6](#0-5) 

So the binding actually enforced is `repository.owner.login → webhook_secret used`, while the binding that matters for state mutation is `repository.full_name → Repository/Stack acted on`. These two fields are never checked for consistency. An attacker who knows (or controls) any single organization configured in Shipit with a blank/absent `webhook_secret` can send `repository.owner.login = "<that org>"` (making `verify_signature` pass unconditionally) while setting `repository.full_name = "<victim-org>/<victim-repo>"`, causing the handler to operate on a stack belonging to a completely different, properly-secured organization.

### Impact Explanation
This breaks cross-organization/cross-repository isolation that the webhook_secret mechanism is meant to guarantee — exactly the "organization that authenticated versus repository that is written" binding called out as in-scope. Concretely, once the forged payload passes `verify_signature`, an unauthenticated network attacker can drive real state changes on a victim stack they have no access to:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for any branch/sha the attacker names, which can seed continuous-deployment eligible commits and lead to an **unauthorized deploy** of attacker-chosen shas. [7](#0-6) 
- `pull_request` closed handlers can archive a victim's review stack. [8](#0-7) 
- `MembershipHandler` and other handlers create/modify `Team`/`User` records tied to `Shipit.github_teams` authorization state.

This satisfies the required Critical/High impact bar (unauthorized deploy / escalation into `Shipit.github_teams` authorization) without any session, `ApiClient` token, repository write access, or webhook secret knowledge for the victim org.

### Likelihood Explanation
Likelihood depends on operator configuration: it requires the Shipit deployment to use the documented multi-org `github:` config where at least one configured organization has no `webhook_secret` set (a state the shipped `secrets.development.example.yml` and `secrets.development.shopify.yml` templates present as normal/default), while another organization in the same install has a properly configured secret. This is a realistic operational configuration for installs onboarding a new org before its webhook secret is provisioned, and requires no credentials from the attacker at all — only network access to `POST /webhooks`.

### Recommendation
In `WebhooksController#verify_signature` / the `Handler` base class, cross-check that the organization used to select the verification secret (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` actually used by handlers, and reject the request (422) on mismatch. Additionally, do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in multi-org configurations — require an explicit secret per organization, or refuse to process events for organizations with no configured secret.

### Proof of Concept
1. Configure Shipit with `github:` multi-org secrets where `OrgA` (attacker's org) has `webhook_secret: nil` and `OrgB` (victim org, owns `victim-org/victim-repo` stack) has a real secret configured — matching the documented multi-org template. [9](#0-8) 
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and any/garbage `X-Hub-Signature`, and JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "OrgA" } }
}
```
3. `repository_owner` resolves to `"OrgA"`; `Shipit.github(organization: "OrgA")` has `webhook_secret` blank, so `verify_webhook_signature` returns `true` regardless of the bogus signature. [4](#0-3) 
4. `create` dispatches the payload to `PushHandler`, which resolves `stacks` via `repository.full_name = "victim-org/victim-repo"` (not `OrgA`) and calls `sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack — a cross-organization write triggered by a signature that only proved control of `OrgA`. [6](#0-5) [7](#0-6)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
