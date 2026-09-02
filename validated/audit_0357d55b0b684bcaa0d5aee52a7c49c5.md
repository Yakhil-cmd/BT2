### Title
Webhook organization used to select the signing secret is not bound to the repository/commit actually mutated - unauthenticated commit-status forgery and team-membership tampering - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `theshr` bug is a case where the value used to *derive* a security-relevant quantity (the shift amount) is taken from the wrong side of an expression, so the derived value ends up wrong and a downstream invariant (non-zero balance requirement) silently breaks. The same class of bug exists in `WebhooksController`: the *organization used to select which HMAC secret verifies the request* is read from the still-unverified JSON body, and once verification (trivially) succeeds, downstream handlers act on a *different* field of that same attacker-controlled body (or, in `StatusHandler`, on no repository field at all) to decide what gets mutated. The value that is "verified" and the value that is "acted upon" are never checked for equality.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the webhook secret) using a field pulled straight out of the unauthenticated request body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization config, and `webhook_secret` is documented as optional (defaults to `nil`): [3](#0-2) [4](#0-3) 

`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no secret is configured for the resolved organization: [5](#0-4) 

Once `verify_signature` passes, the *entire* raw payload is dispatched to handlers, which independently pick whatever repository/commit-identifying field they want, with no requirement that it match the organization that was used to authenticate the request: [6](#0-5) [7](#0-6) 

`StatusHandler` is the worst case: it doesn't even look at `repository_name`/`stacks` — it updates **every** `Commit` row across the whole instance whose `sha` matches the attacker-supplied value, regardless of which repository/organization it belongs to: [8](#0-7) 

`MembershipHandler` similarly creates/updates `Team` records and adds/removes members purely from payload content, gated only by the signature check on whichever organization the attacker names in the same payload: [9](#0-8) 

Equality broken: `organization used to authenticate the webhook request` == `organization/repository/commit that the handler actually mutates`. Neither the controller nor the handlers enforce this equality; the org used for auth-secret lookup and the entity mutated are two independently attacker-controlled reads of the same untrusted JSON body.

### Impact Explanation
In any Shipit deployment using the documented multi-organization `github:` config schema (`docs/setup.md`/`config/secrets.development.example.yml` both show `webhook_secret` as optional/nil per org), an unauthenticated attacker can:
- Send a forged webhook body where `repository.owner.login`/`organization.login` names an organization that has no `webhook_secret` configured (verification short-circuits to `true`), while other fields (`sha`, `repository.full_name`, `team`/`member` in the membership payload) target a victim stack/commit/team belonging to a completely different, properly-configured organization.
- Via `StatusHandler`, set an arbitrary commit's CI status to `success` for any repository in the instance (status handler is not repository-scoped at all), defeating `required_statuses`/`blocking_statuses` deployability checks in `DeploySpec`, enabling deployment of a commit that never actually passed CI — an unauthorized deploy.
- Via `MembershipHandler`, add an attacker-controlled GitHub login to a `Team` that is part of `Shipit.github_teams`, escalating into the application's authorization system (`User#authorized?`).

Both outcomes match the in-scope Critical/High impact bar ("unauthorized deploy" and "escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Requires: (1) the deployer using the multi-organization config schema (explicitly documented and supported), and (2) at least one configured organization having no `webhook_secret` (the documented default). No attacker access to any secret, token, or session is needed — the entire attack is an unauthenticated POST to the public `/webhooks` endpoint with a self-inconsistent JSON body. This is a plausible, even common, misconfiguration given the docs literally show `webhook_secret:` commented as optional/nil.

### Recommendation
- After selecting the `GitHubApp` used for verification, re-derive the repository/organization actually referenced by the payload and require it to belong to the same authenticated organization before dispatching to handlers.
- Do not allow `nil`/absent `webhook_secret` to silently bypass verification for organizations participating in a shared multi-org webhook endpoint; require a secret whenever multiple orgs share the endpoint, or reject requests where verification cannot be performed.
- Scope `StatusHandler` (and any handler that looks up records by content-derived key like `sha`) to the repository resolved from the authenticated organization, not merely `Commit.where(sha:)` globally.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` (has `stacks` Shipit cares about) and `orgB` (attacker-reachable, `webhook_secret` left `nil` per the documented optional default).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha of a real, CI-pending commit belonging to orgA/some-repo>",
  "state": "success",
  "context": "ci/forced",
  "repository": { "owner": { "login": "orgB" }, "full_name": "orgB/whatever" }
}
```
No `X-Hub-Signature` (or any bogus value) is required.
3. `verify_signature` resolves `Shipit.github(organization: "orgB")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the commit in `orgA`'s stack (unrelated to `orgB`), and calls `create_status_from_github!`, marking it `success` — enabling that commit to pass `required_statuses` and be deployed, despite the attacker never having any credential for `orgA` and never possessing `orgA`'s webhook secret.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-34)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```
