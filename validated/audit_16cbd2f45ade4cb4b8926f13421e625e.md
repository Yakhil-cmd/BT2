This confirms the exploit: the `membership` webhook handler grants team membership using `params.organization.login` and `params.member.login` with no additional check that this organization matches the one used for signature verification.

### Title
Webhook signature verification keyed on unverified `repository_owner`/`organization` field allows cross-organization event forgery when any configured tenant has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to use for HMAC verification based on an untrusted field taken straight from the unauthenticated JSON body, while the payload consumed by the actual event handlers (which mutate stack/team state) is read from separate, independently-controlled fields of that same body. If any configured multi-tenant organization has no `webhook_secret` set, an attacker can pick that organization for verification (which then always passes) while pointing the rest of the payload (`repository.full_name`, `organization.login`, `member.login`, etc.) at a completely different, protected organization/repository/team.

### Finding Description
`verify_signature` computes the org used for signature verification purely from the request body: [1](#0-0) 
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified
...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
`Shipit.github` resolves per-organization config via `github_app_config`, which is looked up in the org-keyed `secrets.github` hash: [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that organization's `webhook_secret` is blank — a state explicitly represented in the sample multi-org secrets file (`webhook_secret: # nil`): [3](#0-2) [4](#0-3) 

Once `verify_signature` passes, the same raw, unauthenticated payload is dispatched to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and each handler independently re-reads repository/organization identity from the body: [5](#0-4) [6](#0-5) 

For example, `MembershipHandler` creates/updates a `Team` and grants membership using `params.organization.login` and `params.member.login`, with no relation to the field used for verification: [7](#0-6) 

and `PushHandler` triggers a real sync/deploy pipeline for whatever `repository.full_name` resolves to via `Repository.from_github_repo_name`: [8](#0-7) [9](#0-8) 

**The broken binding, stated as an equality that the code assumes but does not enforce:**
`organization used to select webhook_secret for signature verification == organization/repository whose state the handler actually mutates`.

Nothing in `verify_signature` ties `repository_owner` to `repository.full_name` or to `organization.login` used later by handlers — they are read independently from the same untrusted JSON, so an attacker can make them diverge.

### Impact Explanation
If a Shipit deployment uses the multi-organization GitHub App config (`Shipit.github_organizations` with per-org entries) and at least one configured organization has no `webhook_secret` (a state the codebase's own sample config documents as valid), an attacker can forge unsigned events for every *other* organization/repository Shipit manages:
- Forge `membership` events with `organization.login` set to a protected org and `member.login` set to any GitHub username, escalating/granting that account membership in a `Team`, which is used for `Shipit.github_teams` authorization checks in `Shipit::Authentication#force_github_authentication` — a direct escalation into `Shipit.github_teams` authorization. [10](#0-9) 
- Forge `push`/`status`/`check_suite`/`pull_request` events with `repository.full_name` set to a protected repo to inject fake commits/statuses, unarchive/archive review stacks, or trigger `GithubSyncJob`/deploy pipelines against real stacks.

This matches the report's underlying pattern: a trust check performed against one identity (the org chosen for signature verification) is silently substituted for a different identity (the org/repo actually acted upon), exactly like the optimizer computing a boost for one protocol but applying the resulting allocation to another.

### Likelihood Explanation
Exploitability depends entirely on operator configuration: it requires a multi-org Shipit deployment where at least one configured organization has an empty/missing `webhook_secret`. This is not a hypothetical edge case — it's the exact configuration shown in the repository's own sample secrets file, and per-organization `webhook_secret` is optional by design in `GitHubApp#verify_webhook_signature` (`return true unless webhook_secret`). No token, session, or repository write access is required — only knowledge of one org's login name that Shipit has configured, which is public information. I could not verify how many real-world deployments run multi-org mode with an unset secret; this is a config-dependent likelihood factor I cannot fully confirm from the codebase alone.

### Recommendation
Do not let signature verification select a different trust domain than the one the handlers will act on:
- Bind the delivered `X-Hub-Signature` verification to the specific repository/org that the payload will be applied to (e.g., derive both from `repository.full_name`, not from two independently-read fields), and refuse to fall back between `repository.owner.login` and `organization.login`.
- Require every configured organization to have a non-blank `webhook_secret`; fail closed (reject the webhook) rather than treating a blank secret as "skip verification," and remove the `return true unless webhook_secret` bypass in `GithubApp#verify_webhook_signature`.
- After successful signature verification, assert that the handler's `repository_name`/`organization.login` used for state mutation is consistent with the organization that provided the verified secret before processing.

### Proof of Concept
Preconditions: Shipit is configured with multi-org GitHub Apps, org `no-secret-org` has `webhook_secret` unset, and org `victim-org` is a fully protected tenant with real stacks/teams.

```http
POST /webhooks HTTP/1.1
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": { "id": 123, "name": "Admins", "slug": "admins", "url": "https://api.github.com/teams/123" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-controlled-github-account" },
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/some-repo" }
}
```
1. `verify_signature` computes `repository_owner = "no-secret-org"`, loads that org's `GitHubApp`, and calls `verify_webhook_signature`, which returns `true` unconditionally because `webhook_secret` is blank for `no-secret-org`. No `X-Hub-Signature` header is even required to be valid.
2. `create` parses the body and dispatches to `MembershipHandler`, which reads `params.organization.login == "victim-org"` and `params.member.login`, creating/looking up the `Team` for `victim-org` and adding the attacker-chosen GitHub login as a member — with no connection back to `no-secret-org`, which was the only thing actually "verified."
3. The attacker's GitHub account is now a member of a team used for `Shipit.github_teams` authorization on `victim-org`'s stacks, despite never authenticating as or controlling anything belonging to `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L15-43)
```ruby
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
