Confirmed: `MembershipHandler#process` at [1](#0-0)  creates/adds `User` records to a `Team` based purely on the unverified JSON body (`params.organization.login`, `params.team`, `params.member.login`), and `Shipit.github_teams` (used for the entire application's access control in `Authentication#force_github_authentication`) is derived from these `Team`/`Membership` records: [2](#0-1)  and [3](#0-2) .

### Title
Webhook signature is verified against an org selected from the same untrusted payload used by handlers, allowing cross-organization forgery and `Shipit.github_teams` membership escalation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp`/`webhook_secret` to check the request's HMAC signature against by reading `repository_owner`/`organization.login` out of the same unauthenticated JSON body that is later handed, verbatim, to the event handlers. Nothing binds "the organization whose secret validated this request" to "the organization/team the handlers act on." In a multi-org configuration (explicitly documented and supported), an attacker can name an organization key that has no `webhook_secret` configured (webhook secret is documented as optional) to make `verify_webhook_signature` return `true` unconditionally, while still supplying `membership`/`push`/`pull_request` payload fields that reference a different, legitimately configured organization/team/repository.

### Finding Description
The verification and the enforcement of "who is allowed to do this" are computed from two different trust levels of the exact same field set:

1. `create` parses the raw body once: [4](#0-3) 
2. The `before_action :verify_signature` selects the `GitHubApp` (and therefore the `webhook_secret` used for the HMAC check) using `repository_owner`, itself read from the unverified body: [5](#0-4) [6](#0-5) 
3. `GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as "verification passes": [7](#0-6) 
4. Multiple, independently-secreted organizations are an explicitly supported, documented configuration: [8](#0-7) , and `webhook_secret` itself is documented as optional per app: [9](#0-8) 
5. Once `head(422)` isn't triggered, `create` dispatches the *entire unauthenticated payload* to handlers, e.g. `MembershipHandler`, which trusts `params.organization.login`, `params.team`, and `params.member.login` to create/attach `Team`/`Membership` records with no re-check that this organization matches whatever the signature check actually validated: [10](#0-9) 

This is the direct analog of the LayerZero finding: the report's DstConfig lookup used the *source* chain's `baseGas`/`gasPerByte` instead of the *destination* chain's values — i.e., the field that authorizes/prices the operation didn't match the field the operation is executed against. Here, the field used to select the verifying secret (`repository_owner`/`organization.login`, read pre-verification) is not cryptographically bound to, and need not match, the organization/team the dispatched handler actually mutates.

### Impact Explanation
`Shipit.github_teams` gates access to the entire Shipit UI/API (`ApiClientsController`, `RepositoriesController`, `StacksController`, etc. all rely on `User#authorized?`, which checks `teams.where(id: Shipit.github_teams.map(&:id))`): [3](#0-2) [11](#0-10) . An attacker who can get a forged `membership` event accepted (by naming, in the unverified payload, an org that either has no `webhook_secret` configured or one whose secret the attacker knows) can call `team.add_member(member)` for an arbitrary GitHub login, adding it to a `Team` that is one of `Shipit.github_teams` — escalating an arbitrary GitHub account into Shipit's authorization boundary. This matches the "High" impact category: "escalation into `Shipit.github_teams` authorization." It also enables cross-repository interference via `PushHandler`, which is dispatched under the same weak-org bypass and triggers `stack.sync_github` for any stack matching an attacker-chosen `repository.full_name`, independent of which org's secret was actually validated: [12](#0-11) [13](#0-12) .

### Likelihood Explanation
This requires no session, no `ApiClient` token, and no repository write access — only an unauthenticated POST to `/webhooks`. It is only exploitable in multi-organization Shipit deployments where at least one configured organization key has a blank `webhook_secret` (an explicitly documented, supported configuration state) or where distinct organizations use distinct secrets and the attacker is a legitimate GitHub-App-installer for one of them but wants to affect another. Both scenarios are realistic operational configurations rather than contrived edge cases, since the "Using Multiple GitHub Applications" setup guide shows `webhook_secret:` left blank as an unremarkable template value.

### Recommendation
- Bind signature verification to the same organization the dispatched handler will act on: after verifying the signature with the org key derived from the body, re-derive and assert that every organization/repository reference actually processed by handlers (`membership.organization.login`, `repository.full_name`'s owner, etc.) is consistent with the verified organization, or better, verify the signature against *all* configured `webhook_secret`s and record which organization actually matched, then reject if that doesn't match the organization the handler is about to mutate.
- Do not treat a blank `webhook_secret` as "verification passes" silently in multi-org configs; require every configured organization to have a non-blank secret, or fail closed.
- For `MembershipHandler` specifically, cross-check `params.organization.login` against the organization that produced a *positive* signature match before mutating `Team`/`Membership` state.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs: `Victim` (has `webhook_secret: real-secret`, is one of `Shipit.github_teams`) and `Empty` (installed by attacker's own org or otherwise has `webhook_secret:` left blank, per the documented template).
2. Attacker POSTs to `/webhooks` with `X-Github-Event: membership`, no `X-Hub-Signature` (or an arbitrary one), and body:
   ```json
   {
     "action": "added",
     "team": {"id": <Victim's privileged team's github_id>, "name": "Developers", "slug": "developers", "url": "..."},
     "organization": {"login": "Empty"},
     "member": {"login": "attacker-controlled-login"},
     "repository": {"owner": {"login": "Empty"}}
   }
   ```
3. `verify_signature` calls `Shipit.github(organization: "Empty")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes.
4. `MembershipHandler#process` runs unmodified: it looks up/creates the `Team` by `params.team.id` (which the attacker set to `Victim`'s real, privileged team `github_id`) and adds `member` (`attacker-controlled-login`) to it via `team.add_member(member)`.
5. If that `Team` is configured in `Shipit.github_teams` (`oauth.teams`), the attacker-chosen GitHub login now passes `User#authorized?` and gains access to the Shipit UI/API for `Victim`'s stacks.

### Citations

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-34)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
