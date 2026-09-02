### Title
Membership-webhook signature check authenticates a different GitHub organization than the one used to create/populate the `Team` that grants `Shipit.github_teams` authorization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret used to validate `X-Hub-Signature` based on `repository.owner.login` (falling back to `organization.login` only when `repository` is absent). `MembershipHandler`, however, scopes the `Team` it creates/mutates using a completely independent `organization.login` field from the same JSON body. Because `repository` is optional for `membership` events, an attacker who can get *any* signature check to pass for *some* configured organization (e.g. one whose `webhook_secret` is left unset, which `docs/setup.md` explicitly documents as optional) can forge a `membership` payload whose `organization.login` names a different, victim organization that is part of `Shipit.github_teams`, and add themselves to that `Team`.

### Finding Description
`verify_signature` derives the org used to select the webhook secret purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` completely skips verification when the selected organization has no configured `webhook_secret`: [3](#0-2) 

This is a documented, legitimate configuration state — `docs/setup.md` explicitly lists the webhook secret as "(optional)" for each org in multi-org setups.

Meanwhile, `MembershipHandler` reads a *different* field — `organization.login` — to decide which `Team` to create or mutate, and to add the attacker-controlled `member.login` to it: [4](#0-3) 

The `MembershipHandler#params` block does not `require :repository` at all, so an attacker fully controls whether `repository.owner.login` is present and what it contains, independently of `organization.login`.

The binding broken is: *the organization whose webhook signature "authenticated" the request* (`repository.owner.login`, or absent) ≠ *the organization whose `Team`/membership state the handler actually writes* (`organization.login`). These two must be equal for the signature check to mean anything for membership events, but nothing in the code enforces that equality.

`Team.organization`/`slug` combination is exactly what backs `Shipit.github_teams`, which gates application access in `Authentication#force_github_authentication`: [5](#0-4) [6](#0-5) 

### Impact Explanation
This maps directly to the specified High-severity impact "escalation into `Shipit.github_teams` authorization." An attacker who already has a Shipit `User` record (i.e., has previously logged in via GitHub OAuth, which requires no privilege) can add themselves as a `member` of any `Team` — including a `Team` whose `organization/slug` matches an entry in `Shipit.oauth_teams`/`Shipit.github_teams` — thereby bypassing the team-membership authorization check and gaining full access to Shipit for stacks belonging to an organization they have no legitimate relationship with. This does not require the `webhook_secret`, `api_clients_secret`, or any privileged token for the *target* organization — only that some *other* configured organization in the same Shipit instance has no webhook secret set (a state the docs explicitly allow).

### Likelihood Explanation
Requires a multi-GitHub-app Shipit deployment (documented, supported configuration in `docs/setup.md`) where at least one configured organization has no `webhook_secret` set. Given the docs literally mark the field "(optional)", this is a plausible real-world configuration. The attacker also needs an existing Shipit `User` account, obtainable via ordinary GitHub OAuth login (no special privilege, assuming `Shipit.github_teams` is non-empty but the attacker isn't yet a member of any required team — exactly the scenario this bug lets them escape). No repository write access, GitHub App key, or webhook secret for the victim org is required.

### Recommendation
In `MembershipHandler` (and any other handler that trusts an `organization`/`repository` field to select a trust boundary), verify that the organization used for signature verification (`repository_owner` in `WebhooksController`) is the same organization the handler is about to mutate, rejecting the webhook otherwise. Alternatively, have `WebhooksController#verify_signature` pass the authenticated organization into the handler and have `MembershipHandler` use that value instead of re-reading `params.organization.login` independently.

### Proof of Concept
1. Deploy Shipit configured with two GitHub Apps, per `docs/setup.md`'s "Using Multiple GitHub Applications" section:
   - `attacker-org`: `webhook_secret` left blank (documented as optional).
   - `victim-org`: has `webhook_secret` set and is referenced in `oauth.teams` (i.e., contributes to `Shipit.github_teams`), e.g. `victim-org/admins`.
2. Attacker logs into Shipit via GitHub OAuth as any GitHub user (`AttackerLogin`), creating a `Shipit::User` row (`app/controllers/shipit/github_authentication_controller.rb#sign_in_github`).
3. Attacker sends `POST /webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "Admins", "slug": "admins", "url": "https://api.github.com/teams/999"},
  "organization": {"login": "victim-org"},
  "member": {"login": "AttackerLogin"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
   No `X-Hub-Signature` header needed, since `attacker-org` has no `webhook_secret`, causing `verify_webhook_signature` to `return true unless webhook_secret` (`lib/shipit/github_app.rb:76-77`).
4. `WebhooksController#repository_owner` resolves to `attacker-org` (from `repository.owner.login`), so `verify_signature` passes trivially.
5. `MembershipHandler#process` runs using `params.organization.login == "victim-org"`, creating/finding `Team(organization: "victim-org", slug: "admins")` and adding `AttackerLogin`'s `User` as a member.
6. On the attacker's next request, `User#authorized?` finds the attacker in a team matching `Shipit.github_teams`, granting them full access to Shipit and any stacks under `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-43)
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
