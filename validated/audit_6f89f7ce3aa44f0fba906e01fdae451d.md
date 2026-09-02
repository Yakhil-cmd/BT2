### Title
Cross-organization team-membership escalation via `membership` webhook — organization authenticated by signature ≠ organization bound to the `team.id` acted upon - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that the raw request body was HMAC-signed with the webhook secret configured for the organization named in that same body (`repository.owner.login` / `organization.login`). `MembershipHandler#find_or_create_team!` then looks up the `Team` record purely by the attacker-supplied `team.id` (GitHub's numeric team id), never checking that the found/created team actually belongs to the organization that was cryptographically authenticated. In a multi-tenant Shipit install (multiple `GithubHook::Organization` secrets configured, as shown by `test/fixtures/shipit/github_hooks.yml`), an admin of one onboarded organization can use their own legitimate webhook secret to sign a `membership` payload that targets a `team.id` belonging to a different organization, adding an arbitrary user to that team.

### Finding Description
The verified field and the acted-upon field are not the same:

- Verification binds to `organization`/`repository.owner` from the payload: [1](#0-0) [2](#0-1) 

  `verify_signature` calls `Shipit.github(organization: repository_owner)` and checks `verify_webhook_signature` against that org's secret. Crucially, `verify_webhook_signature` HMACs the **entire raw body** — but the secret used is selected using a field (`repository_owner`) taken from that same untrusted body, and is only as strong as whichever org-specific secret the caller happens to know.

- The handler that actually mutates state trusts an *different* attacker-controlled field — `team.id` — without cross-checking it against the authenticated organization: [3](#0-2) 

  `find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)`. If a `Team` row with that `github_id` already exists (e.g. it was created earlier from a legitimate `membership` event belonging to a different organization), the block that sets `team.organization = params.organization.login` is **not** executed (it only runs on create), and the pre-existing team (bound to a different org) is returned and mutated: [4](#0-3) 

  `team.add_member(member)` then adds an arbitrary `User` (looked up/created by an arbitrary `member.login` string) to that team: [5](#0-4) 

Team membership is a direct authorization primitive: `User#authorized?` grants access to the whole Shipit instance based on membership in `Shipit.github_teams`: [6](#0-5) [7](#0-6) 

**The equality that is supposed to hold and is broken:**
`organization authenticated by HMAC signature` == `organization that owns the team.id being mutated`

Because the signature only proves "this body was signed with organization X's secret," while `MembershipHandler` blindly trusts the payload's `team.id` (a public, guessable/enumerable GitHub numeric id) to select *which* `Team` row (potentially belonging to organization Y) gets a member appended.

### Impact Explanation
In a Shipit deployment onboarding more than one GitHub organization (each with its own `GithubHook::Organization` webhook secret — the standard configuration, as reflected by the fixtures containing `shipit`, `cyclimse`, and `shopify` orgs), any org admin who can configure/know their own organization's webhook secret can forge a `membership` webhook (bypassing GitHub entirely, since only the secret needs to match) that references a `team.id` from an unrelated organization. This lets them add themselves (or a colluding account) into that other organization's team. If that team is listed in `Shipit.github_teams`, this is a direct escalation into `Shipit.github_teams` authorization — granting access to stacks, deploy triggers, and task streams belonging to an organization the attacker has no legitimate relationship with. This matches the explicitly in-scope High-impact category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Likelihood is high for any multi-tenant Shipit instance: GitHub team ids are small sequential integers, easily enumerable via the public GitHub API (`GET /orgs/{org}/teams`) for organizations the attacker is not even part of. The attacker only needs the ability to sign a POST body with a secret they legitimately possess for their own organization's webhook — no session, `ApiClient` token, or victim secret is required. The bug is purely a missing binding check in `MembershipHandler#find_or_create_team!` and requires no race condition or timing.

### Recommendation
In `MembershipHandler#find_or_create_team!`, do not trust an existing `Team` row matched solely by `github_id`; additionally verify (or scope the lookup by) `organization: params.organization.login`, and reject/raise if a team with that `github_id` already exists under a different organization. More generally, `WebhooksController#verify_signature` should scope the authenticated identity down to the exact resource(s) each handler mutates (repository/team/org), and every handler that resolves an entity by an externally-supplied numeric id (`team.id`, etc.) should assert that entity's `organization`/`owner` matches the organization that was cryptographically verified for the request.

### Proof of Concept
1. Shipit is configured with two tenants, e.g. `orgX` (attacker is an admin) and `orgY` (victim), each with its own webhook secret (`GithubHook::Organization` records), per the pattern in `test/fixtures/shipit/github_hooks.yml`.
2. Attacker discovers `orgY`'s numeric team id for a team listed in `Shipit.github_teams` (e.g. via `GET https://api.github.com/orgs/orgY/teams`, a public/authenticated-but-unprivileged GitHub API call).
3. Attacker crafts a JSON body:
```json
{
  "action": "added",
  "team": { "id": <orgY_team_github_id>, "name": "Owners", "slug": "owners", "url": "https://api.github.com/teams/..." },
  "organization": { "login": "orgX" },
  "member": { "login": "attacker-controlled-login" },
  "repository": { "owner": { "login": "orgX" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgX_webhook_secret, body)` themselves (they legitimately know `orgX`'s secret) and POSTs directly to `/github/webhooks` with `X-Github-Event: membership`.
5. `WebhooksController#verify_signature` succeeds because `repository_owner` resolves to `orgX`, and the signature matches `orgX`'s secret.
6. `MembershipHandler#find_or_create_team!` finds the pre-existing `Team` row for `orgY` (matched purely by `github_id`), and `team.add_member(member)` adds the attacker's user to it.
7. If that team is part of `Shipit.github_teams`, the attacker's account now passes `User#authorized?` and gains access to `orgY`'s stacks/deploys.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L6-44)
```ruby
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
      end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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
