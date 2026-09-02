I found a solid analog. Let me confirm the exact mechanics of the membership webhook handler and how team lookups bypass organization scoping.### Title
Membership webhook trusts the verified organization's signature but writes team membership on any `team.id`, letting a signature valid for one tenant organization grant access to another organization's team — ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify the payload's HMAC signature by reading `repository_owner`/`organization.login` straight out of the untrusted JSON body, then calls `github_app.verify_webhook_signature` for *that* organization only. [1](#0-0)  The `membership` event is routed to `MembershipHandler#process`, which resolves (or creates) the `Team` record purely by `github_id: params.team.id`, and only assigns `team.organization = params.organization.login` inside the `find_or_create_by!` block that runs **only on creation** — never re-validating or re-binding `organization` for an already-existing team. [2](#0-1)  The binding that should hold is `organization verified by signature == organization of the Team record mutated`; instead the mutated Team is selected solely by an attacker/GitHub-supplied integer ID with no cross-check against the verified organization, exactly mirroring the vault-ownership omission in the referenced report (some accounts/attributes checked, others silently trusted).

### Finding Description
`Shipit.github(organization: repository_owner)` picks the webhook secret to verify against based on `params.dig('repository','owner','login') || params.dig('organization','login')` — both attacker-controlled JSON fields. [3](#0-2)  This is the documented multi-tenant setup where each GitHub organization has its own app/secret. [4](#0-3) 

For `membership` events, `MembershipHandler#find_or_create_team!` does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
``` [5](#0-4) 
The block that sets `team.organization` only executes when ActiveRecord *creates* a new record. If a `Team` with the given `github_id` already exists (e.g., it was created earlier for organization "OrgB"), the lookup returns that existing record untouched — `organization` is never compared against `params.organization.login`. `process` then calls `team.add_member(member)` using the attacker-supplied `member.login`, directly mutating `Team#members` and, through `Membership`, whichever set of `Shipit.github_teams` gates authorization. [6](#0-5) [7](#0-6) 

Authorization is later checked purely by team membership: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?`. [8](#0-7)  Team IDs (`github_id`) are global GitHub identifiers, unrelated to the organization sending the webhook, so nothing in the signature-verification step (which is scoped to a single organization's secret) constrains which `Team.github_id` a valid, signed payload from that organization may target.

**Before the attack:** organization O1's signature can only be forged/known by parties with access to O1's webhook secret (e.g., O1's own GitHub App installation admin — an "org admin", not a Shipit session/user). Team T (github_id=999) belongs to organization O2 and is one of `Shipit.github_teams`, so its members are authorized Shipit users.

**After the attack:** O1 crafts a `membership` `added` event: `organization.login = "O1"` (valid signature for O1's secret) but `team.id = 999`, `member.login = "attacker"`. `verify_signature` passes because the signature is genuinely valid for O1. `find_or_create_team!` finds the *existing* Team 999 (O2's team) and `team.add_member(attacker)` runs — adding `attacker` as a member of O2's privileged team, without ever authenticating as O2 or holding a Shipit session.

The equality that should hold — `organization authenticated by signature == organization owning the Team mutated` — is broken because only the `github_id` is used for the write path, with no re-check of `organization`.

### Impact Explanation
This escalates an attacker with control of a legitimate but different tenant's webhook secret (or the ability to trigger a `membership` webhook from a GitHub App installed by *any* configured organization) directly into `Shipit.github_teams` authorization for a different organization's team — matching the "High" impact category "escalation into `Shipit.github_teams` authorization" explicitly listed in scope. Since Shipit gates the entire UI/API (`force_github_authentication` / `authorized?`) on team membership [9](#0-8) , this can grant an unauthorized identity full access to another tenant's stacks, deploys, and merges.

### Likelihood Explanation
Exploitability requires: (1) a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration), (2) the attacker being able to produce a validly signed `membership` webhook for at least one of those organizations (i.e., controlling/compromising one tenant's GitHub App webhook secret or installation — much less than a Shipit session, API token, or the target organization's credentials), and (3) knowledge of the target team's numeric GitHub `github_id`, which is discoverable via the GitHub API/UI without requiring org-owner privileges in the target org. This is plausible in the explicit multi-org hosting scenario the docs describe, but requires the attacker to already control one tenant's webhook secret, making it a cross-tenant privilege-escalation path rather than a fully anonymous one.

### Recommendation
When looking up an existing `Team` for a `membership` event, verify that `team.organization` (case-insensitively) matches `params.organization.login` — the organization that was actually authenticated by `verify_signature` — before permitting `add_member`/`delete` mutations, and reject/log the event otherwise. This mirrors adding the missing `check_account_owner` calls for `base_vault`/`quote_vault` in the referenced report: validate ownership of the resource being mutated, not just the resource used to select the signature.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own GitHub App/`webhook_secret`, per `docs/setup.md`'s multi-app example. [4](#0-3) 
2. `orgB` has a `Team` record with `github_id = 999`, `organization = "orgb"`, and is listed in `Shipit.github_teams`.
3. Attacker controls `orgA`'s GitHub App webhook secret (e.g., is an admin of `orgA`'s installation).
4. Attacker POSTs to `/webhooks` with `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with `orgA`'s secret, and body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "x", "slug": "x", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "orgA" },
  "member": { "login": "attacker" }
}
```
5. `verify_signature` succeeds (signature valid for `orgA`). [10](#0-9) 
6. `MembershipHandler#find_or_create_team!` finds the existing Team `github_id: 999` (owned by `orgB`) and `team.add_member(User.find_or_create_by_login!("attacker"))` runs, adding `attacker` to `orgB`'s authorized team. [2](#0-1) 
7. `attacker` now satisfies `User#authorized?` for stacks gated on `orgB`'s team. [8](#0-7)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-61)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
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
