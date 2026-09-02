### Title
Signature Verification Uses `repository.owner.login` While Handlers Act on Unbound `organization.login` / `repository.full_name` Fields, Enabling Cross-Organization Team-Membership Forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` used to validate the inbound webhook HMAC based on `repository.owner.login` (falling back to `organization.login`), but the individual event handlers subsequently trust *other unrelated fields of the same JSON body* (`organization.login`, `team.id`, `member.login`) to decide which `Team`/`Membership` records to mutate. Because GitHub's HMAC only proves "this body was signed with organization X's secret," not "every field inside this body legitimately belongs to organization X," an attacker who controls one legitimate, Shipit-integrated GitHub organization (and therefore knows that organization's own `webhook_secret`) can forge a `membership` event whose `team`/`organization` fields point at a *different* victim organization already tracked by Shipit, and add an arbitrary GitHub login to that team. This breaks the binding "organization that authenticated == organization whose data is written," directly matching the reentrancy report's bug class (a value acted upon that was never actually covered/bound by the verification step).

### Finding Description
`WebhooksController#verify_signature` computes the app/secret to check against solely from the repository owner (or top-level `organization`) field: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end
```

`repository_owner` reads: [2](#0-1) 

This value is used *only* to look up which `webhook_secret` to HMAC-verify against. The HMAC verification (`GithubApp#verify_webhook_signature`) proves the raw body was signed by whoever holds that organization's `webhook_secret` — nothing more: [3](#0-2) 

However, `MembershipHandler` — one of the handlers dispatched with the very same `params` blob — derives the `Team` to create/mutate from a *separate, independently-controlled* field, `organization.login`, embedded in the same payload: [4](#0-3) 

```ruby
def process
  team = find_or_create_team!
  member = User.find_or_create_by_login!(params.member.login)
  case params.action
  when 'added'
    team.add_member(member)
  ...
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```

Nothing in the request-verification path checks that `organization.login` used by `MembershipHandler` equals the `repository_owner` (or any org) whose secret was used to compute the HMAC. For a `membership` event, GitHub webhooks do not even include a `repository` key at all — real GitHub `membership` payloads only carry `organization`. `repository_owner` therefore falls back to `params.dig('organization', 'login')`: [2](#0-1) 

But this is the *same literal field* `MembershipHandler` reads to decide which `Team.organization` to write — so a legitimate GitHub-delivered `membership` event is naturally self-consistent. The break occurs because an attacker does **not** need GitHub to deliver the webhook: the attacker can `POST` directly to `/webhooks` with a hand-crafted JSON body and any header values they like, as long as the HMAC over the raw body matches *some* organization's `webhook_secret` that the attacker legitimately knows (their own organization, onboarded to the same multi-tenant Shipit instance). Since `verify_signature` only checks the HMAC and never re-derives/validates `organization.login` against a canonical, cryptographically-bound identity distinct from attacker-controlled JSON, the attacker can set:
- `organization.login` = attacker's own org login (so `Shipit.github(organization: repository_owner)` picks their own known secret and the HMAC check passes), while simultaneously
- `team.id` / `team.organization` fields describing a **victim organization's team that already exists in Shipit's database** (`Team.find_or_create_by!(github_id: params.team.id)` — if `github_id` collides with a real victim team's GitHub team ID, the existing victim `Team` record is fetched, not recreated), and
- `member.login` = the attacker's own (or any) GitHub login.

Because `find_or_create_team!` only checks `github_id`, if the attacker crafts a payload whose `team.id` matches a *real, already-known* victim `Team#github_id` (team IDs are visible/guessable via GitHub's public/team APIs or from the attacker's UI observations of Shipit if they are also a member of some other team there), `Team.find_or_create_by!` returns the existing victim-org `Team`, and `team.add_member(member)` adds the attacker's user as a member of that victim team — all gated only by an HMAC computed with the attacker's own organization's secret, never the victim's.

### Impact Explanation
`User#authorized?` grants access to the entire Shipit instance based purely on `Team` membership intersecting `Shipit.github_teams`: [5](#0-4) 

```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
```

If the forged `membership` event targets a `Team` that is included in `Shipit.github_teams` (the authorization gate checked in `Shipit::Authentication#force_github_authentication`), the attacker's own GitHub-authenticated user is granted access to the authorized area of the application without ever being a real member of the victim GitHub team/organization. This is a privilege-escalation into `Shipit.github_teams` authorization achieved purely by crafting a webhook body signed with a secret the attacker legitimately possesses (their own org's), which corresponds to the report's "High" severity bucket ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Requires only: (1) the attacker's own organization to be a legitimate, Shipit-tracked tenant configured with its own `webhook_secret` (which the attacker, as that org's admin, would know since they configure the GitHub webhook themselves) — i.e., no privileged Shipit credentials, session, or `ApiClient` token needed, matching the "unprivileged attacker" requirement; (2) knowledge/guess of the target victim `Team#github_id` (obtainable via GitHub's public teams API for known orgs, or via observing another Shipit membership event/UI). Given the `WebhooksController` endpoint is unauthenticated by design (it only relies on HMAC) and every field besides the HMAC-checked raw body is fully attacker-controlled, this is a straightforward crafted-HTTP-request exploit, not a race condition or DoS.

### Recommendation
Bind the `Team`/`Membership` writes to the *same* organization identity that was cryptographically verified. Concretely:
- In `WebhooksController#verify_signature`, store the verified `repository_owner`/organization login (the one whose secret produced a valid HMAC) in a request-scoped value, and pass it through to handlers.
- In `MembershipHandler#find_or_create_team!` (and any other handler trusting `organization.login`/`repository.full_name`), assert that `params.organization.login` (or `params.repository.full_name`'s owner segment) exactly equals the organization identity verified by the HMAC check before performing any lookup/mutation; reject the event otherwise.
- More generally, treat every field read by a handler as attacker-controlled unless it is provably identical to the field used to select the verification secret, mirroring the Check-Effects-Interactions guidance from the original report: verify (checks) against the *exact* value that will be acted upon (effects), not a same-shaped but independently supplied value.

### Proof of Concept
1. Attacker owns/administers GitHub organization `attacker-org`, which is legitimately configured in this Shipit instance with `webhook_secret = S_attacker` (attacker knows `S_attacker` because they set up the GitHub webhook themselves, pointing at the Shipit `/webhooks` endpoint).
2. Attacker identifies (or is told/observes) the numeric `github_id` of a `Team` belonging to victim organization `victim-org` that is already synced into Shipit and is a member of `Shipit.github_teams` (e.g., via `GET https://api.github.com/orgs/victim-org/teams`, which is often publicly readable, or via a previous legitimate membership webhook already recorded).
3. Attacker crafts JSON body:
```json
{
  "action": "added",
  "team": { "id": <victim_team_github_id>, "name": "Victim Team", "slug": "victim-team", "url": "https://api.github.com/teams/123" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-user" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(S_attacker, raw_body)>` and sends:
```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=<computed>
```
5. `WebhooksController#verify_signature` computes `repository_owner` = `"attacker-org"` (from the `organization` fallback), fetches `Shipit.github(organization: "attacker-org")`, and the HMAC verifies successfully since it was signed with `S_attacker`.
6. `MembershipHandler#process` runs: `Team.find_or_create_by!(github_id: victim_team_github_id)` resolves to the **existing victim `Team`** record; `User.find_or_create_by_login!("attacker-user")` creates/fetches the attacker's `User`; `team.add_member(member)` adds the attacker to the victim team.
7. If that victim team is in `Shipit.github_teams`, the attacker's GitHub-authenticated session now passes `User#authorized?`, granting access to stacks/deploys they were never authorized for — an unauthorized escalation achieved purely through a self-signed webhook body. [6](#0-5)

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
