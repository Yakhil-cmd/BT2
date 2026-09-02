### Title
Membership webhook team-lookup bypasses per-organization signature binding, allowing cross-organization escalation into `Shipit.github_teams` authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to use for HMAC verification based on an untrusted field (`repository.owner.login`/`organization.login`) read from the same unauthenticated JSON body it is about to verify [1](#0-0) . This only proves the payload was signed by *some* configured organization's secret, not that the payload's other identifying fields (e.g. `team.id`) actually belong to that organization. `MembershipHandler#find_or_create_team!` then resolves the `Team` to mutate purely by the GitHub numeric `team.id`, with no check that it belongs to the organization whose secret validated the request [2](#0-1) . In a multi-tenant Shipit deployment (explicitly documented, one GitHub App/secret per organization) this breaks the binding "organization that authenticated" = "team record that is written," letting an admin of one onboarded organization add arbitrary users to a `Team` used for global `Shipit.github_teams` authorization if they can guess/know the target team's GitHub numeric ID.

### Finding Description
Shipit supports installing one GitHub App per organization when serving multiple GitHub organizations from a single instance, as documented in `docs/setup.md` ("Using Multiple Github Applications") [3](#0-2) . Each organization's admin can create and configure their own GitHub App, and therefore knows their own `webhook_secret`.

The webhook signature verification flow is:
1. `repository_owner` is read straight from the unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [4](#0-3) .
2. That value selects which organization's `GitHubApp`/secret is used to verify the HMAC signature [1](#0-0) .
3. If verification succeeds, the *entire* raw JSON body — including any other field, not just `organization.login` — is handed unmodified to the registered handlers [5](#0-4) .

This proves only that the payload was signed with organization X's secret; it does not constrain any other field in the payload to be truthful about organization X. `MembershipHandler` uses one such unconstrained field, `team.id` (GitHub's numeric team ID), to look up/create the `Team` record to modify:

```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [6](#0-5) 

`find_or_create_by!(github_id: ...)` first attempts a lookup by `github_id` alone; the `organization` field is only used inside the block that runs on *creation*, and is never used as part of the lookup or re-validated against an existing record. So if a `Team` row with that `github_id` already exists (e.g. it is the org-restriction team wired into `Shipit.github_teams`), the record found and mutated is whichever team already has that GitHub ID — regardless of which organization's secret validated the current request.

`Shipit.github_teams` (the authorization gate) is built from configured team handles and cached by DB `Team#id`, and `User#authorized?` checks membership against those team ids [7](#0-6) [8](#0-7) . `Team#add_member` simply appends the member with no organization cross-check [9](#0-8) .

Equality broken: `organization authenticated via HMAC (organization X's webhook_secret)` ≠ `organization owning the Team record actually mutated (Team.github_id lookup, independent of X)`.

### Impact Explanation
An admin of Organization X (one of several organizations sharing a Shipit instance, each with its own configured GitHub App/`webhook_secret`) can send Shipit a `membership` webhook that is validly signed with X's own secret, but whose `team.id` field is the GitHub numeric ID of a `Team` that already exists in Shipit's database because it's referenced in `Shipit.github_teams` (the org restricting access to the whole application) for a *different* organization Y. Because the lookup in `find_or_create_team!` ignores which organization authenticated the request, the attacker can add any GitHub login (including their own, previously synced via `User.find_or_create_by_login!`) as a `member` of that privileged `Team`, satisfying `User#authorized?` and gaining full access to Shipit — including all of Organization Y's stacks, deploy triggers, and secrets — without ever having legitimate membership in Organization Y or its GitHub teams. This matches the "High — escalation into `Shipit.github_teams` authorization" impact category.

### Likelihood Explanation
Requires a Shipit deployment configured to serve multiple organizations (a documented, supported configuration) where the attacker administers one of the onboarded organizations (and thus legitimately possesses that organization's `webhook_secret`), and can determine the numeric GitHub `team.id` of the target authorization team (obtainable via the GitHub API for any team the attacker can query, or via prior legitimate access, log leakage, etc.). No Shipit session, API token, or GitHub write access to the victim organization is required — only knowledge of one webhook secret the attacker legitimately owns plus the target's numeric team ID.

### Recommendation
- In `MembershipHandler#find_or_create_team!`, always scope the `Team` lookup by both `github_id` **and** `organization` (the organization value implied by the signature-verifying webhook_secret, not the payload's own `organization.login`), and refuse to modify a `Team` whose `organization` does not match the authenticated organization.
- More broadly, `WebhooksController#verify_signature` should carry the authenticated organization forward (e.g., via a validated context) so every handler can assert that any organization/owner fields referenced in the payload match the organization whose secret validated the request, rather than trusting those fields implicitly once the top-level signature check passes.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `OrgX` and `OrgY`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-app setup).
2. `Shipit.github_teams` is configured to include `OrgY/admins`, whose Shipit `Team` row has `github_id: 555` (obtainable via `GET /orgs/OrgY/teams` on GitHub, or already known from prior interaction).
3. Attacker administers `OrgX` and knows `OrgX`'s `webhook_secret` (they created that GitHub App themselves).
4. Attacker crafts a `membership` event payload:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "admins", "slug": "admins", "url": "https://api.github.com/..." },
  "organization": { "login": "OrgX" },
  "member": { "login": "attacker-github-login" }
}
```
5. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgX_webhook_secret, body)` and POSTs to `/webhooks`.
6. `verify_signature` looks up `Shipit.github(organization: "OrgX")` (from `organization.login` in the payload) and verifies successfully against `OrgX`'s secret [1](#0-0) .
7. `MembershipHandler#process` runs, `find_or_create_team!` finds the existing `Team` with `github_id: 555` (`OrgY/admins`) and adds `attacker-github-login` as a member [10](#0-9) .
8. The attacker's Shipit `User` (auto-created/synced from `member.login`) now passes `User#authorized?` because they belong to a `Team` included in `Shipit.github_teams`, gaining full access to the Shipit instance including `OrgY`'s stacks and deploy controls.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L36-43)
```ruby
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
