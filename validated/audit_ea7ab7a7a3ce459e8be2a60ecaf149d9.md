### Title
Cross-organization team-membership injection via `MembershipHandler#find_or_create_team!` keying only on GitHub `team.id` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler` finds/creates a `Team` solely by the numeric `github_id`, never checking that the `organization.login` in the incoming webhook matches the organization that actually owns the pre-existing `Team` row. Combined with the fact that webhook signature verification only proves the request was signed by *some* configured organization's secret (not necessarily the organization the target `Team` belongs to), an attacker who legitimately owns/administers one Shipit-connected organization (and therefore knows its `webhook_secret`, which the threat model explicitly allows — "emit webhooks from a repository/org they own") can add an arbitrary GitHub login as a member of a `Team` record belonging to a different organization.

### Finding Description
The binding that must hold is: **organization whose `webhook_secret` verified the request bytes == organization owning the `Team` row being mutated.** It does not hold.

- `WebhooksController#verify_signature` resolves the signing organization via `repository_owner`, which reads `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) , and then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [2](#0-1) . Since the `membership` webhook schema does not require a `repository` key at all [3](#0-2) , an attacker can omit `repository` and set `organization.login` to their own org ("org-A"), whose secret they know because they own/administer it (per the threat model's "emit webhooks from a repository they own"). The signature therefore verifies successfully against org-A's secret.
- `MembershipHandler#find_or_create_team!` then does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login; ... }` [4](#0-3) . `find_or_create_by!`'s block only runs when a **new** record is built; if a `Team` row already exists with that `github_id` (e.g. a real team belonging to org-B, previously synced via `Shipit.github_teams`/`Team.find_or_create_by_handle`), the existing org-B `Team` is returned unmodified and the block (including the `organization =` assignment) never executes.
- Back in `process`, the handler then does `team.add_member(User.find_or_create_by_login!(params.member.login))` for `action == 'added'` [5](#0-4) . Nothing compares `params.organization.login` (org-A, the org whose secret actually verified the request) against the existing team's `organization` column (org-B). The attacker-supplied `member.login` is added as a member of org-B's `Team` record.
- This `Team`/`members` relation is exactly what gates application-wide authorization: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) , and `force_github_authentication` denies access unless `current_user.authorized?` [7](#0-6) . If org-B's team happens to be one of `Shipit.github_teams` (an org used for authorization), the attacker's GitHub login becomes an authorized Shipit user.

None of the existing guards stop this: `verify_signature` only proves org-A's secret signed the bytes, not that org-A owns the referenced team; the `ExplicitParameters` schema for `MembershipHandler` requires only `team.id/name/slug/url`, `organization.login`, `member.login` — no repository/org binding check; and `find_or_create_by!` silently skips the block (and thus the `organization=` write) for pre-existing rows, meaning the org field of the target `Team` was never even attempted to be validated against the request's organization.

### Impact Explanation
An attacker who controls (or created) an unrelated GitHub organization connected to a multi-tenant Shipit instance can add any GitHub login — including their own or a colluding account — as a `members` of a `Team` record belonging to a different, victim organization, provided they can learn/guess that team's numeric GitHub `id` (team IDs are global, non-secret, and often discoverable via GitHub's API or UI). If that `Team` is part of `Shipit.github_teams` (the authorization allowlist), this is a direct authentication/authorization bypass: the attacker's account becomes `authorized?` in the victim organization's Shipit instance, gaining access to that organization's stacks, deploys, and tasks. This matches the "escalation into `Shipit.github_teams` authorization" Critical/High impact category. The attack is repeatable against any target `Team` github_id already present in the database and is not limited to a single victim.

### Likelihood Explanation
Preconditions: the Shipit deployment must be multi-tenant (multiple organizations configured under `secrets.github`, as documented under "Using Multiple Github Applications" [8](#0-7) ) with at least one victim `Team` row already persisted (created earlier via `Shipit.github_teams`/`Team.find_or_create_by_handle`). The attacker needs their own valid org onboarded to the same Shipit instance and knowledge of its `webhook_secret` (which they legitimately possess, having configured/own that webhook per the stated threat model), plus the target team's numeric GitHub ID. No GitHub or Shipit secret belonging to the victim org is required. This is a low-cost, fully scriptable HTTP POST once the team ID is known.

### Recommendation
In `MembershipHandler#find_or_create_team!`, do not key solely on `github_id`. Either (a) scope the lookup by both `github_id` and `organization` (`Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), or (b) after finding an existing team, explicitly verify `team.organization == params.organization.login` and reject/raise (or drop the event) if they diverge, before calling `team.add_member`/`team.members.delete`.

### Proof of Concept
minitest plan (in `test/controllers/webhooks_controller_test.rb` style):
1. Create/fixture `team_org_b = Team.create!(github_id: 999, organization: 'org-b', slug: 'secret-team', name: 'Secret Team', api_url: 'https://example.com')`.
2. Configure two orgs in test secrets (`org-a`, `org-b`), each with its own `webhook_secret`.
3. Build a `membership` payload: `{"action"=>"added","team"=>{"id"=>999,"name"=>"Secret Team","slug"=>"secret-team","url"=>"https://example.com"},"organization"=>{"login"=>"org-a"},"member"=>{"login"=>"attacker-login"}}` — no `repository` key.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', org_a_webhook_secret, payload_json)`.
5. POST to `/webhooks` with `X-Github-Event: membership` and that signature.
6. Assert response is `:ok` (signature verified against org-A).
7. **Binding check (both sides):** before request, `team_org_b.reload.organization == 'org-b'` and `team_org_b.members.map(&:login)` does not include `'attacker-login'`. After request, assert `team_org_b.reload.organization == 'org-b'` (unchanged) but **assert `team_org_b.members.map(&:login)` does NOT include `'attacker-login'`** — this assertion currently fails against the vulnerable code (the attacker IS added), proving the binding "signing org == team's org" is violated.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
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
