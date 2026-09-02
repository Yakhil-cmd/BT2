### Title
Membership webhook trusts `organization.login` for team attribution without verifying it matches the org whose secret signed the request - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which org's `webhook_secret` to check the HMAC against using `repository_owner`, which prefers `params.dig('repository','owner','login')` over `params.dig('organization','login')`. `MembershipHandler#process`/`#find_or_create_team!`, however, attributes team ownership and calls `Team#add_member` based on `params.organization.login` alone, with no check that this value equals the organization that actually signed the request. In a multi-org Shipit deployment, an attacker who legitimately controls one tenant org (and thus its `webhook_secret`) can forge a `membership` `added` event whose `repository.owner.login` names their own org (so it passes signature verification with a secret they know) while `organization.login` and `team.id` name a *different*, victim org's existing `Shipit.github_teams` team, causing their attacker-controlled `member.login` to be inserted into that team's `Membership` rows.

### Finding Description
The broken binding, stated as an equality that the code must (but does not) enforce:

`signing_organization (used to pick the webhook_secret in verify_signature) == params.organization.login (used by MembershipHandler to attribute/authorize the Team write)`

Trace:
1. `WebhooksController#verify_signature` computes the org used to select the HMAC secret from `repository_owner`, which is `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . If the JSON body includes a `repository` key, it takes precedence over `organization` for choosing which org's secret verifies the HMAC.
2. `MembershipHandler#process` and `#find_or_create_team!` use `params.organization.login` (a completely separate field in the same body) to set `team.organization` when creating a new team, and use `params.team.id` alone (`Team.find_or_create_by!(github_id: params.team.id)`) to look up an *existing* team - the `organization:` value is only applied inside the `create` block, so for an already-existing team (e.g., any team already listed in `Shipit.github_teams`) the lookup ignores `params.organization.login` entirely [2](#0-1) .
3. `Team#add_member` unconditionally appends the member with no re-check of which organization is calling it [3](#0-2) .

Exploit flow (multi-org Shipit config, i.e. `secrets.github` keyed by org name, each with its own `webhook_secret`):
- Attacker owns/administers `attacker-org` as a legitimate Shipit tenant and therefore knows its `webhook_secret`.
- Attacker crafts a `membership` webhook JSON body:
  - `repository: { owner: { login: "attacker-org" } }` → makes `repository_owner` resolve to `attacker-org`, so `verify_signature` checks the HMAC against `attacker-org`'s secret, which the attacker knows and can compute correctly.
  - `organization: { login: "victim-org" }`, `team: { id: <victim's existing Shipit.github_teams team github_id>, name, slug, url }` (all discoverable via GitHub's public org-teams API or from any legitimate webhook the victim org itself already sent), `member: { login: "attacker-controlled-user" }`, `action: "added"`.
- Because `repository.owner.login` (attacker-org) diverges from `organization.login` (victim-org), signature verification is satisfied against attacker's own secret while the handler acts on behalf of `victim-org`.
- `find_or_create_team!` finds the existing victim `Team` by `github_id` alone (organization is not re-validated) and `team.add_member(member)` inserts a `Membership` row tying the attacker's chosen GitHub login to that team, in Shipit's database, without ever needing the victim org's webhook secret.

None of the existing guards close this gap: `verify_signature` only proves *a* recognized org's secret signed the body, not that the org it picked matches the org the payload claims to represent in `organization.login`; `drop_unhandled_event` and the `ExplicitParameters` schema only validate presence/types of fields, not cross-field consistency; there is no model validation on `Team` or `Membership` tying inserted memberships back to a verified signing organization.

### Impact Explanation
A request signed with one tenant org's webhook secret can write a `Shipit::Membership` row attributing arbitrary GitHub-login membership to a *different* org's `Team`, including teams enumerated in `Shipit.github_teams`, which gate login/authorization to the whole Shipit instance [4](#0-3) . This is escalation into `Shipit.github_teams` authorization from an organization that does not own the team, matching the High severity category. Repeatable per victim team/target login as long as the attacker knows (or can enumerate) the team's numeric `github_id`, its org login, and slug - all obtainable from public GitHub team-listing APIs. Blast radius is cross-tenant: any org configured in a multi-org Shipit deployment can forge membership into any other org's teams.

### Likelihood Explanation
Requires: (1) Shipit configured with the multi-org `github:` schema (distinct `webhook_secret` per org) [5](#0-4) , and (2) the attacker legitimately administers at least one tenant org registered in that config (so they know its `webhook_secret`) while targeting a different, victim org's team. Attacker cost is low - only an HTTP POST to `/webhooks` with a correctly HMAC-signed body using their own known secret; no GitHub session, private key, or victim secret is needed. Feasibility depends on discovering the victim team's numeric `github_id`, which is retrievable via GitHub's public `GET /orgs/{org}/teams` for visible teams or leaked through prior legitimate webhook traffic.

### Recommendation
In `MembershipHandler`, assert that the verified signing organization (i.e., `repository_owner`/the org whose secret validated the signature) equals `params.organization.login` before performing any team lookup or `add_member`/`delete` mutation; reject (422) on mismatch. Additionally, `find_or_create_team!` should validate that an existing team's stored `organization` matches `params.organization.login` and refuse to mutate membership otherwise, closing the gap where lookup-by-`github_id` bypasses org attribution.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, multi-org fixtures):
```ruby
test ":membership with mismatched repository.owner and organization.login must not add member to a foreign team" do
  # Arrange: team exists and belongs to 'shopify'
  team = shipit_teams(:shopify_developers)
  assert_equal 'shopify', team.organization

  # Configure attacker's own org as a valid signed tenant
  # (attacker-org webhook_secret known/controlled by attacker)
  @request.headers['X-Github-Event'] = 'membership'

  forged_body = {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: 'shopify' },          # claims to be shopify
    member: { login: 'attacker_login' },
    repository: { owner: { login: 'attacker-org' } } # but signs as attacker-org
  }.to_json

  signature = sign_with_secret(attacker_org_webhook_secret, forged_body)
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { Shipit::Membership.where(team: team).count } do
    post :create, body: forged_body, as: :json
  end

  refute team.members.exists?(login: 'attacker_login')
end
```
Assertions on both sides of the binding: `signing_organization == 'attacker-org'` (derived from `repository.owner.login`) vs `params.organization.login == 'shopify'` - the test asserts these must be equal for any mutation to `team.memberships` to occur, and currently they are not checked, so the forged request should be rejected (fixed behavior) but currently succeeds in inserting the membership (vulnerable behavior).

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
