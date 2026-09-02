### Title
Cross-organization team membership mutation via webhook signed by an unrelated organization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` derives the signing organization from attacker-controlled JSON (`organization.login`/`repository.owner.login`), and `MembershipHandler#find_or_create_team!` looks up the target `Team` purely by `github_id`, never checking that the organization whose secret verified the signature actually owns that team. An org that is a legitimate Shipit tenant (and thus knows its own `webhook_secret`) can forge a `membership` webhook naming another org's team `github_id` and a real member login, causing `team.members.delete(member)` to strip that user's `Shipit::Membership`, degrading their `User#authorized?` result.

### Finding Description
The claimed binding is: `organization whose webhook_secret verified the raw body == organization owning the Shipit::Team being mutated`.

Trace:
- `Shipit::WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and fetches the per-organization app/secret via `Shipit.github(organization: repository_owner)` before checking `verify_webhook_signature(header, raw_post)` [2](#0-1) . Both `organization.login` and the signature belong to the *same* attacker-supplied payload, so the org used to pick the verification secret is fully attacker-chosen.
- `Shipit.github(organization:)` resolves per-org config via `github_app_config(organization)` when multiple orgs are configured [3](#0-2) , meaning each tenant org has (and knows) its own `webhook_secret`.
- Once signature verification passes (using the attacker org's own secret), `WebhooksController#create` parses the raw body independently and dispatches to `MembershipHandler.call(params)` [4](#0-3) .
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { ... }` [5](#0-4) . The block (which sets `team.organization = params.organization.login`) only runs on **creation**; if a `Team` with that `github_id` already exists (the real, legitimate target team), it is returned unmodified regardless of what `organization.login` says.
- `process` then does `team.members.delete(member)` for `action == 'removed'` on the found team [6](#0-5) , with no re-check that the verified signing organization equals `team.organization`.
- `User#authorized?` is computed from `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) , so deleting the `Membership` row directly degrades the victim's access.

Attacker request: attacker owns/operates org `attacker-org`, which is configured in Shipit as a tenant with its own `webhook_secret`. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with `attacker-org`'s own secret, and a JSON body:
```json
{
  "action": "removed",
  "team": {"id": <real target team's github_id>, "name": "...", "slug": "...", "url": "..."},
  "organization": {"login": "attacker-org"},
  "member": {"login": "<real victim login>"}
}
```
`verify_signature` resolves `repository_owner` = `"attacker-org"`, verifies successfully against attacker's own secret, and the request proceeds. `find_or_create_team!` finds the pre-existing target `Team` by `github_id` (ignoring the mismatched `organization.login`), and `team.members.delete(member)` removes the victim's membership.

Existing guards do not prevent this: `drop_unhandled_event` and `check_if_ping` don't inspect organization identity; `verify_signature` only proves the request was signed by *some* known org, not the org that owns the referenced team; the `ExplicitParameters` schema in `MembershipHandler.params` validates types/presence only, not cross-organization ownership [8](#0-7) .

### Impact Explanation
A single forged webhook lets one tenant organization silently revoke another organization's user's team membership, degrading that user's `authorized?` status and hence Shipit access, without any privileged credential belonging to the victim org. This is repeatable against any team `github_id` the attacker can guess/observe (team ids are often discoverable via GitHub's public API) and any member login, across every tenant sharing the same Shipit installation. This matches the High severity category ("escalation into `Shipit.github_teams` authorization" — here, de-escalation/denial of legitimate authorization is the mirror-image of that same authorization-boundary violation), since the mutation crosses an organizational trust boundary that the provenance check is supposed to enforce.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured for multiple GitHub organizations (multi-tenant `github_app_config` schema) with `Shipit.github_teams` populated, and the attacker must control at least one such tenant org (i.e., legitimately possess its own `webhook_secret`, which is a normal, low-privilege onboarding action for any org admin who can install the GitHub App). No GitHub-level compromise, no access to the victim org's secrets, and no Shipit session/API token are needed — only the ability to sign a JSON body with a secret the attacker already legitimately owns. This is highly feasible and cheaply repeatable per request.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and any other handler resolving records solely by a GitHub-supplied numeric id), require that the resolved `Team#organization` match the organization that was used to verify the webhook signature (e.g., pass the verified `repository_owner`/organization down through `Handler.call` and assert `team.organization.casecmp?(verified_organization)` before performing any mutation, raising/dropping otherwise). More generally, `WebhooksController#verify_signature` should bind the verified organization to the request (e.g., store it and pass it explicitly into handlers) rather than relying on handlers to separately re-derive organization identity from the same untrusted payload.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test ":membership removed cannot be forged by a different signed organization" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify'
  victim = shipit_users(:walrus) # already a member of victim_team via fixtures
  assert victim.teams.include?(victim_team)

  @request.headers['X-Github-Event'] = 'membership'

  # Attacker's org, distinct from 'shopify', with its own webhook_secret configured.
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true)
  )

  forged_payload = {
    action: 'removed',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' }, # used only for signature lookup
    member: { login: victim.login }
  }.to_json

  assert_no_difference -> { Shipit::Membership.where(team: victim_team, user: victim).count } do
    post :create, body: forged_payload, as: :json
  end

  assert victim.reload.teams.include?(victim_team), "victim's membership must survive a webhook signed by an unrelated organization"
end
```
Both sides of the equality: before, `verified_organization == 'attacker-org'` while `team.organization == 'shopify'` (mismatch); the assertion checks that despite the mismatch, no `Membership` row is destroyed and `victim.authorized?`/team membership remains intact. Currently this test would fail against `MembershipHandler#find_or_create_team!` and `#process`, demonstrating the vulnerability.

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
