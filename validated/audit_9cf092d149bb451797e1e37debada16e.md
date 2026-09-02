### Title
Cross-organization `Membership` escalation via unscoped `Team.find_or_create_by!(github_id:)` in `MembershipHandler` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` looks up the target `Team` solely by `github_id`, without scoping to the `organization.login` that the webhook signature actually authenticated. An attacker who administers their own GitHub organization (and thus can legitimately sign `membership` webhooks for that org) can send a payload whose `team.id` equals the `github_id` of a pre-existing, sensitive `Team` belonging to a *different* org (e.g. one already provisioned via `Shipit.github_teams`), causing `team.add_member(member)` to attach a `Membership` on that sensitive team instead of on the attacker's own team.

### Finding Description
The broken binding: `organization whose webhook_secret verified the request == organization that owns the Team row being mutated` — is **not enforced**.

`WebhooksController#verify_signature` selects the HMAC key via `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight out of attacker-controlled JSON (`params.dig('repository','owner','login') || params.dig('organization','login')`): [1](#0-0) [2](#0-1) 

This only proves the request was signed with *that org's* configured `webhook_secret` — each org has its own independently configured secret (`lib/shipit/github_app.rb`, `@webhook_secret = @config[:webhook_secret]`) — it says nothing about which `team.id`/`team.organization` the payload is allowed to reference.

`MembershipHandler#process` then resolves the team purely by numeric `github_id`, with no check that `params.organization.login` matches the found team's `organization`: [3](#0-2) 

If a `Team` row for the sensitive org already exists (e.g. pre-populated by `Shipit.github_teams`, which calls `Team.find_or_create_by_handle` for each admin-configured trusted team): [4](#0-3) [5](#0-4) 

then `Team.find_or_create_by!(github_id: params.team.id)` returns that *existing* record and the block (`team.organization = params.organization.login`) is skipped entirely, because it only runs on record creation. `team.add_member(member)` then appends a `Membership` row onto the found (sensitive) team: [6](#0-5) 

Exploit flow:
1. Attacker owns/administers GitHub org `evil-org`, with a Shipit GitHub App installed (or is otherwise able to fire a validly signed `membership` webhook for `evil-org`, e.g. by adding any GitHub login to a team inside their own org — this is a normal GitHub org-owner action, not a Shipit secret).
2. Attacker learns (or guesses/enumerates) the numeric GitHub team `id` of a sensitive team belonging to `Shipit.github_teams` in a different org, `victim-org` (team IDs are commonly discoverable via the GitHub API/UI and are not secret).
3. Attacker POSTs `/webhooks` with `X-Github-Event: membership`, a signature valid for `evil-org`, and payload: `{ action: 'added', team: { id: <victim-org sensitive team's github_id>, slug: 'whatever', name: 'whatever', url: 'whatever' }, organization: { login: 'evil-org' }, member: { login: '<attacker-or-operator-login>' } }`.
4. `verify_signature` passes because it only checks `evil-org`'s secret against `organization.login: 'evil-org'`.
5. `find_or_create_team!` matches the existing sensitive `Team` row by `github_id`, ignoring that the payload claims to be from `evil-org`.
6. `team.add_member(member)` inserts a `Membership` binding an arbitrary user to the sensitive team.

Existing guards fail because: signature verification is scoped by an attacker-supplied `organization.login` field used only to select the *verification key*, not to constrain which `Team` row can be touched; `Membership` validates only intra-request uniqueness (`user_id` unique per `team_id`), not organization provenance; and `ExplicitParameters` only enforces field *types/presence*, not cross-field authorization.

### Impact Explanation
An attacker with control over one legitimate (but Shipit-irrelevant) GitHub organization can grant an arbitrary GitHub login `Membership` in a `Shipit.github_teams`-trusted team belonging to a completely different, sensitive organization. Since `User#authorized?` grants application access based on `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, this is a direct escalation into `Shipit.github_teams` authorization for whichever login the attacker names (themselves, or by naming an already-registered operator's login to implicate/piggyback on them). This is repeatable against any pre-existing `Team` record whose `github_id` the attacker can learn, across arbitrary tenants, matching the High severity category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Preconditions: the attacker needs (a) control of any GitHub org configured in Shipit's `github:` secrets with its own `webhook_secret` (or any org for which they can produce a validly signed `membership` webhook by performing a real team-membership change in their own org), and (b) the numeric `github_id` of a pre-existing sensitive `Team` row (obtainable via public/organization-visible GitHub API team metadata). No Shipit secrets, sessions, or API tokens are required — matching the stated unprivileged attacker model. This is fully repeatable per target team/org.

### Recommendation
Scope the team lookup by both `github_id` and `organization` derived from the *verified* signing organization, e.g.:
```ruby
Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login.downcase)
```
and additionally verify that `params.organization.login` matches the org used in `verify_signature` (`repository_owner`) before processing, rejecting the webhook if an existing `Team` with that `github_id` belongs to a different `organization` than the one that signed the request.

### Proof of Concept
Under `test/controllers/webhooks_controller_test.rb` (or `test/models/team_test.rb`), add a minitest:
```ruby
test ":membership webhook cannot attach a member to a team from a different organization" do
  sensitive_team = shipit_teams(:shopify_developers) # organization: 'shopify', existing github_id
  @request.headers['X-Github-Event'] = 'membership'

  # Signed as 'evil-org', but referencing shopify's team github_id
  Shipit.stubs(:github).with(organization: 'evil-org').returns(stub(verify_webhook_signature: true))

  payload = {
    action: 'added',
    team: { id: sensitive_team.github_id, name: 'Fake', slug: 'fake', url: 'http://x' },
    organization: { login: 'evil-org' },
    member: { login: 'walrus' },
    repository: { owner: { login: 'evil-org' } }
  }.to_json

  assert_no_difference -> { sensitive_team.memberships.count } do
    post :create, body: payload, as: :json
  end
end
```
Assert both sides of the binding: `organization.login` (`'evil-org'`, the org that signed the request) must equal `sensitive_team.organization` (`'shopify'`) before a `Membership` write is allowed; currently they diverge and the write still succeeds.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/team.rb (L17-27)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
      end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
