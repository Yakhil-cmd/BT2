### Title
Membership webhook signature verification is keyed off attacker-controlled payload fields, letting a signature valid for one organization authorize team/user mutations for another - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC against by reading `organization.login`/`repository.owner.login` straight out of the untrusted JSON body being verified [1](#0-0) [2](#0-1) . `MembershipHandler#process` then trusts the payload's `team.id` and `member.login` unconditionally: it looks up an existing `Team` purely by `github_id` with no check that the team's real `organization` matches the org whose secret produced the valid signature, and resolves `member` via `User.find_or_create_by_login!`, which returns an already-existing `User` row untouched if one exists [3](#0-2) [4](#0-3) . `Team#add_member` then binds that unrelated, already-existing user to the team [5](#0-4) , which can flip `User#authorized?` to true for any team listed in `Shipit.github_teams` [6](#0-5) .

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`organization_whose_secret_verified_signature.login == team.organization` (the org owning the `Team` row identified by `params.team.id`)

and

`member.login (payload)== the GitHub account that actually just joined that team per that org's real membership`

Neither equality is checked anywhere in the call path.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` — both are attacker-supplied fields inside the very body being signed [2](#0-1) . It then calls `Shipit.github(organization: repository_owner)` and verifies the signature against **that** org's `webhook_secret` [1](#0-0) . This proves only "this payload was signed with org X's secret" where X is chosen by the attacker inside the payload — not that the payload's `team`/`member` data actually pertains to org X.
2. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [7](#0-6) . If a `Team` row with that `github_id` already exists (e.g. a privileged team belonging to a completely different, victim organization that was previously synced), it is returned as-is — the block that sets `team.organization` only runs on creation, so no organization consistency check occurs on the found path.
3. `member = User.find_or_create_by_login!(params.member.login)` finds the existing `User` by login without any verification against GitHub, since the block is skipped when the record already exists [4](#0-3) .
4. `team.add_member(member)` appends the found user to the found team's `members` association [5](#0-4) , creating a `Membership` row.

Attacker request: a POST to `/webhooks` with `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with a `webhook_secret` the attacker legitimately knows for **some** organization registered in this Shipit instance (their own org's app config), and a JSON body where `organization.login` matches that org (so signature verification passes) but `team.id` is set to the numeric `github_id` of a privileged team belonging to an unrelated victim organization, and `member.login` is the login of an existing, previously-OAuth'd privileged `Shipit::User`.

Existing guards that fail to stop this:
- `drop_unhandled_event` only checks the event type is registered, not payload consistency.
- `verify_signature` verifies a signature exists for *some* org named in the payload, not that the payload's team/member content belongs to that org.
- `ExplicitParameters` schema in `MembershipHandler` only requires field presence/type, not cross-organization ownership [8](#0-7) .
- No model validation ties `Team#organization` to the webhook's verified org during lookup-by-`github_id`.

### Impact Explanation
A successful request silently inserts a `Membership` row binding an already-existing, potentially privileged `Shipit::User` to an arbitrary `team.id`, without that user's GitHub account having actually joined that team, and without the payload's verified organization matching the team's real organization. Since `User#authorized?` is computed as team membership against `Shipit.github_teams` [6](#0-5) , this is a direct escalation into `Shipit.github_teams` authorization for a user who never consented and for an organization that never authenticated this action — matching the High severity category ("escalation into `Shipit.github_teams` authorization"). It is repeatable against any `team.id` the attacker can enumerate/guess and any existing login, and the blast radius spans every tenant/org configured in the same Shipit instance since `Team` and `User` records are global, not scoped per organization's webhook secret.

### Likelihood Explanation
Preconditions: the attacker must control (or self-register) at least one organization/app entry in Shipit's `github` config so they know its `webhook_secret` and can produce a valid signature for their own org (a low-cost, self-service step in multi-org Shipit deployments; if that org's `webhook_secret` is left blank as shown in the example configs, no secret at all is needed) [9](#0-8) . The target team must already exist as a `Team` row (i.e., previously synced through a legitimate membership event) and the target user must already exist as a `Shipit::User` row (created via prior OAuth login), both plausible for active privileged teams/users. Given these, the attack is a single unauthenticated HTTP POST, fully repeatable, with no rate limiting concerns relevant to this scope.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that any existing `Team` found by `github_id` has `team.organization == params.organization.login` (raise/reject otherwise), and ensure the org used for signature verification in `WebhooksController#verify_signature` is cross-checked against `params.team`'s/`params.organization`'s actual claimed organization instead of trusting `repository_owner` derived purely from the payload without any independent confirmation. More broadly, do not select the verification secret using data taken from inside the payload being verified; bind the expected organization to a trusted, out-of-band source (e.g., a per-org webhook URL/route) rather than `params.dig('organization', 'login')`.

### Proof of Concept
minitest plan (controller test, no live GitHub):
1. Fixture: an existing `Shipit::User` (e.g. `shipit_users(:bob)`) with a login, simulating a prior OAuth login, and an existing privileged `Shipit::Team` (e.g. `shipit_teams(:shopify_developers)`) whose `organization` is `"shopify"` and is included in `Shipit.github_teams`.
2. Configure a second org `"attacker-org"` in `Shipit.github` config/secrets with a known `webhook_secret` (or leave blank to skip secret step), distinct from `"shopify"`.
3. Build payload: `{ action: 'added', team: { id: shipit_teams(:shopify_developers).github_id, name: ..., slug: ..., url: ... }, organization: { login: 'attacker-org' }, member: { login: shipit_users(:bob).login } }`.
4. Compute `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the raw JSON body (this is the "attacker-verified org" signature).
5. `post :create, body: payload.to_json, as: :json` with `X-Github-Event: membership` and the computed signature header.
6. Assert `response.status == 200` (signature check for `attacker-org` passes since it's the attacker's own valid secret — asserting the equality `organization_whose_secret_verified_signature.login ("attacker-org") == team.organization ("shopify")` is false yet the request still succeeds).
7. `assert_difference -> { Shipit::Membership.count }, 1` around the post.
8. After the request, `assert_includes shipit_teams(:shopify_developers).members.reload, shipit_users(:bob)`.
9. `assert shipit_users(:bob).reload.authorized?` (with `Shipit.github_teams` stubbed/configured to include `shipit_teams(:shopify_developers)`), proving escalation into `Shipit.github_teams` authorization for a user whose real GitHub account never joined that team via the attacker's org.

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

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
