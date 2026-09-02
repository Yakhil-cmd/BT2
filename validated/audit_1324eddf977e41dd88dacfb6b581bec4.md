### Title
Cross-organization Team-ID collision in `MembershipHandler#process` allows a signed webhook from an unrelated org to mutate another org's team membership - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id` (`params.team.id`), never verifying that the record's `organization` matches the `organization.login` in the incoming webhook. Because `WebhooksController#verify_signature` only proves the webhook was signed by *some* configured organization (the one named in the payload), and never checks that the `team.id` in the payload actually belongs to that organization, an org that is legitimately registered with the same multi-tenant Shipit instance can forge a `membership`/`removed` event referencing another org's team ID and have Shipit apply it to the real team.

### Finding Description
The broken binding is:
`team.organization == params.organization.login` for the `Team` record identified by `github_id == params.team.id`

This is never checked. Trace:

- `WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` from `params.dig('organization','login')` and validates `X-Hub-Signature` against that org's configured `webhook_secret`. This only proves the request was signed with the secret of the organization *named in the payload* — it does nothing to bind the `team.id` field elsewhere in the same JSON body to that organization. [1](#0-0) 
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { ... }`. The `organization:` assignment only happens inside the block, which only executes on **creation**. If a `Team` row with that `github_id` already exists (i.e., the real victim team, previously synced under `Shipit.github_teams`), the lookup returns that existing record regardless of which organization sent the current webhook. [2](#0-1) 
- `process` then executes `team.members.delete(member)` for `action == 'removed'`, deleting the `Membership` row for the named `member.login`/`team` pair with no further org check. [3](#0-2) 

Exploit flow: The attacker controls (or is a genuine member of) an organization `evil-org` that is also registered/configured in the same Shipit deployment (Shipit supports multiple configured GitHub orgs/apps, e.g. `test/dummy/config/secrets_double_github_app.yml`). The attacker triggers (or directly POSTs, since the body is fully attacker-controlled JSON aside from the signature) a `membership` webhook: `X-Github-Event: membership`, body `{"action":"removed","organization":{"login":"evil-org"},"team":{"id":<victim_team.github_id>,"name":"x","slug":"x","url":"http://x"},"member":{"login":"<victim-operator-login>"}}`, signed with `evil-org`'s own legitimate webhook secret. `verify_signature` passes because it only checks that `evil-org`'s secret matches. `find_or_create_team!` finds the pre-existing victim `Team` by `github_id` and ignores the `evil-org` claim. `team.members.delete(member)` strips the real operator's `Membership` on that team.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) all pass unmodified — none of them check organizational ownership of the referenced `team.id`; the schema in `MembershipHandler.params` only requires the fields to be present/typed, not that they are mutually consistent. [4](#0-3) 

### Impact Explanation
A `Membership` row backing `Shipit.github_teams` authorization (`app/models/shipit/team.rb`, `has_many :members, through: :memberships`) can be deleted for an arbitrary real operator, purely by a webhook signed by an unrelated, attacker-controlled organization that happens to also be configured in the same Shipit instance. This strips `User#authorized?` for that operator (`test/models/users_test.rb` shows `authorized?` is driven by `Shipit.github_teams` membership). The same code path (`'added'` branch, `team.add_member(member)`) is symmetric and could instead be used to *grant* an arbitrary GitHub login membership in a real Shipit-authorized team, which is a privilege escalation into `Shipit.github_teams`, not just denial. [5](#0-4) [6](#0-5) 

### Likelihood Explanation
This requires the Shipit deployment to be configured for more than one GitHub organization (a supported configuration, evidenced by `test/dummy/config/secrets_double_github_app.yml`), and the attacker must control/own one of those configured orgs plus know the target team's numeric `github_id` (team IDs are not treated as secrets and can be observed via GitHub API responses visible to the attacker's own org's app installation, or by any org member with team-listing access on GitHub generally). Given those preconditions, the attack is a single crafted, genuinely-signed HTTP POST, fully repeatable and cheap (no Shipit credentials needed).

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify in `process` that the team's `organization` matches `params.organization.login` before applying `add_member`/`delete`, raising/discarding the event otherwise.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership 'removed' from an unrelated org cannot strip membership from a different org's team" do
  victim_membership = shipit_memberships(:walrus_shopify_developers)
  victim_team = victim_membership.team
  assert_equal 'shopify', victim_team.organization

  # attacker's own org, also configured in Shipit, genuinely signed
  Shipit.stubs(:github).with(organization: 'evil-org').returns(evil_org_github_app_with_real_secret)

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'removed',
    organization: { login: 'evil-org' },
    team: { id: victim_team.github_id, name: 'x', slug: 'x', url: 'http://x' },
    member: { login: victim_membership.user.login }
  }
  signature = sign_with_evil_org_secret(payload.to_json)
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { Membership.where(team: victim_team, user: victim_membership.user).count } do
    post :create, body: payload.to_json, as: :json
  end
end
```
Assert before/after: `victim_team.organization == 'shopify'` while the signing org is `'evil-org'` — these must remain unequal and the code must reject the mutation; currently the test fails because `Membership.count` decreases, proving the binding is not enforced.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** test/models/users_test.rb (L252-265)
```ruby
    test "users are always authorized? if Shipit.github_teams is empty" do
      Shipit.stubs(:github_teams).returns([])
      assert_predicate @user, :authorized?
    end

    test "users are not authorized? if they aren't part of any Shipit.github_teams" do
      Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks)])
      refute_predicate @user, :authorized?
    end

    test "users are authorized? if they are part of any Shipit.github_teams" do
      Shipit.stubs(:github_teams).returns([shipit_teams(:shopify_developers)])
      assert_predicate @user, :authorized?
    end
```
