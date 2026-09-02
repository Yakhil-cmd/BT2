This confirms the finding: `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, so deleting the `Membership` row directly flips `authorized?` to `false` for any user whose only qualifying team membership was removed.

### Title
Cross-organization Team ID confusion in `membership` webhook allows any onboarded org to strip a victim operator's authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up `Team` solely by the numeric `github_id` from the payload, never checking that `params.organization.login` matches the team's stored `organization`. In a multi-org Shipit deployment, signature verification is performed per-organization using the `organization.login`/`repository.owner.login` field taken directly from the attacker-controlled payload, so an attacker who administers their own onboarded org (and thus legitimately possesses that org's `webhook_secret`) can forge a `membership`/`removed` event whose `team.id` matches a different, victim org's team, deleting the victim operator's `Membership` and flipping `User#authorized?` to `false`.

### Finding Description
The broken binding: a `Membership` row for `(team_id, user_id)` should only change in response to a genuine GitHub `membership` event for that exact team, i.e. `event.organization.login == team.organization` must hold before `team.members.delete/add` executes. This binding is never checked.

Path:
1. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)`, and `repository_owner` falls back to `params.dig('organization', 'login')` when there's no `repository` key [1](#0-0) . This organization value is entirely attacker-supplied in the JSON body; it is used only to select which configured `GitHubApp`/secret to validate the signature against.
2. `Shipit.github(organization:)` resolves the per-org config from `secrets.github` in multi-org mode [2](#0-1) . An attacker who owns/administers one legitimately onboarded org (e.g. `OrgTwo`) possesses that org's real `webhook_secret` and can compute a valid `X-Hub-Signature` for a `membership` payload where `organization.login: "OrgTwo"`.
3. `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { ... }` [3](#0-2) . Because the team already exists (created earlier by a genuine event from the victim org), `find_or_create_by!` returns the existing row without checking or updating `organization` — the attacker's `organization.login` value is silently ignored.
4. `params.action == 'removed'` then executes `team.members.delete(member)` [4](#0-3) , deleting the `Membership` row for `member.login` (set to the victim operator's login) against the victim's team, regardless of which org actually sent the signed request.
5. `User#authorized?` is computed live from `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [5](#0-4) , so removing the sole qualifying `Membership` immediately deauthorizes that operator.

None of the existing guards prevent this: `verify_signature` validates that the signature matches *some* org's secret, but that org is selected by attacker-controlled payload data, not tied to the target team; `drop_unhandled_event`/`ExplicitParameters` only validate shape, not cross-org ownership; there is no check anywhere binding `team.organization` to `params.organization.login` on repeat events.

### Impact Explanation
A malicious but legitimately onboarded organization admin can deauthorize any operator belonging to `Shipit.github_teams` in a completely different tenant organization by guessing/knowing that team's numeric GitHub `github_id` (a small integer, often enumerable/brute-forceable, and potentially previously observed in prior legitimate webhook deliveries, UI, or API responses). This is a High-severity escalation/deauthorization vector affecting `Shipit.github_teams` authorization scope, repeatable per victim login and per target team id, and not limited to a single tenant — any onboarded org in a multi-org Shipit install can attack any other tenant's operators.

### Likelihood Explanation
Requires: (a) the Shipit instance runs in multi-org mode with the attacker controlling one legitimately configured org (a plausible tenant-boundary violation, not a hard secret to obtain in a multi-tenant SaaS-style deployment of Shipit), and (b) knowledge of the victim team's numeric `github_id`. Team IDs are small sequential integers and may leak through team URLs, prior webhook payloads, or GitHub's API for teams the attacker can otherwise observe. Given those, the attack is trivial to script and fully repeatable (one HTTP POST per removal).

### Recommendation
In `MembershipHandler#find_or_create_team!`, require that an existing `Team` record's `organization` matches `params.organization.login` before operating on it; raise/drop the event on mismatch instead of silently reusing the record. Additionally, `WebhooksController#verify_signature` should not let the payload's own `organization`/`repository.owner.login` value be the sole selector determining which secret authorizes mutations against records owned by a different organization — cross-check that the resolved organization equals the team/repository's persisted owner before allowing writes.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style):
```ruby
test ":membership from a different org cannot delete a victim team's membership" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: 1
  victim = shipit_users(:walrus) # already a member via fixtures
  Membership.create!(team: victim_team, user: victim) unless victim_team.members.include?(victim)

  # Attacker controls "OrgTwo" (configured with its own webhook_secret) and forges
  # a membership 'removed' event claiming team.id == victim_team.github_id but
  # organization.login == "OrgTwo"
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate valid signature for OrgTwo's own secret
  @request.headers['X-Github-Event'] = 'membership'
  body = {
    action: 'removed',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'OrgTwo' },      # attacker's own org, not 'shopify'
    member: { login: victim.login },
    repository: { owner: { login: 'OrgTwo' } }
  }.to_json

  assert_difference -> { Membership.where(team: victim_team, user: victim).count }, -1 do
    post :create, body:, as: :json
    assert_response :ok
  end

  assert_not victim.reload.teams.exists?(victim_team.id)
end
```
Both sides of the binding: expected `event.organization.login == team.organization` ("OrgTwo" != "shopify") should block the deletion; observed behavior deletes the `Membership` anyway, proving the divergence.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L26-33)
```ruby
          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
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
