### Title
Cross-organization webhook forgery escalates into `Shipit.github_teams` authorization - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/user.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization credentials to use for HMAC verification based on a payload field that is independent of the actual authorization-relevant data the resulting handler acts on. For `membership` events (and generally), the signature only proves the sender knows the webhook secret of *some* configured GitHub organization on the instance — not that they are authorized to affect the specific `Team`/`User` state that `Shipit.github_teams` uses instance-wide to grant deploy authorization.

### Finding Description
`verify_signature` derives the organization used for HMAC verification from the payload itself, not from any pre-validated source: [1](#0-0) 

The organization is resolved via: [2](#0-1) 

For `membership` events there is no `repository` object in the payload, so `repository_owner` falls back to `params.dig('organization', 'login')`. The signature is verified against `Shipit.github(organization: <that login>)`'s `webhook_secret` — i.e., it only proves the sender controls the webhook secret configured for *that particular* organization's GitHub App installation on this Shipit instance.

Once verification passes, `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler`, which creates/updates a `Team` record and adds a `User` as a member (confirmed by the existing test coverage for `:membership creates the mentioned team on the fly` and `:membership creates the mentioned user on the fly`): [3](#0-2) 

Crucially, deploy-authorization in this engine is **not** scoped per organization — it is a single, global check: [4](#0-3) 

`User#authorized?` checks membership against `Shipit.github_teams` — a flat, instance-wide list of authorized teams — regardless of which organization's webhook installation produced that `Team`/membership record. This breaks the binding: *the organization whose webhook secret authenticated the request* ≠ *the authorization scope (`Shipit.github_teams`) that gets written*. An operator who administers any organization configured on the shared Shipit instance (and therefore legitimately knows that organization's own `webhook_secret`) can forge a signed `membership` webhook event referencing the **team id/slug that is actually listed in `Shipit.github_teams`** (which may belong to a completely different, more privileged organization) and add an arbitrary GitHub login as a member of it.

### Impact Explanation
This directly escalates into `Shipit.github_teams` authorization — explicitly listed as a High-impact outcome. Any user added this way becomes `authorized?` and gains access to privileged actions gated on team authorization (e.g., approving/triggering deploys), even though the only credential proven was a webhook secret for an unrelated, lower-privilege organization.

### Likelihood Explanation
Requires the attacker to control (or be an admin of) at least one organization's GitHub App installation on the same multi-tenant Shipit instance — a low bar in shared/multi-org deployments, and explicitly an "unprivileged attacker" relative to the victim organization's authorization scope. No repository write access, API token, or session is required; only the ability to send a crafted, self-signed webhook to the shared `/webhooks` endpoint.

### Recommendation
`verify_signature` and the subsequent handlers must bind the verified organization to the entity being mutated. Concretely: reject/ignore `membership` (and other org-scoped) events unless the organization that signed the payload matches the organization actually associated with the `Team` being created/modified (e.g., validate `Team#organization` against `repository_owner` before allowing membership changes), rather than trusting the payload's `organization.login` in isolation for both verification and mutation scope.

### Proof of Concept
1. Attacker administers Org-A's GitHub App on a shared Shipit instance and knows Org-A's `webhook_secret`.
2. Attacker crafts a `membership` event payload: `organization.login = "org-a"`, `team = { id: <id-of-team-in-Shipit.github_teams>, slug: <victim-team-slug> }`, `member.login = "attacker-controlled-login"`, `action = "added"`.
3. Attacker signs the raw JSON with Org-A's `webhook_secret` and sets `X-Hub-Signature` accordingly, then POSTs to `/webhooks`.
4. `verify_signature` resolves `repository_owner` to `"org-a"` (no `repository` key present), calls `Shipit.github(organization: "org-a").verify_webhook_signature(...)`, which succeeds because the attacker legitimately knows Org-A's secret.
5. `MembershipHandler` processes the event and adds the attacker-controlled login to the victim team referenced by `Shipit.github_teams`.
6. `User#authorized?` now returns `true` for that login, granting deploy authorization instance-wide — despite no credential belonging to the victim organization ever being presented.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-149)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
