[1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Webhook payload fields (membership grants, push refs, status) are fully acted upon without ever being covered by a verified signature when `webhook_secret` is unset - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` delegates authenticity checking to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` whenever the configured `webhook_secret` for the target organization is blank. In this state, none of the payload fields consumed downstream (team, member, action, repository, sha, etc.) are covered by any cryptographic check, yet the `create` action still dispatches the entire attacker-controlled JSON body to `Shipit::Webhooks` handlers that mutate authorization-relevant state, most notably `MembershipHandler`, which creates/removes `Team` memberships from raw payload data.

### Finding Description
`WebhooksController#create` parses the raw request body and hands it directly to registered handlers after `verify_signature` runs as a `before_action`: [4](#0-3) 

`verify_signature` selects the `GitHubApp` for the organization named inside the (still unverified) payload and asks it to verify the `X-Hub-Signature` header against the raw body: [5](#0-4) 

`GitHubApp#verify_webhook_signature` is the sole gate protecting that binding, but it short-circuits to `true` whenever no `webhook_secret` is configured for that organization: [3](#0-2) 

`webhook_secret` is documented and shipped as an optional, nil-by-default configuration key (`webhook_secret: # nil`) in both the single-app and multi-org secrets templates, so this is a reachable, "as documented" state rather than a misconfiguration outside the engine's own contract. When this condition holds, `head(422) unless verified` never fires, and the controller proceeds to run every handler registered for the declared `X-Github-Event` against completely attacker-forged JSON. `MembershipHandler` (exercised in `test/controllers/webhooks_controller_test.rb`, e.g. ":membership creates the mentioned user on the fly" and ":membership can append an user membership") creates `User` records and appends `Membership` rows purely from the `member.login` / `team` / `action` fields of the payload, with no re-validation against GitHub. Because `User#authorized?` and the `force_github_authentication` gate solely check `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, an attacker who can reach the public `/webhooks` endpoint (no session, no API token, no repository access needed) can add an arbitrary GitHub login of their choosing to a `Shipit.github_teams`-authorized team, then complete the normal OAuth login flow as that GitHub login to gain full authenticated access to Shipit.

This is the same class of defect as the report's rounding bug: a value that is *acted upon* (the membership/team/action fields) is never actually bound to the value that was *cryptographically verified* (nothing, since verification is a no-op) — the binding "payload processed == payload verified" silently breaks whenever `webhook_secret` is absent, which is a supported and default state of the engine's own code, not a deployment error external to it.

### Impact Explanation
This allows an unauthenticated network attacker to escalate into `Shipit.github_teams` authorization by forging a `membership` webhook that grants team membership to a GitHub login they control, then authenticating via the normal OAuth flow to obtain full authorized access to the Shipit instance (stacks, deploys, rollbacks, custom tasks). This matches the High-impact category "escalation into `Shipit.github_teams` authorization." Other handlers (`push`, `status`, `check_suite`) are equally unauthenticated in this state and can be used to inject bogus commit statuses or trigger sync jobs, but the membership escalation is the clearest, most severe path.

### Likelihood Explanation
Likelihood is contingent on an operator leaving `webhook_secret` unset for an organization — an explicitly supported, documented, nil-by-default value in `config/secrets.development.example.yml` and `docs/setup.md`'s multi-org example. No attacker credential, session, or repository access is required beyond the ability to send an HTTP POST to the public `/webhooks` route with the correct `X-Github-Event` header.

### Recommendation
Fail closed instead of failing open: `verify_webhook_signature` should reject (return `false`) when `webhook_secret` is blank, or the engine should refuse to boot/register an organization without a configured `webhook_secret`. Additionally, `MembershipHandler` should treat webhook-driven team membership changes as advisory and reconcile against a live GitHub API call (as `Team#refresh_members!` already does) rather than trusting webhook payload contents outright for security-relevant state.

### Proof of Concept
1. Configure (or note the shipped default) an organization/app in `secrets.yml` with `webhook_secret` left blank, as shown in `config/secrets.development.example.yml`.
2. As an unauthenticated network client, POST to `/webhooks` with header `X-Github-Event: membership` and a crafted JSON body:
   ```json
   {
     "action": "added",
     "team": { "id": 48, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://example.com" },
     "member": { "login": "attacker-controlled-login" },
     "organization": { "login": "target-org" }
   }
   ```
3. Because `verify_webhook_signature` returns `true` (no `webhook_secret` configured for `target-org`), `WebhooksController#create` dispatches this straight to `MembershipHandler`, which creates the `attacker-controlled-login` user and adds it as a member of the team, mirroring the behavior asserted in `test/controllers/webhooks_controller_test.rb` (":membership can append an user membership").
4. If that team is one of `Shipit.github_teams`, the attacker then completes a normal GitHub OAuth login as `attacker-controlled-login` and is granted `authorized?` access to the Shipit instance.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-15)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
