### Title
Query-string parameters can override the webhook payload used to select the signature-verifying GitHub App, bypassing HMAC verification - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which configured GitHub App's `webhook_secret` to verify the request against based on `repository_owner`, which is derived from `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) . However, the value actually processed by the event handlers in `create` is re-parsed directly from `request.raw_post` [3](#0-2) . In Rails, `ActionController` params merge query-string parameters over body-parsed parameters at the top level (`request_parameters.merge(query_parameters)`), so a `repository` key supplied in the query string overrides the entire `repository` object that came from the signed JSON body when computing `params.dig('repository', 'owner', 'login')`. This creates exactly the "authenticated organization vs. repository actually written" binding mismatch: the organization whose `webhook_secret` gates admission is not the organization whose data is written by the handler.

### Finding Description
`verify_signature` picks the GitHub App config with `Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(header, request.raw_post)` [1](#0-0) . `verify_webhook_signature` trivially returns `true` when the selected app has no `webhook_secret` configured (an explicitly supported, documented case — "Webhook secret (optional)" in `docs/setup.md`) [4](#0-3) . Because `repository_owner` is computed from the mutable `params` hash (query + body merged) rather than from the exact bytes that were HMAC-verified, an attacker can supply a query string that swaps in an organization with no `webhook_secret` (or one whose secret they know), causing `verify_webhook_signature` to short-circuit to `true` without validating anything meaningful about the actual `raw_post` — the same raw body whose `X-Github-Event`/JSON is separately re-parsed in `create` and dispatched to handlers such as `Shipit::Webhooks::Handlers::MembershipHandler`, which trusts the payload to find-or-create `Team`/`User` records and call `team.add_member(member)` [5](#0-4) , and `Shipit::Webhooks::Handlers::PushHandler`, which triggers `stack.sync_github` [6](#0-5) .

Equality broken: `organization used to select verify_webhook_signature's secret` (from `params.dig('repository','owner','login')`, attacker-influenceable via query string) ≠ `organization/repository whose full JSON is actually dispatched to handlers` (from `JSON.parse(request.raw_post)`, the value that is nominally HMAC-signed).

### Impact Explanation
If the deployment configures at least one GitHub organization without a `webhook_secret` (an explicitly supported/documented configuration) alongside a target organization that does have a secret, an unauthenticated attacker can forge a `membership` webhook that is accepted as "verified" and have `MembershipHandler` add an arbitrary GitHub login to a `Team`. Since `User#authorized?` grants access based on membership in `Shipit.github_teams` [7](#0-6) , this is a direct escalation into `Shipit.github_teams` authorization — matching the "High" impact bucket (escalation into `Shipit.github_teams` authorization). It can similarly be used to forge `push`/`status`/`pull_request`/`check_suite` events against any repository tracked by Shipit, triggering unauthorized syncs/deploy-relevant state changes without a valid signature for the target organization.

### Likelihood Explanation
Requires: (a) the Shipit instance to be configured for more than one GitHub organization where at least one lacks a `webhook_secret` (explicitly supported per `docs/setup.md`, "Webhook secret (optional)"), or has a secret the attacker can learn/guess, and (b) attacker ability to send arbitrary unauthenticated HTTP requests to the public `/webhooks` endpoint with a crafted query string plus arbitrary JSON body — both trivially satisfied, since `WebhooksController` requires no session, `ApiClient` token, or other credential. Likelihood is Medium-High for multi-org deployments with any secret-less/weak-secret org configured; not exploitable in single-org deployments where the same org is always selected (in which case the merge is a no-op since query and body would reference the same org's secret).

### Recommendation
Do not derive the organization used for signature selection from mutable `ActionController::Parameters`. Instead, parse `repository_owner` from the same immutable, already-verified byte string (`request.raw_post`) that is used for both the HMAC check and the later `JSON.parse` in `create`, and reject requests where query-string parameters attempt to inject a `repository`/`organization` key. Additionally, consider treating a missing `webhook_secret` for a matched organization as a hard misconfiguration error rather than an implicit bypass, or require verification against the *actual* target repository's organization only (never one influenced by request parameters outside the verified body).

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has `webhook_secret: S`) and `attacker-org` (no `webhook_secret` configured, or a known one).
2. Attacker sends:
   ```
   POST /webhooks?repository[owner][login]=attacker-org
   X-Github-Event: membership
   Content-Type: application/json

   {
     "action": "added",
     "team": {"id": 999, "name": "evil", "slug": "evil", "url": "https://x"},
     "organization": {"login": "victim-org"},
     "member": {"login": "attacker-github-login"},
     "repository": {"owner": {"login": "victim-org"}, "full_name": "victim-org/some-repo"}
   }
   ```
3. In `verify_signature`, `params.dig('repository','owner','login')` resolves to `"attacker-org"` from the query string (overriding the body's `repository.owner.login`), so `Shipit.github(organization: 'attacker-org')` is used; its `webhook_secret` is blank, so `verify_webhook_signature` returns `true` with no header check at all [1](#0-0) [4](#0-3) .
4. `create` re-parses `request.raw_post` (the JSON body above, unaffected by the query string) and dispatches to `MembershipHandler`, which creates the `Team` scoped to `victim-org` and calls `team.add_member(member)` for `attacker-github-login` [8](#0-7) .
5. If `victim-org`'s team is one of `Shipit.github_teams`, the attacker's GitHub login is now authorized in Shipit per `User#authorized?` [7](#0-6) , without ever presenting a valid signature for `victim-org`.

**Uncertainty**: I could not execute this against a live Rails instance to confirm the exact precedence of `request_parameters.merge(query_parameters)` in this specific Rails version, nor whether `ActionController::Base` (used by `WebhooksController`, not `ApplicationController`) applies any additional parameter-wrapping/filtering that could block query-string injection of a `repository` key. This should be verified empirically (e.g., via a Devin session reproducing the request against a running instance) before treating this as fully confirmed rather than a structurally-supported analog.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
