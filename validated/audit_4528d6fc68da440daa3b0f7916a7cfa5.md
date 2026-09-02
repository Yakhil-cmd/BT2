### Title
Webhook signature is verified against the GitHub App selected by the payload's `repository.owner.login`/`organization.login`, but event handlers act on the repository identified by the separate, unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `Shipit::GitHubApp` (and therefore which `webhook_secret`) to check the `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* JSON body. [1](#0-0)  Once the signature check for that selected app passes, every registered handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, PR handlers, etc.) is invoked with the same raw params, and each of them locates the target `Repository`/`Stack`/`Commit` using a *different* field, `repository.full_name`, via `Handler#repository_name` / `Repository.from_github_repo_name`. [2](#0-1)  Nothing ties the organization whose secret validated the request to the repository that the handler subsequently mutates. This is the same class of bug as the reported liquidation issue: the entity that is cryptographically vetted (`repository.owner.login` → GitHub App secret) is not the entity actually operated on (`repository.full_name` → Stack/Repository).

### Finding Description
- Signature verification: `Shipit.github(organization: repository_owner)` looks up the app config keyed by `repository_owner`, computed from the payload itself, and `verify_webhook_signature` explicitly **returns true (bypasses verification) if that org's `webhook_secret` is blank**: `return true unless webhook_secret`. [3](#0-2) 
- Multi-org installs are an explicitly supported and documented configuration (`config/secrets.development.shopify.yml`, `docs/setup.md`), each org with its own independent `webhook_secret`. [4](#0-3) 
- Handler dispatch never re-derives or checks which org actually authenticated the request; `Handler#repository_name` simply reads `payload.dig('repository', 'full_name')` to resolve the `Repository`/`Stack` to act on, and `PushHandler`, `StatusHandler`, `MembershipHandler`, and the pull-request handlers all inherit or use variants of this pattern. [5](#0-4) [6](#0-5) 

Because `repository.owner.login`/`organization.login` (used for auth) and `repository.full_name` (used for the write) are two independently-attacker-controlled JSON fields inside the same unauthenticated payload before verification, and because verification degrades to a no-op for any org configured without a `webhook_secret`, an attacker only needs knowledge of (or access to) one org in the Shipit instance's config that has no secret (or whose secret they know) to forge webhooks that are dispatched as if they came from an entirely different, better-protected org/repo. The binding broken is: `organization that authenticated == repository that is written`, which does not hold.

### Impact Explanation
This crosses the "escalation into `Shipit.github_teams` authorization" / "unauthorized deploy" bar explicitly listed as in-scope High/Critical impacts:
- `MembershipHandler` creates/populates `Team` records and adds/removes `User` memberships purely from payload content (`params.team`, `params.organization.login`, `params.member.login`), with no relationship at all to the repository fields used to select the signature — so a forged/weakly-authenticated `membership` webhook can add an attacker-controlled GitHub login to a `Team` that is part of `Shipit.github_teams`, escalating an otherwise unauthorized GitHub identity into an authorized Shipit user via `User#authorized?`. [7](#0-6) [8](#0-7) 
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for any `Stack` under the repository named in `repository.full_name`, letting a forged webhook drive sync/merge-queue behavior for a stack outside the org whose secret actually validated the signature. [6](#0-5) 
- `StatusHandler` writes commit statuses that feed into deploy/merge gating logic for arbitrary commits matched by `sha`, again independent of the authenticated org. [9](#0-8) 

### Likelihood Explanation
Requires: (1) a Shipit deployment tracking repositories under more than one configured GitHub App/org (a supported, documented setup), and (2) at least one configured org's `webhook_secret` being blank/nil, or the attacker being able to derive/register an org with a secret they control (they need only be able to complete a webhook signed with a valid-but-different org's secret). The `webhooks_controller_test.rb` and `github_app.rb#verify_webhook_signature` show this "blank secret ⇒ verified" branch is intentional current behavior, not a hypothetical. [10](#0-9)  No repository write access, `ApiClient` token, or session is required — only the ability to POST to the public `/webhooks` endpoint, which fits the "no privileged credential" constraint for this analysis.

### Recommendation
Bind the organization that authenticates the request to the repository the handler is allowed to act on. Concretely:
- After selecting `github_app` in `WebhooksController#verify_signature`, also require that every repository/organization login referenced anywhere in the payload (in particular `repository.full_name`'s owner segment) matches `repository_owner`, and reject (422) on mismatch.
- Alternatively, look up the target `Repository`/`Stack` in the controller (not deep inside each handler) and confirm `stack.repository.owner == repository_owner` before dispatching to handlers.
- Do not allow `verify_webhook_signature` to silently succeed when `webhook_secret` is blank in a multi-org configuration; require every configured org to set a secret, or explicitly refuse to route webhooks for orgs without one.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `victim-org` (has `webhook_secret: S`) and `attacker-org` (no `webhook_secret` set, per the documented optional config). [4](#0-3) 
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 48, "name": "Deployers", "slug": "deployers", "url": "https://example.com"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker-github-handle"},
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/some-repo"}
}
```
   No valid `X-Hub-Signature` is required because `Shipit.github(organization: "attacker-org")` has a blank `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally. [11](#0-10) [3](#0-2) 
3. `MembershipHandler#process` runs unconditionally, creating/looking up the `deployers` team (which may be part of `Shipit.github_teams` for `victim-org`) and adding `attacker-github-handle` as a member, without ever checking that the acted-upon team/org matches `victim-org`. [7](#0-6) 
4. If `deployers`/`Deployers` corresponds to one of `Shipit.github_teams`, `attacker-github-handle`'s corresponding `User#authorized?` now returns true, granting UI/API access previously restricted to legitimate `victim-org` members. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L19-38)
```ruby
        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
