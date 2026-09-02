### Title
Webhook signature verification silently succeeds when no `webhook_secret` is configured, allowing unauthenticated forged webhooks to escalate into `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` treats "no secret configured" as an implicit pass, returning `true` without validating any cryptographic proof that the request came from GitHub. This mirrors the CVE-2024-8096 bug class: a verification routine that is supposed to gate trust returns a "success" result for a case ("nothing to check") that the caller (`WebhooksController#verify_signature`) treats identically to a fully verified signature. The org key used to select which check (if any) applies is attacker-influenced payload data (`repository.owner.login` / `organization.login`), while the object actually mutated by the handler (`Team`/`Membership`, which feeds directly into `Shipit.github_teams` authorization) is trusted unconditionally once `verified` is truthy.

### Finding Description
`WebhooksController#verify_signature` resolves the `GitHubApp` instance for the organization named in the untrusted request body, then asks it to verify the signature: [1](#0-0) 

`verify_webhook_signature` is: [2](#0-1) 

`return true unless webhook_secret` means: if that organization's config has no `webhook_secret` set (which the setup docs explicitly call *optional*, and the sample `config/secrets.development.shopify.yml` ships with `webhook_secret: # nil`), the function reports the request as verified regardless of the actual `X-Hub-Signature` header or body content. The controller then proceeds to dispatch the raw, attacker-supplied JSON to registered handlers: [3](#0-2) 

The equality that should hold is: *"the identity that produced this payload" == "the identity Shipit trusts to mutate state on its behalf"*. Instead, when `webhook_secret` is unset for the target org, that equality collapses to *always true*, because the verification step is a no-op. Any unauthenticated third party can hit the public `/webhooks` endpoint (documented, mandatory route, no `ApiClient` token or session required — this is the pre-authentication ingress point by design) and submit a `membership` event: [4](#0-3) 

This directly creates/finds a `Team` and adds an arbitrary GitHub login as a member: [5](#0-4) 

`Team` membership is exactly the binding used for authorization decisions: [6](#0-5) 

If the attacker forges a `membership` webhook naming an organization/team that matches one of `Shipit.github_teams`, and adds a login they control (or that will subsequently authenticate via OAuth), that user becomes `authorized?` in the deployment engine — all without ever presenting the GitHub App's `webhook_secret`, without repository write access, and without a Shipit session.

### Impact Explanation
This crosses the "escalation into `Shipit.github_teams` authorization" threshold explicitly called out as High-impact in the program rules. It also enables unauthenticated triggering of other handlers (`push` → `GithubSyncJob`, `status`, `check_suite`) against any stack whose repository's GitHub org has no `webhook_secret` configured, since the same no-op verification gates all events, not just `membership`. Because `webhook_secret` is documented as optional and the shipped example configs leave it blank, this is a realistic, not merely theoretical, deployment state.

### Likelihood Explanation
Likelihood is directly tied to configuration: any Shipit installation (or any single organization within a multi-org installation, since `Shipit.github(organization:)` is looked up per-org) that has not set `webhook_secret` is exposed with zero additional attacker capability required — a plain unauthenticated HTTP POST to a publicly documented route. No secret, token, or session is needed to exploit it, which matches the "unprivileged attacker" bar for this scan.

### Recommendation
Fail closed instead of open: if `webhook_secret` is blank for an organization, `verify_webhook_signature` should reject the request (or the org should be refused a `GitHubApp` webhook mount at all) rather than returning `true`. At minimum, sensitive handlers such as `MembershipHandler` (which feed `Shipit.github_teams` authorization) should not be reachable without a verified signature.

### Proof of Concept
1. Deploy Shipit with an organization entry that omits `webhook_secret` (as shown in `config/secrets.development.shopify.yml`, lines 5-9, and permitted by `docs/setup.md`).
2. Without any GitHub App private key, `ApiClient` token, or Shipit session, send:
```
POST /webhooks
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": {"id": <id of a team in Shipit.github_teams>, "name": "n", "slug": "s", "url": "u"},
  "organization": {"login": "<target-org>"},
  "member": {"login": "<attacker-controlled-login>"}
}
```
3. `verify_webhook_signature` returns `true` (no secret configured for `<target-org>`), `MembershipHandler#process` runs and calls `team.add_member(member)`.
4. Once `<attacker-controlled-login>` completes GitHub OAuth against Shipit, `User#authorized?` returns `true` via the forged team membership, granting full access to the Shipit UI/API for that installation.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L36-43)
```ruby
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
