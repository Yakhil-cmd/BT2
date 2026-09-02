### Title
Organization Chosen for Webhook Signature Verification Is Not Bound to the Repository/Team Acted On, Allowing Cross-Organization Forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization config used to check the HMAC signature by reading `repository_owner` straight out of the still-unverified JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . That value is used only to pick which `GitHubApp` (and therefore which `webhook_secret`) verifies the signature: `github_app = Shipit.github(organization: repository_owner); verified = github_app.verify_webhook_signature(...)` [2](#0-1) . Once `verified` is true, the entire raw JSON body is handed unmodified to the event handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .

The handlers, however, do **not** re-derive the repository/organization from the same field used for signature selection. `Handler#repository_name` (used by e.g. `PushHandler`) reads `payload.dig('repository', 'full_name')` [4](#0-3) , and `Repository.from_github_repo_name` splits that string on `/` to look up the target `Repository`/`Stack` [5](#0-4) . Similarly, `MembershipHandler#process` trusts `params.organization.login` to create/attach a `Team` and grant it members, independent of whatever org key was used to verify the signature [6](#0-5) .

Critically, `GitHubApp#verify_webhook_signature` treats an organization with no configured secret as automatically verified: `return true unless webhook_secret` [7](#0-6) . Shipit explicitly supports multi-organization deployments where each org has its own (optionally absent) `webhook_secret`, as shown in the fixture `secrets_double_github_app.yml` where both `OrgOne` and `OrgTwo` have `webhook_secret: # nil` [8](#0-7) .

### Finding Description
This is the same TOCTOU/binding-confusion bug class as the Sherlock M-2 report: a security check is evaluated against one piece of state/identity (`totalTokenXBalance()` before the transfer / here, `repository.owner.login` used to pick the verifying secret) while the operation that follows acts on a *different* piece of data that was never covered by that check (the minted amount after re-entrant `provide` / here, `repository.full_name` or `organization.login` used to select the `Repository`, `Stack`, or `Team` acted upon).

Concretely, the binding that should hold is:

`organization authenticated by verify_signature == organization/repository the handler subsequently writes to`

but nothing enforces this equality. Both `repository.owner.login` and `repository.full_name` (or `organization.login` for membership events) are read from the *same unverified* JSON body, and the code never checks that they agree. If any organization configured in Shipit has a blank `webhook_secret` (a documented, supported configuration — see `docs/setup.md` and the double-org fixture), signature verification for that organization always returns `true` regardless of what signature header (or none) is sent. An attacker can then submit an unauthenticated POST to `/github/webhooks` with `repository.owner.login` (or `organization.login`) set to the org with no secret, while setting `repository.full_name` (or the `team`/`organization` fields for `membership` events) to point at a **different**, secured organization's repository, stack, or team.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding called out as in-scope. Concretely reachable impacts:
- Forged `push`/`status`/`check_suite` events causing `stack.sync_github` or check-run refreshes to run against an arbitrary stack belonging to a different, properly-secured organization, without ever presenting a valid signature for that organization.
- Forged `membership` events (`MembershipHandler#process`) that create/attach a `Team` and add an attacker-chosen GitHub login as a member of that team — a direct escalation into `Shipit.github_teams`-based OAuth authorization, since Shipit team membership gates access to the application in this engine's authentication flow.
- Forged `pull_request` events driving `ReviewStackAdapter` to archive/unarchive/provision review stacks for repositories that were never validated against the signing organization.

This matches the High-impact category "escalation into `Shipit.github_teams` authorization" explicitly listed as in scope, and depends on no privileged token, session, or GitHub write access — only knowledge that at least one configured organization has no webhook secret (a documented supported configuration), i.e., no credential is required for that org.

### Likelihood Explanation
Likelihood is conditioned on the deployment having at least one Shipit-managed GitHub organization configured without a `webhook_secret`. This is not a hypothetical edge case: it's the exact configuration shown in Shipit's own multi-org test fixtures (`secrets_double_github_app.yml`) and is permitted by the setup documentation (`webhook_secret` is described as optional). In such a deployment, the vulnerable path requires nothing more than an unauthenticated HTTP POST with a crafted JSON body — no signature, no credentials, no session.

### Recommendation
After verifying the signature for the organization derived from the payload, re-validate that every organization/repository identifier subsequently consumed by handlers (`repository.full_name`, `organization.login` in membership events, etc.) is consistent with the organization whose secret was used to authenticate the request — e.g., assert that `repository.full_name.split('/').first == repository_owner` (case-insensitively) before dispatching to handlers, and reject the request otherwise. Alternatively, resolve the target `Repository`/`Team` first, and use its owning organization (not attacker-supplied fields) to pick the signing secret, eliminating the two-source-of-truth problem entirely.

### Proof of Concept
1. Deploy Shipit with two organizations configured, `OrgOne` (no `webhook_secret`, as in `test/dummy/config/secrets_double_github_app.yml`) and `OrgTwo` (configured `webhook_secret`, with a stack tracking `OrgTwo/victim-repo`).
2. As an unauthenticated attacker, POST to `/github/webhooks` with header `X-Github-Event: push` and no (or any) `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" }
}
```
3. `verify_signature` computes `repository_owner = "OrgOne"`, calls `Shipit.github(organization: "OrgOne").verify_webhook_signature(...)`, which returns `true` unconditionally because `OrgOne` has no `webhook_secret` [9](#0-8) .
4. The request passes verification and is dispatched to `PushHandler`, which resolves the target stack via `Repository.from_github_repo_name("OrgTwo/victim-repo")` [4](#0-3)  and triggers `stack.sync_github` on `OrgTwo`'s protected stack — despite the attacker never presenting a valid signature for `OrgTwo`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-8)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
```
