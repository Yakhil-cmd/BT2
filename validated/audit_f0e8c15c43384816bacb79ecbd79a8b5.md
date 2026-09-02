### Title
Webhook signature check authenticates the payload's `organization`/`repository.owner` while every handler acts on the payload's `repository.full_name` and `team.id` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to use for HMAC verification based on an attacker-controlled field of the *same unauthenticated request body* (`repository.owner.login` / `organization.login`), but the code that actually mutates state (`PushHandler`, `MembershipHandler`, etc.) reads a *different* attacker-controlled field (`repository.full_name`, `team.id`) to decide which `Stack`/`Team` to act on. Because per-organization `webhook_secret` is documented as optional and can be blank, and because verification is keyed by a field that is never checked for consistency against the field used for mutation, an attacker can make the signature check trivially pass for a "cover" organization while the write happens against a completely unrelated repository or authorization team.

### Finding Description
The webhook endpoint requires no session or API token — it is only protected by `verify_signature`: [1](#0-0) [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
```

`repository_owner` is derived from the same untrusted JSON body: [2](#0-1) 

`Shipit.github(organization:)` resolves the per-organization config, and `GitHubApp#verify_webhook_signature` **trivially returns `true` whenever that organization's `webhook_secret` is blank**: [3](#0-2) 

Leaving `webhook_secret` empty for an organization is an explicitly supported, documented configuration (`webhook_secret # nil` is shown as a valid value in `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`, and described as "optional" in `docs/setup.md`).

Once `verify_signature` passes, `create` dispatches the *entire same payload* to handlers: [4](#0-3) 

Handlers resolve the target `Stack` using `repository.full_name` from the payload — a field completely independent of the `repository_owner`/`organization.login` field used to select the verifying secret: [5](#0-4) [6](#0-5) 

Even more severe, `MembershipHandler` creates/finds a `Team` by `team.id` and adds an arbitrary GitHub login as a member of that team: [7](#0-6) 

`User#authorized?` grants app access purely by checking cached local `Membership` rows against `Shipit.github_teams`, never re-verifying against GitHub live: [8](#0-7) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository_owner)` ≠ `repository/team actually written by the handler (repository.full_name / team.id)`.

Before the attack: the two fields normally match because a genuine GitHub webhook always sets `organization.login`/`repository.owner.login` and `repository.full_name` consistently for the same real event. After the attack: an attacker submits a single crafted JSON body where `organization.login` (or `repository.owner.login`) is set to an org configured with a blank `webhook_secret` (so `verify_webhook_signature` returns `true` unconditionally, regardless of the `X-Hub-Signature` header value), while `repository.full_name` (for push/status/etc.) or `team.id`/`team.name`/`team.slug` (for membership events) references a *different*, legitimately-configured stack or authorization team.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary called out for this class of bug, and its most severe manifestation reaches the explicitly listed High-impact bucket: **escalation into `Shipit.github_teams` authorization**. By forging a `membership` event with `action: 'added'`, an unauthenticated attacker can insert an arbitrary GitHub login into any `Team` (creating it if needed via `find_or_create_by!`), and if that team's `github_id`/handle happens to be one enumerated in `Shipit.github_teams`, the corresponding `User#authorized?` check will pass — the attacker obtains logged-in, authorized access to the whole Shipit instance without ever touching real GitHub OAuth or the real webhook secret protecting that team's real organization. It also allows unauthenticated forgery of `push`/`status`/`check_suite` events against arbitrary stacks (triggering `stack.sync_github`), independent of the actual owning organization's real webhook secret, as long as any one configured organization in the same Shipit deployment has a blank `webhook_secret`.

### Likelihood Explanation
Requires: (1) at least one GitHub organization configured in `secrets.yml` with an empty `webhook_secret` — a state the project's own example configs and docs present as a normal, supported option, and (2) knowledge of the organization login used as the "cover" org, which is public information for any GitHub org. No credentials, tokens, or GitHub App secrets are needed. This is reachable by any unauthenticated network client that can POST to `/webhooks`.

### Recommendation
- Never allow `webhook_secret` to be silently optional per-organization for verification purposes; require it, or explicitly disable verification only in test/dev environments, not via a data-dependent "blank secret" fallback.
- Verify that the field used to select the App/secret for `verify_webhook_signature` (`repository_owner`) is the *same* organization that owns the entity being mutated (`repository.full_name`'s owner, `team.organization`) before dispatching to handlers — reject if they diverge.
- For `MembershipHandler`, cross-check `params.organization.login` against the actual authenticated organization used to validate the signature, not just trust the payload.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (no `webhook_secret` set) and `OrgB` (real repo/stack `OrgB/secret-app`, with a real `webhook_secret`), as shown supported in `test/dummy/config/secrets_double_github_app.yml`.
2. POST to `/webhooks` with header `X-Github-Event: push` and any `X-Hub-Signature` value, and a body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "organization": {"login": "OrgA"},
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/secret-app"}
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the bogus signature header.
4. `PushHandler#process` resolves `stacks` via `repository.full_name` = `OrgB/secret-app` and calls `stack.sync_github(expected_head_sha: "deadbeef")` — a forged event applied to `OrgB`'s real stack despite never possessing `OrgB`'s webhook secret.
5. For the authorization-bypass variant, send `X-Github-Event: membership` with `action: added`, `team` matching one of `Shipit.github_teams`' `github_id`, and `member.login` set to the attacker's own GitHub login, again using `organization.login: "OrgA"` to trivially pass signature verification; the attacker's user gains team membership and thus `authorized?` access to the app.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
