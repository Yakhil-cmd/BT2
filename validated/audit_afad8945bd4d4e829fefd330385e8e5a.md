## Analysis

This is exactly the bug class described: a value used to establish a trust boundary (here, the **signing organization** used to verify the webhook HMAC) is decoupled from the value later used to determine **what gets written** (the repository/team acted upon).

### The binding that should hold

`organization authenticated by verify_webhook_signature == organization/repository actually written by the handler`

### Where it breaks

`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to verify the signature against using an attacker-supplied field: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), and is used only to pick which app's `webhook_secret` to HMAC-verify against: `Shipit.github(organization: repository_owner)`.

Crucially, `verify_webhook_signature` treats a missing/blank `webhook_secret` for that org as automatically valid: [3](#0-2) 

`return true unless webhook_secret` — so for any configured org whose `webhook_secret` is nil (which the setup docs list as **optional**, and which appears as `webhook_secret: # nil` in `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`), signature verification is trivially satisfied for a payload that merely *claims* `repository.owner.login` (or `organization.login`) equal to that org — with no real HMAC check at all.

Meanwhile, the actual state-mutating logic never re-derives or cross-checks the organization from `repository.owner.login`. It uses a *different* field from the same attacker-controlled JSON body — `repository.full_name` — to resolve the `Repository`/`Stack` to act on: [4](#0-3) 

and for membership events, `params.organization.login` is stored directly as the `Team#organization`, and team membership is granted based on it: [5](#0-4) 

There is nothing in `Handler#stacks`/`Handler#repository_name`, nor in `PushHandler`, that checks `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` value that was used to select the verification secret. These are two independent JSON fields inside the same attacker-controlled body.

### Exploit

An unprivileged, unauthenticated attacker (no Shipit session, no `ApiClient` token, no GitHub write access needed) posts to `/webhooks` with `X-Github-Event: push` and a body such as:

```json
{
  "repository": { "owner": { "login": "org-with-no-webhook-secret" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```

`repository_owner` resolves to `org-with-no-webhook-secret`. Because that org has no configured `webhook_secret`, `verify_webhook_signature` returns `true` immediately — no valid `X-Hub-Signature` is required at all. The request passes `verify_signature` and is dispatched to `PushHandler`, which resolves the target stack via `Repository.from_github_repo_name('victim-org/victim-repo')` (from `repository.full_name`) — a completely different org than the one whose (non-)secret was checked — and calls `stack.sync_github(expected_head_sha: params.after)`, forcing a sync/deploy-eligible state change on the victim's stack with an attacker-chosen SHA. The same technique works against `MembershipHandler` (forging `organization.login` to create/alter `Team` records and add arbitrary GitHub users to a `Team`, which is used for `Shipit.github_teams` authorization in `User#authorized?`), and other handlers deriving their target from `repository.full_name`.

This satisfies the required binding-break pattern: an org value is authenticated by the signature check, while a distinct (unauthenticated) repository/organization field drives the actual write — with no requirement that the two match.

### Title
Webhook signature verification keyed off unsigned `repository.owner.login`/`organization.login` allows cross-organization forgery of stack syncs and team membership - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to HMAC-verify against using an attacker-controlled JSON field (`repository.owner.login`/`organization.login`), and treats a blank/unset secret as automatically verified. Handlers then act on a *different*, equally attacker-controlled field (`repository.full_name`, `organization.login`, `team.id`) with no cross-check against the value used for verification, letting an attacker impersonate any org that lacks a `webhook_secret` while targeting another org's `Stack`/`Team`.

### Finding Description
`repository_owner` (line 59-61 of `webhooks_controller.rb`) is read from unauthenticated request body content and used only to look up which `GithubApp`'s secret to verify with. `GithubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) short-circuits to `true` when that app has no `webhook_secret` configured — an officially supported (documented as "optional") configuration shown in this engine's own fixture/config files. The downstream handlers (`Handler#repository_name`/`#stacks` in `app/models/shipit/webhooks/handlers/handler.rb:32-38`, and `MembershipHandler` at lines 22-43) never validate that the repository/organization they act on matches the organization used to select the verification key — they simply re-read a sibling JSON field from the same unsigned payload.

### Impact Explanation
An attacker with zero Shipit privileges can forge `push`, `status`, `pull_request`, and `membership` events targeting *any* repository/stack/team configured in the Shipit instance, as long as at least one configured GitHub organization has no `webhook_secret`. This can trigger unauthorized syncs with attacker-chosen `expected_head_sha`, create/alter `Team` records, and add/remove team memberships that feed into `User#authorized?` (`Shipit.github_teams` gate) — an escalation into `Shipit.github_teams` authorization, and a cross-repository/cross-tenant write via forged sync state.

### Likelihood Explanation
Medium-to-High: it requires only that one org in the multi-tenant Shipit config has no `webhook_secret` set (an explicitly supported/optional configuration per `docs/setup.md` and reflected in the shipped example configs), and no credentials, sessions, or GitHub access are needed to send the forged HTTP POST to `/webhooks`.

### Recommendation
Bind the organization used for signature verification to the same value used for authorization of the write: after selecting `repository_owner` for the secret lookup, re-validate that every field the handler will act on (`repository.full_name`'s owner segment, `organization.login`) is consistent with `repository_owner`, and reject mismatches. Additionally, do not treat an absent `webhook_secret` as automatic verification success — require a configured secret (or another positive-trust mechanism) for every organization capable of writing to Shipit state.

### Proof of Concept
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "repository": {
    "owner": { "login": "org-with-blank-webhook-secret" },
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
No `X-Hub-Signature` header is required: `verify_webhook_signature` returns `true` because `org-with-blank-webhook-secret` has no configured secret. `PushHandler` then resolves and syncs `victim-org/victim-repo`'s stack using `repository.full_name`, a field never covered by the (non-existent) signature check.

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
