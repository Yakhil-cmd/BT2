### Title
Webhook signature verified against `repository.owner.login` while every handler acts on the independent `repository.full_name` field — allows a valid webhook credential holder to trigger actions against stacks belonging to other organizations - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but the HMAC only certifies "this raw body was signed with org X's secret." Every downstream handler then determines *which repository/stack to mutate* using a different, uncorrelated field in the same JSON body — `repository.full_name` — via `Handler#repository_name`. Nothing ties `repository.owner.login` to `repository.full_name`, so a party who legitimately possesses one organization's webhook secret can forge a payload whose signature validates for their own org while `repository.full_name` names a stack belonging to a completely different, unrelated organization.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The HMAC secret used is selected purely from `repository.owner.login` inside the same attacker-suppliable JSON body, and `verify_webhook_signature` only checks that the raw bytes match that org's secret — it makes no claim about any other field in the payload: [3](#0-2) 

Every handler, however, resolves the target stack from a *different* field, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

Because `Repository.from_github_repo_name` looks up `owner/name` independently of who "authenticated" the request, a payload can claim `"repository": {"owner": {"login": "attacker-org"}}` (used only for signature selection) while `"repository": {"full_name": "victim-org/victim-repo"}` (used for the actual mutation). This is exactly the "organization that authenticated versus the repository that is written" binding break called out in the analog rules: the verified equality should be `repository_owner_used_for_signature == repository_owner_acted_on`, but the code never enforces it.

Concretely: `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` for stacks resolved via `full_name`, regardless of `repository.owner.login`: [5](#0-4) 

`StatusHandler#process` writes commit statuses to arbitrary commits matched by `sha` across all stacks (statuses aren't even scoped by repository at all — any commit with a matching SHA in *any* repo gets a forged CI status attached): [6](#0-5) 

`MembershipHandler#process` creates/updates `Team` records and adds/removes arbitrary GitHub users to/from teams that gate `Shipit.github_teams` authorization, keyed by `params.team.id`/`params.organization.login`, again taken from body fields not bound to the signing organization: [7](#0-6) 

### Impact Explanation
An entity that legitimately owns one Shipit-registered GitHub organization (and therefore knows that organization's own `webhook_secret`, which is a normal, expected credential for an org admin — not a stolen application secret) can forge a signed webhook whose `repository.full_name`/`sha`/`team`/`organization.login` fields point at a *different* organization's stacks, commits, or teams:
- Trigger unauthorized syncs/deploys of another org's stack (`PushHandler`, `CheckSuiteHandler`) — unauthorized deploy/rollback trigger path.
- Forge CI/commit statuses on arbitrary commits across the whole install (`StatusHandler`), which can be used to mark a malicious commit as "deployable" for a victim stack.
- Escalate into `Shipit.github_teams` authorization by creating/joining teams (`MembershipHandler`) that gate `User#authorized?` for the whole application.

This directly matches the in-scope High-impact class: "escalation into `Shipit.github_teams` authorization" and borders on "unauthorized deploy" (Critical), since a forged `push`/`status` sequence can drive an unauthorized deploy of another organization's stack.

### Likelihood Explanation
Requires the attacker to control a legitimate GitHub organization that is configured as a Shipit "app" (has its own registered `webhook_secret`), which is a realistic, unprivileged-relative-to-other-tenants position in a multi-tenant Shipit deployment. No `ApiClient` token, session, or GitHub App private key is needed — only the webhook secret the attacker's own org already possesses, which is the intended credential for *that org's* webhooks, not for cross-tenant actions. The mismatch between the field used for signature-org-selection and the field used for target resolution is a straightforward, always-reachable code path (`verify_signature` → `Webhooks.for_event(event).each { |handler| handler.call(params) }`).

### Recommendation
After verifying the signature, re-derive the authorized organization and require `repository.full_name.split('/').first == repository_owner` (and similarly bind `organization.login` for org-level events like `membership`) before dispatching to handlers, rejecting the webhook with 422 on mismatch.

### Proof of Concept
Conceptual forged request (assuming attacker administers `attacker-org`, a Shipit-registered organization, and knows its `webhook_secret`):
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>
Body:
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha, e.g. one already present in victim stack history>",
  "repository": {
    "owner": { "login": "attacker-org" },      // used only to pick the secret for verify_signature
    "full_name": "victim-org/victim-repo"       // used by Handler#repository_name / PushHandler to pick the target stack
  }
}
```
`verify_signature` uses `Shipit.github(organization: "attacker-org")` and succeeds because the HMAC was computed with `attacker-org`'s own known secret over this exact body. `PushHandler` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack — an action the attacker has no authorization over.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
