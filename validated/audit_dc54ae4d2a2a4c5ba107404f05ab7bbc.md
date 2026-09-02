### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while handlers act on the independently-read `repository.full_name` / `organization.login`, allowing a webhook signed with one organization's secret to trigger writes against another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC using a value extracted from the same untrusted JSON body it is about to verify, and this value is not cross-checked against the field the downstream handler actually uses to select which `Stack`/`Repository`/`Team` record to mutate.

### Finding Description
`verify_signature` computes the organization used to look up the webhook secret directly from the request body: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) straight out of the same JSON payload whose integrity that org's secret is meant to protect. The signature check only proves "this body was signed with *some* configured org's secret" - it does not prove any relationship between that org and the `repository.full_name` (or `organization.login`) value the handler later uses to select which record to write to.

Handlers resolve the target independently, from the very same attacker-supplied body, with no cross-check against `repository_owner`:
- `Handler#repository_name` / `#stacks` resolve via `payload.dig('repository', 'full_name')`: [3](#0-2) 
- `PushHandler#process` uses that repository's stacks to enqueue `GithubSyncJob` with an attacker-chosen `expected_head_sha`: [4](#0-3) 
- `MembershipHandler#process` resolves/creates a `Team` from `params.team.id` and adds/removes a `member` purely from the organization-scoped payload, with no re-validation that `organization.login` matches the org whose secret validated the request: [5](#0-4) 
- `Repository.from_github_repo_name` performs a plain owner/name lookup with no tie back to the authenticating org: [6](#0-5) 

Because `repository.owner.login` (used for the signature-secret lookup) and `repository.full_name` (used for the actual write target) are two independent fields inside the same fully attacker-controlled JSON body, nothing prevents them from disagreeing. An attacker who legitimately controls a GitHub organization/repository that is itself connected to this Shipit instance (and therefore possesses/receives that org's `webhook_secret` via normal GitHub webhook delivery to their own repo) can craft and sign a payload where `repository.owner.login` (or `organization.login`) is their own org, but `repository.full_name` (or the `team`/`member` fields for membership events) references a victim organization's repository/team. `verify_signature` will authenticate the request using the attacker's own legitimate secret, then the handler will act on the victim's `Stack`/`Team` because it re-reads the target from the untrusted body instead of trusting the value that was actually used for authentication.

### Impact Explanation
This breaks the binding "organization that authenticated == repository/organization actually written," which is explicitly called out as in-scope. Concretely:
- Via `PushHandler`, an attacker can enqueue `GithubSyncJob` for a victim stack with an attacker-chosen `expected_head_sha`, causing the victim stack to sync/append commits and re-cache its deploy spec (`CacheDeploySpecJob`) based on attacker-influenced timing/state - a cross-repository write to a stack the attacker has no authorization over.
- Via `MembershipHandler`, an attacker can find-or-create a `Team`/`User` and add or remove memberships tied to a victim `organization.login`, which can affect `Shipit.github_teams` authorization checks (`User#authorized?`) — an escalation into the engine's team-based authorization.

Both outcomes fall under the defined High-impact categories ("escalation into `Shipit.github_teams` authorization" and unauthorized writes to stack state via unauthenticated-for-that-org input).

### Likelihood Explanation
Exploitability requires only that the attacker control (or compromise) one legitimate GitHub organization/repository that has a Shipit App/webhook configured with a known secret to them (a normal "unprivileged" position relative to any *other* org's stacks in the same Shipit deployment) — no Shipit session, `ApiClient` token, or GitHub App private key is needed. Since `X-Hub-Signature` verification never ties the authenticated org to the acted-upon `repository.full_name`/`organization.login`, likelihood is moderate-to-high in any multi-tenant Shipit deployment serving more than one GitHub organization.

### Recommendation
Bind the value used for HMAC-secret selection to the value used for record resolution: after verifying the signature for `repository_owner`, re-derive/validate that `repository.full_name`'s owner segment (or `organization.login` for org-scoped events) exactly equals the `repository_owner`/org used to select the secret, and reject the webhook otherwise. Alternatively, verify the signature against every configured secret only for the org actually implicated by `full_name`/`organization.login`, not a value read ad hoc from the body.

### Proof of Concept
1. Attacker owns `attacker-org/attacker-repo`, which has a Shipit GitHub App configured with `webhook_secret = S_attacker`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "repository": {
    "owner": {"login": "attacker-org"},
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(S_attacker, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully verifies using `S_attacker` (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `PushHandler#process` resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and enqueues `GithubSyncJob` for the victim's stack with `expected_head_sha` set to the attacker's chosen SHA (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), even though the attacker has no relationship to `victim-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
