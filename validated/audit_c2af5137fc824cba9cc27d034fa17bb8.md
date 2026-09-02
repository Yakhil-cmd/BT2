### Title
Webhook signature verification is bound to the wrong "organization", allowing cross-repository writes to any Stack once a single onboarded organization has no `webhook_secret` configured - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate an inbound webhook against using `repository_owner`, a value taken straight from the unauthenticated JSON body. The event handlers, however, resolve the actual `Repository`/`Stack` to mutate using a *different* field from the same untrusted body (`repository.full_name`), with no requirement that the two agree. Combined with `GitHubApp#verify_webhook_signature` returning `true` whenever that organization's `webhook_secret` is blank, this breaks the intended equality `organization authenticated == repository written`.

### Finding Description
`verify_signature` picks the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')` — both attacker-controlled JSON fields, read *before* any signature has been validated.

`Shipit.github(organization: repository_owner)` returns a `GitHubApp` configured for that organization, and `verify_webhook_signature` intentionally treats a blank `webhook_secret` as always-valid: [3](#0-2) 

Meanwhile, every default handler determines the record it will act on from an entirely separate field of the same request body, `repository.full_name`, with no cross-check against the organization used for signing: [4](#0-3) [5](#0-4) 

Nothing in `Handler#stacks`/`#repository_name`, nor in the concrete handlers (e.g. `PullRequest::ClosedHandler#repository`, `PullRequest::OpenedHandler#repository`), verifies that `repository.owner.login` (used to pick the verifying `GitHubApp`) matches the owner segment of `repository.full_name` (used to pick the `Repository`/`Stack` that gets written): [6](#0-5) [7](#0-6) 

As a result: if the deployment has *any* configured organization whose `webhook_secret` is blank/unset — a state the engine explicitly supports (`@webhook_secret = @config[:webhook_secret].presence`, `test/dummy/config/secrets_double_github_app.yml` even ships a fixture organization with `webhook_secret: # nil`) — an unauthenticated attacker can:
1. Set `repository.owner.login` (or `organization.login`) to that no-secret organization so `verify_webhook_signature` short-circuits to `true` with no signature at all.
2. Set `repository.full_name` (or, for `membership` events, `team.id`/`organization.login`) to point at a completely unrelated, fully-secured victim repository/stack/team.
3. The event is dispatched to the real handler, which trusts `repository.full_name`/`team.id` and mutates state belonging to the victim organization — e.g. archiving/unarchiving review stacks (`PullRequest::LabeledHandler`, `UnlabeledHandler`), creating pull-request-driven review stacks (`OpenedHandler`), or adding an attacker-controlled GitHub login to a `Team` whose `github_id` happens to match one referenced by `Shipit.github_teams` (`MembershipHandler#find_or_create_team!`, which looks the team up by `github_id` only, ignoring `organization`): [8](#0-7) 

This is exactly the binding class called out in scope: *"an organization that authenticated versus the repository that is written."* The verifying identity (`repository_owner` → `GitHubApp`/secret) and the acted-upon identity (`repository.full_name` / `team.id`) are never required to be equal.

### Impact Explanation
Once any single onboarded organization lacks a `webhook_secret`, the attacker gains an unauthenticated write path into any Stack/Repository/Team tracked by the Shipit instance, including ones belonging to organizations that *do* have a properly configured secret. This can archive/unarchive review stacks, forge pull-request-driven provisioning against arbitrary repositories, and — via the `membership` handler's `github_id`-only team lookup — potentially inject a user into a `Team` whose id collides with one in `Shipit.github_teams`, escalating into the app's authorization boundary (`User#authorized?`). This matches the High-impact criterion "escalation into `Shipit.github_teams` authorization" and the general cross-repository-write criterion.

### Likelihood Explanation
Requires: (a) at least one configured `GitHubApp` organization with a blank `webhook_secret` — an officially supported configuration state in this engine, not a host-app misconfiguration — and (b) the attacker being able to reach the public `/webhooks` endpoint, which requires no Shipit session, API token, or repository access at all. No GitHub credentials or write access to any repository are needed; the entire attack is a single unauthenticated `POST` with a crafted JSON body.

### Recommendation
- Require `webhook_secret` to be present for every configured `GitHubApp`; refuse to boot or reject all webhooks for an organization without one instead of treating a blank secret as "verified".
- After signature verification, enforce that the organization used to verify the signature matches the owner of every repository/team referenced inside the payload before dispatching to handlers (i.e., derive `Repository`/`Team` lookups from the same verified organization context, not from independently-trusted payload fields).
- In `MembershipHandler#find_or_create_team!`, additionally bind on `organization` (not `github_id` alone) so a team record cannot be mutated by a webhook whose verified organization differs from the team's stored `organization`.

### Proof of Concept
1. Configure Shipit with two organizations: `secure-org` (proper `webhook_secret`) and `open-org` (blank/unset `webhook_secret`), both with the GitHub App "installed" per `Shipit.github_apps` config.
2. Without any secret or signature, `POST /webhooks` with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "opened",
  "number": 1,
  "pull_request": { "...": "required PullRequest::OpenedHandler fields ..." },
  "repository": { "owner": { "login": "open-org" }, "full_name": "secure-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "open-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally, and no `X-Hub-Signature` header is required.
4. `PullRequest::OpenedHandler#repository` resolves `Shipit::Repository.from_github_repo_name("secure-org/victim-repo")` and, if provisioning is enabled, creates/mutates a `ReviewStack` for the victim's fully-secured repository — despite the request never being signed with `secure-org`'s secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
