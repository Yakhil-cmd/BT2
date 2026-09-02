### Title
Webhook signature verification selects the signing organization from an unverified payload field, letting the org whose secret is used diverge from the repository the handler writes to - ([File: app/controllers/shipit/webhooks_controller.rb](app/controllers/shipit/webhooks_controller.rb))

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to HMAC-verify against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted JSON body, before any signature has been validated. All the actual webhook handlers (`Shipit::Webhooks::Handlers::Handler#repository_name`, and `PullRequest::OpenedHandler#repository`) instead resolve the target `Repository`/`Stack` from the *independent* `repository.full_name` field. Nothing ties these two fields together, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is blank for the selected org. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` computes the signing org from the payload itself: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` skips verification entirely when no secret is configured for that org: [3](#0-2) 

Multi-org setups are explicitly supported, and `webhook_secret` is documented as optional per app/org (`# nil` in the sample configs): [4](#0-3) 

Once the signature check passes (either because it matches, or because the selected org has no `webhook_secret` configured at all), the request body is dispatched to handlers, all of which independently resolve the actual `Repository`/`Stack` to act on from `repository.full_name`, completely decoupled from `repository.owner.login` used above: [5](#0-4) [6](#0-5) 

`PushHandler` and `PullRequest::OpenedHandler` are two concrete examples that use this repository resolution to mutate real state (trigger a sync, or create/provision a `ReviewStack`): [7](#0-6) [8](#0-7) 

`MembershipHandler` is a more sensitive example: it reads `organization.login` to create/attribute a `Team`, and mutates team membership (`Team#add_member`) based on attacker-controlled `member.login` and `team` fields, gated only by the same signature check: [9](#0-8) 

**Concretely**: on a Shipit instance configured with two GitHub orgs, e.g. `OrgOne` (secret set, hosts the real target stacks) and `OrgTwo` (no `webhook_secret` configured, as shown to be a legitimate/documented configuration), an attacker submits a POST to `/webhooks` with header `X-Github-Event: push` and a body where `repository.owner.login = "OrgTwo"` (so `verify_signature` resolves `Shipit.github(organization: "OrgTwo")`, whose `verify_webhook_signature` short-circuits to `true` because `webhook_secret` is blank) but `repository.full_name = "OrgOne/victim-repo"`. `verify_signature` passes unconditionally, and `PushHandler#stacks` then resolves and acts on the real `OrgOne/victim-repo` stack via `Repository.from_github_repo_name("OrgOne/victim-repo")`.

The binding broken: **organization authenticated (`OrgTwo`, unauthenticated because it has no webhook secret) != repository written (`OrgOne/victim-repo`, protected in intent by a real secret)**.

### Impact Explanation
This lets an unauthenticated network attacker who knows only that a second, loosely-configured (or secret-less) GitHub org/app is registered on the same Shipit instance forge webhook events that are dispatched against any other org's tracked stacks/repositories, without needing that org's `webhook_secret`. Concretely reachable actions include: forcing `stack.sync_github` (push events), creating/unarchiving `ReviewStack`s and enqueueing provisioning for pull-request events, and creating/mutating `Team` membership via `MembershipHandler`, all cross-organization. Team membership changes are particularly severe because `Shipit.github_teams` membership is the authorization mechanism gating privileged UI actions (deploys, locks, API client management) elsewhere in the app, so this can be used to escalate into that authorization boundary.

### Likelihood Explanation
Exploitability depends entirely on whether the Shipit deployment has at least one org configured with a blank `webhook_secret` (shown to be an explicitly supported/documented state) while other orgs are actually protected. Where that holds, no credentials, tokens, or the webhook secret of the target org are needed at all - only knowledge of the second org's name and any tracked repository's `owner/name`. Where every configured org has a secret, direct signature guessing is required, which is not realistically feasible (out of scope per rules). The severity/likelihood is therefore conditional on the "no secret configured for at least one org" state, which the codebase itself treats as a normal, supported configuration rather than a hardening requirement.

### Recommendation
Do not select the verification key or bypass verification based on unauthenticated payload fields. Concretely:
- Remove the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`, or require `webhook_secret` to be present for every configured organization at boot.
- After signature verification, before dispatching to handlers, assert that the `repository.owner.login`/`organization.login` used to select the verifying org actually matches the owner embedded in `repository.full_name` (or better, resolve the target `Repository`/`Stack` first and verify the signature using **that** repository's own org secret, not a value read out of the same unverified payload).

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `OrgOne` (webhook_secret set, hosts stack `OrgOne/victim-repo`), `OrgTwo` (webhook_secret left blank/`nil`), mirroring the supported layout in `test/dummy/config/secrets_double_github_app.yml`.
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/victim-repo" }
}
```
No `X-Hub-Signature` header is required to match anything real.
3. `WebhooksController#verify_signature` computes `repository_owner = "OrgTwo"`, calls `Shipit.github(organization: "OrgTwo").verify_webhook_signature(...)`, which returns `true` immediately because `OrgTwo`'s `webhook_secret` is blank (`lib/shipit/github_app.rb:76-83`).
4. `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) resolves `stacks` via `Repository.from_github_repo_name("OrgOne/victim-repo")` and invokes `stack.sync_github(expected_head_sha: "deadbeef")` on the real `OrgOne` stack, despite the request never being authenticated as `OrgOne`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

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
