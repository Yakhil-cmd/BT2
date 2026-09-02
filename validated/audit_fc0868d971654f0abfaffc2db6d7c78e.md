### Title
Webhook signature validation selects the trust anchor from an unauthenticated field, decoupling the authenticated organization from the repository actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` chooses *which* GitHub App's `webhook_secret` to validate the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the still‑unverified JSON body, before the signature has been checked. [1](#0-0) [2](#0-1)  The `create` action and every `Shipit::Webhooks::Handlers::Handler` subclass then independently determine the repository/stack to mutate using a *different* field from the same untrusted body, `repository.full_name`. [3](#0-2)  Nothing ties these two fields together, and `GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatically "verified": `return true unless webhook_secret`. [4](#0-3)  In a multi-organization deployment (a documented, supported configuration where each org gets its own `app_id`/`private_key`/`webhook_secret`), this creates an equality break: **the organization whose secret authenticated the request ≠ the organization/repository whose stack the handlers act on.** [5](#0-4) 

### Finding Description
1. On every inbound POST to `/webhooks`, `verify_signature` looks up `repository_owner` from the raw JSON body and asks `Shipit.github(organization: repository_owner)` for that org's `GitHubApp` instance, then verifies the `X-Hub-Signature` header against **that org's** `webhook_secret`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 

2. `create` re-parses the same raw body and dispatches to handlers with the full payload; handlers resolve the *target* repository/stack using `repository.full_name`, entirely independent of the field used to pick the verification secret:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

3. `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the org's `webhook_secret` is blank — a state the setup docs explicitly present as a normal, optional configuration (`webhook_secret: # nil`):
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) [7](#0-6) 

Because `repository.owner.login`/`organization.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon stack) are two independently attacker-controlled JSON fields in the same unauthenticated body, and are never cross-checked against each other, an operator's multi-org configuration collapses the "which org authenticated this request" check and "which repository/stack is mutated" check into unrelated trust domains. If any one configured organization in the fleet has a blank/never-rotated `webhook_secret` (or an attacker manages to obtain/guess any single org's secret through any means outside this engine, e.g. a leaked non-privileged webhook secret for an unrelated low-value org), the same request can carry a `repository.full_name` pointing at a completely different, high-value org's stack — and the handler layer will happily act on it, because it never re-derives or re-validates the organization that was actually authenticated in `verify_signature`.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding. Concretely, an attacker who satisfies the (comparatively weak, non-`webhook_secret`-privileged) precondition of controlling a signature valid for *any one* configured org can forge webhook events that:
- Alter an unrelated org's `Shipit::Commit` statuses (`status` event), which feed directly into `Stack#deployable?` / `MergeRequest#all_status_checks_passed?`, potentially enabling an unauthorized deploy or an unauthorized merge through the merge queue on a repository the attacker has no legitimate relationship with. [8](#0-7) 
- Archive/unarchive review stacks or trigger provisioning/deprovisioning (`pull_request` events) for stacks belonging to a different org. [9](#0-8) 
- Create arbitrary `Shipit::User`/`Team` membership records or trigger GitHub syncs for repos outside the attacker's control.

This matches the High-severity bucket ("escalation into `Shipit.github_teams` authorization" territory, or enabling an unauthorized deploy/merge) once the forged status/PR events are combined with existing merge-queue/deploy automation.

### Likelihood Explanation
Exploitability is gated on the operator running a multi-organization `Shipit.github` configuration (explicitly documented and supported) where at least one configured org has no `webhook_secret`, or on the attacker separately obtaining a valid signature for any single low-privilege org. Given the docs list `webhook_secret` as optional and show `# nil` as the default value in example configs, this is a realistic, not purely theoretical, deployment state.

### Recommendation
- Do not let the request body dictate which secret is used to authenticate itself. Verify the HMAC using every configured org's secret (or a global secret) and only accept the payload once at least one valid signature is found, rather than trusting `repository.owner.login` to pick the verifier.
- After a signature verifies against a specific org's `GitHubApp`, assert that `repository.full_name`'s owner matches that same org before dispatching to handlers, rejecting the event otherwise.
- Stop treating a blank `webhook_secret` as automatically verified; require an explicit, logged opt-in (e.g., a separate `insecure_webhooks: true` flag) instead of silent pass-through in `verify_webhook_signature`.

### Proof of Concept
Given a multi-org `secrets.github` config with `OrgA` (no `webhook_secret`) and `OrgB` (private, high-value repos):
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything   # ignored because OrgA has no webhook_secret

{
  "sha": "<victim commit sha in OrgB repo>",
  "state": "success",
  "context": "ci/forced",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/private-repo" }
}
```
`verify_signature` resolves `repository_owner` to `"OrgA"`, whose `verify_webhook_signature` returns `true` unconditionally (blank secret). [4](#0-3)  `create` then dispatches to the `status` handler, which resolves the target strictly via `repository.full_name` = `"OrgB/private-repo"`, forging a successful CI status on `OrgB`'s real commit despite the request never being signed with `OrgB`'s secret. [3](#0-2)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit/engine.rb (L46-51)
```ruby
      if Shipit.github.oauth?
        OmniAuth::Strategies::GitHub.configure(path_prefix: '/github/auth')
        app.middleware.use(OmniAuth::Builder) do
          provider(:github, *Shipit.github.oauth_config)
        end
      end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
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
