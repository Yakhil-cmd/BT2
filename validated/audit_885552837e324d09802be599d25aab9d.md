### Title
Cross-organization webhook forgery: `repository.owner.login` (used for signature verification) is decoupled from `repository.full_name` (used to select the mutated stack) — ([File: lib/shipit/github_app.rb, app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret`) to verify against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')`. `Shipit::Webhooks::Handlers::Handler#stacks` (used by `PushHandler`) instead resolves the target repository from `payload.dig('repository', 'full_name')`. These are two independently attacker-controlled fields in the same unauthenticated JSON body, so a request can be verified as belonging to one organization while its `push` payload mutates stacks belonging to a completely different organization.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`organization_used_for_verification (params.dig('repository','owner','login'))` **should equal** `organization_that_owns_the_mutated_repository (parsed from payload.dig('repository','full_name'))`.

Trace:
- `Shipit::WebhooksController#verify_signature` picks the GitHub app config via `Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that org's `webhook_secret` is blank/unset, without ever parsing or comparing the `X-Hub-Signature` header: `return true unless webhook_secret` [3](#0-2) .
- `Shipit.github(organization:)` in multi-org mode resolves configuration purely from the org name string via `github_app_config(organization)` [4](#0-3) , with no cross-check against any other field of the payload.
- Once verification passes (trivially, for a no-secret org), `Shipit::Webhooks::Handlers::Handler#stacks` resolves the target `Repository` using a *different* field, `payload.dig('repository', 'full_name')` [5](#0-4) .
- `PushHandler#process` then syncs every non-archived stack on that resolved repository whose branch matches `params.ref`, calling `stack.sync_github(expected_head_sha: params.after)` [6](#0-5) .

Exploit flow: In a multi-organization `secrets.yml` configuration (documented feature, see `docs/setup.md` "Using Multiple Github Applications"), an attacker crafts one JSON body where `repository.owner.login` is a configured organization that has no `webhook_secret` set, and `repository.full_name` is `victim-org/victim-repo` (a different, properly-secured organization's repository). `X-Github-Event: push` is set; `X-Hub-Signature` can be anything or omitted since it is never inspected when the resolved org has no secret. Verification passes for the no-secret org's identity, but the handler processes and mutates state (`sync_github`) for `victim-org`'s stacks, which the request never actually authenticated against.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type is handled; `verify_signature` only ever checks one org (the attacker-chosen one) against one field (`repository.owner.login`); nothing in `WebhooksController` or `Handler` cross-validates that `repository.owner.login` and `repository.full_name`'s owner segment refer to the same organization.

### Impact Explanation
An attacker who controls no secret can drive `Shipit::Stack#sync_github` for another organization's repository/stack whenever the deployment is configured with multiple GitHub organizations and at least one of them has no `webhook_secret` configured. This can append commits into the victim's stack pipeline and trigger downstream continuous-delivery behavior (auto-deploy, merge queue progression, etc.) for a repository the attacker does not own or control — a cross-tenant state manipulation matching the "Critical" impact category (payload for one repository mutating another's stack/commit). Blast radius is scoped to installations using the multi-org config with at least one org missing `webhook_secret`; it is repeatable per request with no rate limiting concerns in scope.

### Likelihood Explanation
This requires a specific, but documented and plausible, configuration: multi-organization `secrets.yml` (`github_default_organization` non-nil) where at least one configured organization omits `webhook_secret`. Single-organization deployments are not exploitable this way because `Shipit.github(organization:)` ignores the caller-supplied organization entirely in that mode (`config = secrets.github` regardless of `repository_owner`) [7](#0-6) , so there is only one webhook_secret/app for the whole app and no cross-org divergence is possible. Given the precondition, attacker cost is minimal (a single crafted HTTP POST, no secrets needed) and the attack is fully repeatable.

### Recommendation
Cross-validate the organization used to select the verifying `GitHubApp` against the organization that will actually be mutated: derive both from the same trusted field (e.g., always use `repository.full_name`'s owner segment, or require `repository.owner.login == full_name.split('/').first`) before calling `verify_signature`, and reject the request if they diverge. Additionally, treat a missing `webhook_secret` for an organization as a hard misconfiguration (fail closed / reject webhooks) rather than silently accepting all signatures for that org.

### Proof of Concept
Minitest plan (ActionDispatch::IntegrationTest or the existing `WebhooksControllerTest` style):
1. Configure `test/dummy` secrets for multi-org mode with two orgs: `org-a` (no `webhook_secret`) and `org-b` (has a `webhook_secret`).
2. Create a `Stack`/`Repository` fixture owned by `org-b` (e.g., `full_name: "org-b/victim-repo"`) with a commit and branch matching a crafted `ref`.
3. POST to `/webhooks` with `X-Github-Event: push`, an arbitrary/garbage `X-Hub-Signature`, and body:
   ```json
   { "repository": {"owner": {"login": "org-a"}, "full_name": "org-b/victim-repo"},
     "ref": "refs/heads/master", "after": "<attacker-chosen sha>" }
   ```
4. Assert `response.status == 200`.
5. Assert `Shipit::Stack#sync_github` (or `GithubSyncJob`) was invoked/enqueued for the `org-b/victim-repo` stack — i.e., `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: "<attacker sha>"])` — proving verification against `org-a` (no secret) authorized a mutation on `org-b`'s stack.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
