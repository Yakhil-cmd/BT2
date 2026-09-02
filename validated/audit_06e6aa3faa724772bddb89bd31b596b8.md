### Title
Webhook signature-verification organization is decoupled from the repository/commit that gets written - cross-repository status/state forgery (Webhooks Controller) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, a value pulled straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`). The handlers that actually mutate application state (e.g. `StatusHandler`, `PullRequest::ClosedHandler`, `PushHandler`) instead resolve the target repository/commit from a *different* field of the same body — `repository.full_name`, or in `StatusHandler`'s case, a global `sha` lookup with no repository binding at all. Because these two fields are never checked for consistency, and because `verify_webhook_signature` trivially returns `true` when an organization has no `webhook_secret` configured (a documented, supported setup — see `config/secrets.development.example.yml`), an attacker can authenticate a webhook request as an unprotected organization while having it write state (commit statuses, review-stack archival, sync jobs) against a *different, protected* organization's repository or commit.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`GitHubApp#verify_webhook_signature` in `lib/shipit/github_app.rb`: [3](#0-2) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

`Shipit.github` resolves per-organization app configs from `secrets.github` keyed by organization name, supporting the documented multi-org schema where each org may or may not have a `webhook_secret` set: [4](#0-3) 

The handler-side resolution uses an entirely independent field of the same JSON body. For example, `StatusHandler#process` resolves the target purely from `sha`, with no repository scoping whatsoever: [5](#0-4) 

and `PullRequest::ClosedHandler` resolves the repository from `repository.full_name`: [6](#0-5) 

**Binding that should hold:** `organization authenticated by verify_signature == organization/repository the handler writes to`.

**Before the attack:** in a legitimate GitHub-originated webhook, `repository.owner.login` (used to select the signing secret) and `repository.full_name` (used by handlers) are always consistent because GitHub itself populates both from the same source repository.

**After the attack:** an attacker POSTs directly to `/webhooks` (this controller has no other authentication requirement — it explicitly skips CSRF and only gates on `verify_signature`) with a forged JSON body where `repository.owner.login` names an organization configured in `secrets.github` with **no `webhook_secret`** (or one the attacker knows), while `repository.full_name` (and/or a bare `sha`) names a resource belonging to a different, protected organization/stack that Shipit tracks. `verify_signature` authenticates successfully against the unprotected org's (nil) secret, but the handler dispatched in `create` writes state using the *other* organization's repository/commit reference.

### Impact Explanation
This lets an unauthenticated network attacker forge GitHub-originated events for a repository/stack they do not control and for which they hold no valid signing secret, as long as any other organization on the same Shipit instance has a blank `webhook_secret` (a supported, documented configuration). Concretely:
- `StatusHandler` allows forging arbitrary CI `state`/`context`/`description` onto any commit sha tracked by Shipit, system-wide, with zero repository binding at all — this can be used to fabricate "green" CI statuses that gate deploy/merge decisions.
- `PullRequest::ClosedHandler` allows archiving arbitrary review stacks belonging to a different, protected repository.
- `PushHandler`/`membership` and other handlers can similarly be triggered against a protected repo/org's stacks.

This crosses a genuine authentication boundary: the organization that authenticated the request is not the organization/repository whose state is mutated, matching the "an organization that authenticated versus the repository that is written" binding class. Forged CI statuses feeding into deploy-gating logic can escalate to an unauthorized deploy.

### Likelihood Explanation
Requires (a) a multi-organization Shipit deployment, and (b) at least one configured organization with no `webhook_secret` set — both are explicitly supported/documented configurations, not misconfigurations outside the engine's control (`config/secrets.development.example.yml` shows `webhook_secret: # nil` as a normal example). No GitHub credentials, session, or `ApiClient` token are required — only network access to the public `/webhooks` endpoint.

### Recommendation
Bind the signature-verification organization to the exact same field the handler will use to resolve the repository, and require it to be the actual owning organization of that repository/stack (not an attacker-selectable value from the payload). Additionally, disallow signature verification from unconditionally succeeding when `webhook_secret` is blank if any other organization on the instance has one configured, or require every configured organization to declare `webhook_secret` explicitly, and cross-check that `repository.owner.login` matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure two organizations in `secrets.github`: `protected-org` (with `webhook_secret: s3cr3t`) and `open-org` (with `webhook_secret` left blank), both supported by `Shipit.github_app_config`.
2. Shipit tracks a repository `protected-org/secret-repo` and has commits/stacks for it.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "open-org" }, "full_name": "protected-org/secret-repo" },
  "organization": { "login": "open-org" },
  "sha": "<known sha of a commit on protected-org/secret-repo>",
  "state": "success",
  "context": "ci/required-check"
}
```
4. `verify_signature` computes `repository_owner = "open-org"`, loads its `GitHubApp` whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes with any/no `X-Hub-Signature` header.
5. `create` dispatches to `StatusHandler`, which finds `Commit.where(sha: params.sha)` — the real commit on `protected-org/secret-repo` — and writes a forged successful status via `create_status_from_github!`, despite the attacker never possessing `protected-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
