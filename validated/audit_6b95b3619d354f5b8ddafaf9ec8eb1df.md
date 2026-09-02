This confirms a multi-tenant configuration exists: each GitHub organization can have its own `github_app_config` with its own `webhook_secret`, looked up via `Shipit.github_app_config(organization)` [1](#0-0) , and repositories are scoped to `owner`/`name` with signature verification performed per-organization via `Shipit.github(organization: repository_owner)` [2](#0-1) .

### Title
Webhook signature verified against `repository.owner.login` while dispatch acts on the unrelated, unverified `repository.full_name` field, enabling cross-organization payload injection - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) [3](#0-2) . However, every event handler resolves which `Repository`/`Stack` the payload actually acts on using a *different* JSON field: `payload.dig('repository', 'full_name')` [4](#0-3) , which is also used directly in `PullRequest` handlers via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [5](#0-4) . Neither of these two fields is cross-checked against the other anywhere in the controller or handler chain.

### Finding Description
The equality that should hold is: **organization authenticated by signature == organization of the repository being written to**. Concretely: `params.repository.owner.login` (used to select the HMAC secret) must equal the owner segment of `params.repository.full_name` (used to look up the `Repository`/`Stack` and dispatch `sync_github`, archive/unarchive, pull-request updates, etc.).

Nothing in `WebhooksController#verify_signature` or `Handler#repository_name` enforces this. `Shipit.github(organization: repository_owner)` fetches a config keyed strictly by `repository_owner` (via `github_app_config`) [6](#0-5) , and `verify_webhook_signature` only checks that the raw body's HMAC matches that organization's own `webhook_secret` [7](#0-6) . Since an attacker who administers an installed GitHub App/webhook for **their own organization** (`attacker-org`) knows that organization's `webhook_secret` (it is configured by them when installing the app on their own org, a standard, unprivileged, self-service action supported by this multi-tenant Shipit deployment), they can freely construct any JSON payload, sign it with their own secret, and set:
- `repository.owner.login = "attacker-org"` (so `verify_signature` validates against the secret they control), and
- `repository.full_name = "victim-org/victim-repo"` (so the handler dispatches against a target repository/stack that has nothing to do with `attacker-org`).

Because `verify_signature`'s target-org lookup and the handler's target-repo lookup read two independent, unrelated fields of the same attacker-controlled JSON body, the signature only proves the request originated from *some* organization the attacker legitimately controls — not that it is authorized to act on the repository the handler will actually mutate.

### Impact Explanation
This breaks the deployment-trust binding between "the organization that authenticated the webhook" and "the repository/stack that is written." A `push` event with `full_name` pointed at a victim repo/branch triggers `stack.sync_github(expected_head_sha:)` for any matching, non-archived stack, forcing an unauthorized deploy-target ref sync [8](#0-7) . Crafted `pull_request` events (`opened`/`closed`/`labeled`/etc.) let the attacker archive, unarchive, or otherwise manipulate review stacks belonging to a victim repository they were never granted access to, since these handlers use the same unverified `full_name` field to resolve the target `Repository` [9](#0-8) . This is an unauthorized cross-organization/cross-repository state manipulation of Shipit stacks, matching the "cross-repository writes / unauthorized deploy or rollback" Critical impact class.

### Likelihood Explanation
Exploitability requires only that the attacker control one organization's `webhook_secret` in a multi-tenant Shipit deployment (a routine, self-service GitHub App installation on their own org — no privileged Shipit credential, `ApiClient` token, or repository write access to the victim is needed) and know/guess the victim's `owner/repo` `full_name` string, which is public information for any public GitHub repository. This is a low-friction, unprivileged-attacker path.

### Recommendation
In `WebhooksController#verify_signature`, derive the organization strictly from `repository.full_name`'s owner segment (or ensure `repository.owner.login` and the owner segment of `full_name` are equal) before dispatching, and reject the webhook if they diverge. Alternatively, have `Handler#repository_name` re-derive the repo strictly from the same `owner` object already validated during signature verification instead of trusting `full_name` independently.

### Proof of Concept
1. Attacker installs/configures their own GitHub App organization `attacker-org` in the Shipit multi-tenant config, obtaining its `webhook_secret`.
2. Attacker crafts a `push` payload: `{"ref": "refs/heads/master", "after": "<attacker-controlled sha>", "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}}`.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, raw_body)` and POSTs to `/github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own secret [2](#0-1) .
5. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, whose `Handler#repository_name` reads `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` [10](#0-9) , causing `stack.sync_github(expected_head_sha: params.after)` to run against the victim's stack — despite the request only having been authenticated for `attacker-org` [8](#0-7) .

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
