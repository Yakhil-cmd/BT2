### Title
Cross-org webhook signature confusion lets a blank-secret org's identity be used to bypass signature verification while mutating an arbitrary victim repository's stacks - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org secret to validate the HMAC signature against using `params.dig('repository', 'owner', 'login')`, while the actual handler (`OpenedHandler`) resolves the target `Repository` independently via `params.repository.full_name`. Nothing binds these two fields together, so in a multi-org Shipit deployment, an attacker can name an org with a blank `webhook_secret` in the `owner.login` field (which trivially passes verification per `GitHubApp#verify_webhook_signature`) while pointing `full_name` at a completely different, properly-secured victim repository.

### Finding Description
Binding claimed: `repository_owner (used for signature verification) == owner of repository.full_name (the repo actually mutated by the handler)`. Tracing the code shows this binding does **not** hold:

- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login')` and calls `Shipit.github(organization: repository_owner)` to fetch that org's `GitHubApp`, then calls `verify_webhook_signature`. [1](#0-0) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the org's configured `webhook_secret` is blank: `return true unless webhook_secret`. [2](#0-1) 
- In multi-org mode (`secrets.github` keyed by org rather than top-level GH keys), `Shipit.github_app_config(organization)` looks up the config solely by the `organization` string passed in — i.e., by `repository.owner.login` from the attacker-controlled payload. [3](#0-2) 
- `Webhooks::Handlers::PullRequest::OpenedHandler#repository` resolves the record to mutate via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a **separate** field from `owner.login`, with no cross-check that `full_name`'s owner prefix matches `owner.login`. [4](#0-3) 

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request`, body `{"action":"opened", ..., "repository": {"owner": {"login": "<blank-secret-org>"}, "full_name": "<victim-org>/<victim-repo>"}}`. `verify_signature` looks up `<blank-secret-org>`'s `GitHubApp`, finds its `webhook_secret` blank, and returns `true` regardless of the actual `X-Hub-Signature` header value (or its absence). The request proceeds to `OpenedHandler`, which loads the real victim `Repository` by `full_name`, and if that repository has `review_stacks_enabled` and `provisioning_behavior_allow_all?`, creates a real `ReviewStack`/`PullRequest` and queues provisioning — all without ever validating a signature tied to the victim org's actual secret.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema on `OpenedHandler` only validates types/presence of `full_name`, `owner.login`, etc., not that they are mutually consistent; there is no repository-ownership cross-check anywhere in the verification or handler path.

### Impact Explanation
An attacker who can get any single org onto Shipit's multi-org config with a blank `webhook_secret` (e.g., a low-priority integration org, a newly-added org pending secret rotation, or any org an operator forgot to configure) can forge webhooks that create `ReviewStack`s (with real provisioning/deploy side effects) for **any other repository** tracked by Shipit, regardless of that victim repository's own org having a properly configured secret. This is repeatable against arbitrary tracked repositories and matches the Critical category "a payload for one repository mutating another's stack." The blast radius spans all repositories across all orgs configured in the same Shipit instance, since the handler trusts `full_name` independently of the org used for signature verification.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (`secrets.github` keyed by org), and (2) at least one org configured in that map with a blank/missing `webhook_secret`. Given (1) and (2), the attack costs a single unauthenticated HTTP POST with no secrets, no GitHub App keys, and no signature — fully repeatable at will. The only precondition outside attacker control is operator misconfiguration of one org's secret, which is a plausible real-world state (e.g., staged rollout of a new org) that the engine does nothing to prevent or warn about, and which the engine's own decoupling of "org used for verification" vs. "org actually mutated" turns into a full authentication bypass for unrelated repositories.

### Recommendation
Bind the verified org to the repository actually mutated: after resolving the target `Repository` via `full_name` in each handler (or centrally in `WebhooksController`), verify that the resolved repository's real owner/org matches `repository_owner` used for signature selection, and reject the request otherwise. Additionally, treat a blank `webhook_secret` for a configured org as a hard misconfiguration (e.g., raise/refuse in `GitHubApp#verify_webhook_signature` rather than defaulting to `true`) instead of silently permitting unsigned webhooks for that org.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style):
```ruby
test "webhook signed by a blank-secret org cannot mutate a different org's repository" do
  # Precondition: multi-org secrets config with two orgs:
  #   "low-security-org" => { webhook_secret: nil, ... }
  #   "victim-org"        => { webhook_secret: "s3cr3t", ... }
  # victim_repo belongs to "victim-org", review_stacks_enabled + provisioning_behavior_allow_all?

  request.headers['X-Github-Event'] = 'pull_request'
  body = JSON.parse(payload(:pull_request_opened))
  body['repository']['owner']['login'] = 'low-security-org'   # verification org (blank secret)
  body['repository']['full_name'] = victim_repo.github_repo_name # mutated org (victim-org)
  # no X-Hub-Signature header set at all

  assert_difference -> { Shipit::Stack.count }, 1 do
    post :create, body: body.to_json, as: :json
  end
  assert_response :ok
end
```
Assertions on both sides of the binding: `repository_owner` resolved in `verify_signature` == `"low-security-org"`, while the `Repository` actually mutated in `OpenedHandler#repository` == the record for `victim-org/victim-repo`. The two are unequal yet the request is accepted and a stack is created, demonstrating the broken binding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
