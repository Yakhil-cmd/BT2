Based on my investigation, I found a genuine binding break in the webhook signature verification path.

### Title
Webhook signature is verified against an attacker-chosen `organization`/`repository.owner.login` field while writes are performed against an independently-controlled `repository.full_name` field, allowing cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which HMAC secret) to verify a webhook against using `repository_owner`, which is read straight out of the untrusted, attacker-suppliable JSON body via `params.dig('repository', 'owner', 'login')`. All downstream `Handler` subclasses, however, resolve the `Stack`/`Repository` to write to using a *different* field of the same JSON body: `payload.dig('repository', 'full_name')`.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is [2](#0-1) . This value is taken from the JSON body the attacker fully controls (before any signature check occurs, since the signature check *uses* this field to pick the verification secret in the first place).

Meanwhile, every concrete handler (`Handler#stacks`, `PullRequest::OpenedHandler#repository`, etc.) resolves the actual target `Repository`/`Stack` using `payload.dig('repository', 'full_name')`: [3](#0-2)  and [4](#0-3) .

`repository.owner.login` and `repository.full_name` are two independent JSON keys inside the same attacker-controlled payload. Nothing in the code enforces that `full_name`'s owner segment matches `owner.login`. In Shipit's multi-tenant GitHub App configuration (`Shipit.github(organization:)` in [5](#0-4) ), each organization key can have its own `webhook_secret`. If an attacker controls (or has been granted) a legitimate GitHub App installation/secret for **any one** configured organization ("org-A"), they can craft a raw webhook body where `repository.owner.login = "org-A"` (so the signature is computed/verified with org-A's known secret) but `repository.full_name = "org-B/victim-repo"` (an entirely different organization/repository they do not control). The signature check in `verify_signature` passes because it only checked org-A's secret against org-A's claimed identity field — it never checked that `full_name` agrees with `owner.login`. The handler then proceeds to modify `org-B/victim-repo`'s `Stack`, `PullRequest`, `Commit`, or `Team`/`Membership` records via `Repository.from_github_repo_name(params.repository.full_name)` [6](#0-5) .

This is the same class of bug as the reference report: the value that is *authenticated* (the `organization`/`owner.login` field used to pick the HMAC secret) is not the value that is *acted upon* (`repository.full_name`, used to select which record in the datastore gets mutated) — an equality binding (`verified_organization == written_repository_owner`) that the code assumes but never enforces.

### Impact Explanation
An attacker with a legitimate (even low-trust) GitHub App installation/webhook secret for one organization onboarded into a multi-tenant Shipit instance can forge webhook events (`push`, `pull_request`, `status`, `check_suite`) that are accepted as authentic for a *different* organization/repository's stacks, enabling cross-repository writes: creating/mutating `PullRequest`/`ReviewStack` records, injecting fake commit `Status`/`CheckRun` records that unblock deploy/merge gating (`StatusChecker`, `all_status_checks_passed?`), or triggering `schedule_merges`/`ContinuousDeliveryJob` paths on a repository the attacker was never granted access to. This crosses the "cross-repository writes" impact bar explicitly called out in the rules.

### Likelihood Explanation
Requires the deployment to be configured with more than one organization's GitHub App credentials (Shipit's documented multi-tenant `secrets.github` schema) and requires the attacker to control/know the webhook secret for at least one onboarded organization — a modest bar in a shared/multi-tenant Shipit instance, and importantly does **not** require a Shipit session, `ApiClient` token, or GitHub App private key for the *target* organization, only for their own.

### Recommendation
After verifying the signature, cross-check that `payload.dig('repository', 'owner', 'login')` (or `organization.login`) matches the owner segment of `payload.dig('repository', 'full_name')` before dispatching to handlers, and reject the request if they diverge. Alternatively, derive the repository/stack lookup key from the same field used for signature-secret selection rather than a second independent field.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `org-a` (attacker-controlled, secret known to attacker) and `org-b` (victim, hosts a tracked `Stack`).
2. Attacker crafts a `pull_request` (or `push`/`status`) webhook JSON body with:
   - `repository.owner.login = "org-a"`
   - `repository.full_name = "org-b/victim-repo"`
   - other required fields for the event's `ExplicitParameters` schema.
3. Attacker computes `X-Hub-Signature` using `org-a`'s known `webhook_secret` over the raw body and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` (derived from `repository.owner.login`) and successfully verifies the signature against `org-a`'s secret.
5. `Shipit::Webhooks.for_event(event)` handlers then resolve `Repository.from_github_repo_name("org-b/victim-repo")` and mutate `org-b`'s `Stack`/`PullRequest`/`Commit` records, despite the attacker never having a valid secret for `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
