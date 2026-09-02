### Title
Signature verified against a webhook-selected org (`repository.owner.login`) while the PR lookup trusts a different attacker-controlled field (`repository.full_name`), allowing cross-repository `PullRequest` metadata corruption - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify the HMAC signature against using `params.dig('repository', 'owner', 'login')`, a value read straight out of the unsigned-at-parse-time raw JSON body. In multi-org configurations (`Shipit.github_default_organization` present), `Webhooks::Handlers::PullRequest::AssignedHandler#pull_request` and `EditedHandler#pull_request` instead use a different field from the same body, `params.repository.full_name`, to look up the target `Shipit::Repository`/`Stack`/`PullRequest` to mutate. Nothing ties these two fields together, so an attacker who legitimately controls the webhook secret for their own org can sign a payload that names a victim's repository in `full_name` while keeping `owner.login` set to their own org, causing the victim's `PullRequest#github_pull_request` (title, head sha/ref, labels, state) to be overwritten with attacker-supplied data.

### Finding Description
The claimed binding, stated as an equality that must hold and does not:

`org(secret used in verify_signature) == org(repository referenced by params.repository.full_name used in the PullRequest lookup)`

Path:
1. `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `github_app = Shipit.github(organization: repository_owner)` [1](#0-0) [2](#0-1) .
2. `Shipit.github` only honors the passed `organization` when the instance is configured for multi-org mode (`github_default_organization` non-nil); in that mode it fetches `github_app_config(organization)` -- i.e. `secrets.github[organization.downcase]` -- and verifies the signature with that org's own `webhook_secret` [3](#0-2) . `GitHubApp#verify_webhook_signature` performs a plain HMAC-SHA1 compare using that org-specific secret [4](#0-3) .
3. `AssignedHandler#pull_request` / `EditedHandler#pull_request` derive `repository` from an entirely different JSON field, `params.repository.full_name` (via `Shipit::Repository.from_github_repo_name`), and use it to scope the `PullRequest` lookup: `Shipit::PullRequest.joins(:stack, stack: :repository).find_by(number: params.number, stacks: { repositories: { id: repository.id } })` [5](#0-4) [6](#0-5) .
4. If found, `pull_request.update(github_pull_request: params.pull_request)` overwrites `github_id`, `number`, `api_url`, `title`, `state`, `additions`, `deletions`, `user`, `assignees`, `labels`, and `head` from attacker-controlled `params.pull_request` [7](#0-6) .

Root cause: the controller uses `repository.owner.login` to pick the trust anchor (which org's secret must sign the request), while the handlers use the unrelated `repository.full_name` field from the same untrusted body to pick which tenant's data to mutate. Nothing cross-checks that `full_name` actually belongs to the org identified by `owner.login`/the secret that validated the signature. An attacker who administers their own org's GitHub App/webhook integration (and therefore legitimately possesses that org's `webhook_secret`, as is normal for any org owner setting up a webhook integration) can craft an arbitrary raw JSON body: set `repository.owner.login = "attacker-org"` (so `Shipit.github(organization: "attacker-org")` picks attacker's own known secret) but set `repository.full_name = "victim-org/victim-repo"` and `number` = an existing victim PR number, then compute a valid `X-Hub-Signature` using the attacker's own secret. `verify_signature` passes because it validates against the attacker's own org's secret, and the handler then resolves and mutates the victim's `PullRequest` record because it only trusts `full_name`, never checking it is consistent with the org that actually signed the payload.

None of the existing guards prevent this: `verify_signature` explicitly selects the org used for verification from the same attacker-suppliable body (`owner.login`), not from any fixed/authenticated channel; `drop_unhandled_event` and the `ExplicitParameters` schema only validate presence/types of fields, not cross-field consistency between `owner.login` and `full_name`; there is no `require_permission!`/ownership check tying the verifying org to `repository.id` inside either handler.

This finding is scoped to deployments running Shipit in multi-org mode (`secrets.github` keyed by multiple organizations rather than the single top-level GitHub config). In single-org mode, `Shipit.github` ignores the `organization:` argument entirely and always uses the single configured secret, so the divergence does not create a cross-tenant issue there (though it also means `repository_owner` is never actually checked against anything, which is consistent with the single-secret model).

### Impact Explanation
A payload signed with one org's legitimate webhook secret can cause `Shipit::PullRequest#update` to overwrite title, head commit SHA/ref, labels, state, additions/deletions, assignees and author of a PR record belonging to a completely different org's stack/repository, as long as the attacker can guess/know an existing PR `number` for that victim repo. This is "a payload for one repository mutating another's stack/commit" as described in the Critical impact category: downstream logic that trusts `PullRequest#head`/`github_pull_request` state (e.g., review-stack creation, merge/deploy checks referencing PR metadata) can be corrupted. The blast radius spans all orgs configured in the same multi-tenant Shipit instance's `secrets.github`, and the attack is repeatable against any PR number in any victim repository known to the attacker.

### Likelihood Explanation
Requires: (a) Shipit configured in multi-org mode with more than one org's webhook secret registered, and (b) the attacker legitimately controlling at least one of those orgs' webhook secrets (a normal condition for any org onboarded to a shared multi-tenant Shipit instance). Given that, the attacker's cost is minimal: craft one HTTP POST to `/webhooks` with a custom JSON body and a correctly computed HMAC signature using their own known secret. No GitHub-side event needs to actually occur; it's a direct POST to the Shipit host, consistent with the stated threat model. The attack is fully repeatable and requires no elevated privileges beyond ownership of one already-configured org's webhook secret.

### Recommendation
Bind repository resolution in the handlers (and any other webhook handler using `params.repository.full_name`) to the same org identity that was cryptographically verified. Concretely: derive `repository_owner` once in the controller, verify the signature against it, and pass the verified organization identity down to handlers so they can assert `params.repository.full_name.split('/').first.casecmp?(verified_organization)` before resolving/mutating any record — rejecting the event (422/ignore) if they diverge. Alternatively, always verify using `params.repository.full_name`'s owner (not a separately-read `owner.login`/`organization.login`) so the same field drives both authentication and authorization.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/assigned_handler_test.rb` (or a new controller-level integration test):

1. Configure test secrets with two orgs, `"attacker-org"` and `"victim-org"`, each with a distinct `webhook_secret` (mirrors `test/dummy/config/secrets_double_github_app.yml` pattern already used for multi-org tests).
2. Create `victim_repository = Shipit::Repository.create!(name: "victim-repo", owner: "victim-org")`, a `Stack` on it, and a `Shipit::PullRequest` with `number: 42`, `title: "Original victim title"`, `head` pointing at a known commit sha `"aaaa...aaaa"`.
3. Build a raw JSON body:
```ruby
payload = {
  action: "assigned",
  number: 42,
  pull_request: {
    id: 999, number: 42, url: "https://api.github.com/...",
    title: "PWNED", state: "open", additions: 1, deletions: 1,
    head: { sha: "bbbb...bbbb", ref: "attacker-branch" },
    user: { login: "attacker" },
    assignees: [{ login: "attacker" }],
    labels: []
  },
  repository: { owner: { login: "attacker-org" }, full_name: "victim-org/victim-repo" },
  sender: { login: "attacker" }
}.to_json
```
4. Compute `signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_org_webhook_secret, payload)`.
5. `post shipit.webhooks_path, params: payload, headers: { 'X-Github-Event' => 'pull_request', 'X-Hub-Signature' => signature, 'Content-Type' => 'application/json' }`.
6. Assert response is `:ok` (signature accepted using attacker's own secret) — confirming binding side 1: `org(secret) == "attacker-org"`.
7. Reload the victim `PullRequest` and assert `pull_request.title == "PWNED"` and `pull_request.head.sha == "bbbb...bbbb"` — confirming binding side 2 diverged: the mutated record belongs to `"victim-org"`, not `"attacker-org"`, proving the equality claimed by the question is broken and victim data was overwritten by an attacker who only ever proved control of `"attacker-org"`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L53-69)
```ruby
          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L49-65)
```ruby
          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/pull_request.rb (L36-50)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
    end
```
