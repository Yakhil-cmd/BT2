### Title
Webhook signature verified against attacker-chosen `repository.owner.login` org while `AssignedHandler` mutates a different `repository.full_name`'s `PullRequest` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/HMAC secret to check using `repository_owner` (`params.dig('repository','owner','login')`), while `AssignedHandler#repository` resolves the target `Repository`/`PullRequest` using `params.repository.full_name`. These two fields are never checked for consistency, so an attacker can pick an org with no `webhook_secret` configured for `repository.owner.login` (which skips signature verification entirely) and point `repository.full_name` at a legitimate victim repo whose `PullRequest` record then gets overwritten with attacker-controlled data.

### Finding Description
The broken binding: the code implicitly assumes `repository.owner.login == owner_of(repository.full_name)`, but nothing enforces this equality.

- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` using only `repository.owner.login` [1](#0-0)  and `repository_owner` is read strictly from `params.dig('repository','owner','login')` [2](#0-1) .
- `Shipit.github(organization:)`, when the deployment uses the multi-org config schema (`github_default_organization` non-nil), looks up `github_app_config(organization)` for that specific org and constructs a `GitHubApp` scoped to it [3](#0-2) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that specific org has **no** `webhook_secret` configured: `return true unless webhook_secret` [4](#0-3) . So naming a configured-but-secret-less org in `repository.owner.login` makes signature verification a no-op regardless of the actual `X-Hub-Signature` header or body.
- Once past `verify_signature`, `AssignedHandler#process` never re-checks `repository.owner.login`; it resolves the repository purely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` [5](#0-4) , finds the matching `Shipit::PullRequest` joined through that repository's stacks [6](#0-5) , and unconditionally overwrites its `github_pull_request` attribute with attacker-supplied JSON on `assigned`/`unassigned` actions [7](#0-6) .

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, a body with `action: "unassigned"`, `repository.owner.login` set to a configured org that has an empty/absent `webhook_secret`, and `repository.full_name` set to `"victim-org/victim-repo"` (an org whose real webhook secret the attacker does not have). `verify_signature` authenticates the request against the no-secret org (trivially true), then `AssignedHandler` writes attacker-chosen `title`, `additions`, `deletions`, `head.sha`, `head.ref`, `assignees`, and `labels` into the victim repo's real `PullRequest` record — a payload authenticated under one repository's identity mutating a different repository's data, satisfying "a payload for one repository mutating another's stack, commit, task or team."

The `review_stacks_enabled`/provisioning-precedence angle raised in the question does not apply here: `AssignedHandler` never provisions review stacks or reads `review_stacks_enabled` — it only calls `pull_request.update(github_pull_request: params.pull_request)` on an already-existing `PullRequest` row [8](#0-7) . I found no code path in this handler that reads `review_stacks_enabled` or triggers provisioning, so the claimed "provision precedence bug amplifies the effect" is unsubstantiated for this specific handler/target.

Existing guards that fail to prevent this: `verify_signature` only checks the signature under the org named by `repository.owner.login`, never cross-checks it against `repository.full_name`'s owner; `GithubOrganizationUnknown` handling only protects against unknown orgs, not secret-less ones; there is no model validation tying `repository.owner.login` to `repository.full_name` in the handler.

### Impact Explanation
An unauthenticated internet client can overwrite the persisted `PullRequest` metadata (`github_pull_request` JSON: title, sha, ref, additions/deletions, assignees, labels) of any tracked repository/stack in the Shipit instance, as long as (a) the deployment uses the multi-org GitHub config format and (b) at least one configured org lacks a `webhook_secret`. This is a cross-tenant write authenticated under the wrong repository's identity — matching the Critical bucket "a payload for one repository mutating another's stack, commit, task or team." Because `github_pull_request` data feeds review-stack/PR based UI and downstream automation (labels/assignees drive other handlers such as `LabeledHandler`/`UnlabeledHandler`/provisioning logic), forging this data can indirectly influence provisioning or review-stack behavior of the victim repo, though this specific handler alone doesn't itself trigger deploys or command execution. This is repeatable against any stack/repo whose `full_name` is guessable (public repo names are trivially known).

### Likelihood Explanation
Requires the operator to run Shipit with the multi-org secrets schema (`secrets.github` keyed by org) and to have at least one configured org without a `webhook_secret` — a plausible but not universal configuration (e.g., staging/dev orgs added without secrets, or an org intentionally left open). No attacker credentials, GitHub App keys, or Shipit session are needed; the attacker only needs to know the victim's `owner/repo` and PR number, and needs a `PullRequest` record to already exist for that PR (created by prior legitimate `opened`/`synchronize` events). Cost is a single crafted HTTP POST, fully repeatable.

### Recommendation
In `WebhooksController#verify_signature`, after selecting `github_app` by `repository_owner`, require the resolved `GitHubApp` to have a non-blank `webhook_secret` (reject/422 if a configured org has none, rather than treating missing secret as "verified"), and additionally validate that every repository object referenced later in the payload (e.g. `repository.full_name`) belongs to the same `repository_owner` used for verification before dispatching to handlers.

### Proof of Concept
Under `test/controllers/webhooks_controller_test.rb`, add a fixture-backed test:
1. Configure a `no_secret_org` in test secrets (multi-org schema) with `webhook_secret: nil`, and a `victim_org` with a real secret.
2. Create `shipit_repositories(:victim_org_repo)` with `owner: "victim_org"`, a stack, and an existing `Shipit::PullRequest` (`number: 2`) with a known `github_pull_request` payload.
3. Build a `pull_request` webhook body: `action: "unassigned"`, `number: 2`, `repository: { full_name: "victim_org/repo" }`, `repository.owner.login: "no_secret_org"`, plus required nested fields for the `AssignedHandler` schema.
4. POST to `/webhooks` with `X-Github-Event: pull_request` and an arbitrary/garbage `X-Hub-Signature` (no valid secret known).
5. Assert response is `:ok` (not `:unprocessable_entity`), and assert the victim `PullRequest#github_pull_request` was updated to the attacker-supplied values — proving `repository_owner` used for authentication ("no_secret_org") diverged from the mutated repository's real owner ("victim_org") while the write still succeeded.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-51)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L53-65)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L67-69)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
