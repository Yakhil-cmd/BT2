### Title
Cross-tenant forgery via `webhook_secret`-less organization lookup lets an attacker overwrite another repository's `PullRequest` record through `AssignedHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to check against using `repository.owner.login`, while every `pull_request` handler (here `AssignedHandler`) resolves the actual target repository using the independent field `repository.full_name`. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's config has no `webhook_secret`, so an attacker who names an org with a blank secret in `repository.owner.login` gets a free pass through signature verification, then can set `repository.full_name` to any real victim repository, causing `AssignedHandler` to persist a forged `PullRequest#github_pull_request=` update against that victim's stack.

### Finding Description
The broken binding is: the request should only be able to mutate the repository/stack `R` such that `verify_webhook_signature` was validated against `R`'s own secret, i.e. `authenticated_repository == mutated_repository`. In this codebase these are two different fields that are never cross-checked.

- `repository_owner` (used only for auth) is read from `params.dig('repository', 'owner', 'login')` [1](#0-0) , and is used to pick the `GitHubApp` instance: `Shipit.github(organization: repository_owner)` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when that org's `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) .
- `AssignedHandler#repository` (used for the actual mutation) resolves via the *independent* field `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) , and the handler looks up and updates the persisted `PullRequest` for that repository/stack: `pull_request.update(github_pull_request: params.pull_request) if pull_request.present?` [5](#0-4) .
- `PullRequest#github_pull_request=` writes title, state, additions/deletions, user, assignees, labels and head commit onto the real DB record [6](#0-5) .

Exploit flow: the attacker registers/controls (or simply names) an org configured in Shipit whose `github` config block has no `webhook_secret` set (e.g., a sandbox/legacy org entry). They send `POST /webhooks` with header `X-Github-Event: pull_request`, `action: "assigned"`, `repository.owner.login` = that no-secret org, but `repository.full_name` = `"victim-org/victim-repo"` (a real, existing Shipit-tracked repository) and `number` matching a real open PR. `verify_signature` authenticates against the no-secret org and passes unconditionally regardless of the actual `X-Hub-Signature` header. `Shipit::Webhooks.for_event('pull_request')` dispatches to `AssignedHandler`, which looks up the victim's `PullRequest` by `number` joined through `stacks: { repositories: { id: repository.id } }` using the forged `full_name`, and persists attacker-supplied PR metadata (title, labels, assignees, head commit sha lookup) onto it. None of `drop_unhandled_event`, the `ExplicitParameters` schema, or `Repository` validations catch this because they only validate shape/format, not that `repository.owner.login` matches `repository.full_name`'s owner segment.

### Impact Explanation
This is a payload authenticated for one (attacker's, secret-less) organization mutating another organization's/repository's persisted `PullRequest` record, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The write includes `head` commit resolution (`find_or_create_commit_from_github_by_sha!`), which, combined with a target stack's `ignore_ci: true` (`Commit#deployable?` returns `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [7](#0-6) ), means any commit sha the attacker references becomes deployable without any CI gate once persisted as a commit against the victim stack. The attack is repeatable against any repository whose owner/full_name is known, as long as any single org in the Shipit deployment lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: at least one org configured in `Shipit.github_apps`/config without a `webhook_secret`, and knowledge of the victim's `repository.full_name` and an open PR `number` (both are public GitHub information). No Shipit credentials, GitHub App keys, or `webhook_secret` for the victim are needed. Attacker cost is a single crafted unauthenticated HTTP POST; fully repeatable and scriptable.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, derive the `GitHubApp` used for verification from the same field that handlers use to resolve the target repository (`repository.full_name`'s owner segment) rather than the independently-controlled `repository.owner.login`, and additionally assert that `repository.owner.login` (when present) matches the owner segment of `repository.full_name` before dispatch. Consider also refusing to treat a blank `webhook_secret` as automatically valid for events carrying a `repository` payload, and require all production/org configs to set a `webhook_secret`.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (no live GitHub):
1. Configure `Shipit.github_apps` (or stub `Shipit.github`) with two orgs: `"no-secret-org"` (no `webhook_secret`) and the victim org matching an existing fixture stack's repository (e.g. `shipit_stacks(:shipit)` repository `owner/name`).
2. Create/find a `Shipit::PullRequest` fixture belonging to the victim stack (with `ignore_ci: true`), with a known `number`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` (or an arbitrary bogus one), and JSON body: `action: "assigned"`, `repository.owner.login: "no-secret-org"`, `repository.full_name: "<victim-owner>/<victim-repo>"`, `number: <victim PR number>`, forged `pull_request` object (title/labels/assignees/head sha of attacker's choosing).
4. Assert response is `200 OK` (not `422`).
5. Reload the victim `PullRequest` and assert its `title`, `labels`, `assignees`, and `head_id` now equal the attacker-supplied values — i.e., assert `pull_request.reload.title == forged_title` even though the request was authenticated (if at all) only against `"no-secret-org"`'s (absent) secret, not the victim's. This demonstrates `authenticated_org != mutated_repository_owner` while the write still succeeded.

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

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
