### Title
Webhook signature verification is bound to `repository.owner.login`, but `PullRequest::EditedHandler` mutates records selected by the unrelated `repository.full_name` field, allowing cross-tenant PR metadata forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` to authenticate a payload using `params.dig('repository','owner','login')`, while `PullRequest::EditedHandler#repository` looks up the target repository using the independent `params.repository.full_name` field. These two JSON fields live in the same attacker-controlled body and are never cross-validated against each other, so an attacker who can satisfy verification for any one onboarded org can point `full_name` at a completely different (victim) repository and have `EditedHandler` mutate that victim's `PullRequest` row.

### Finding Description
The claimed binding, expressed as an equality that the code should (but does not) enforce, is:

`org(repository.owner.login)` used in `WebhooksController#verify_signature` **==** `owner(repository.full_name)` used to resolve the `Repository`/`PullRequest` mutated in `EditedHandler#process`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` strictly from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` HMAC-validates the raw body against that org's configured `webhook_secret`, but explicitly `return true unless webhook_secret` when no secret is configured for that org. [3](#0-2) 
- `PullRequest::EditedHandler#repository` resolves the target repository from a *different* JSON path, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name`. [4](#0-3) 
- `EditedHandler#pull_request` then finds the `PullRequest` joined through `stack: :repository` filtered on that resolved repository's `id`, and `process` calls `pull_request.update(github_pull_request: params.pull_request)` on it. [5](#0-4) 
- `PullRequest#github_pull_request=` writes `title`, `state`, `additions`, `deletions`, `assignees`, `labels`, and resolves `head` from the attacker-supplied SHA (fetching/creating the commit against the victim stack's own real GitHub repo if not already known). [6](#0-5) 

Because `repository.owner.login` (used for signature verification) and `repository.full_name` (used for the record lookup) are two independently attacker-supplied fields in the same unsigned JSON body sent directly to `POST /webhooks`, an attacker can set them to different values: e.g. `repository.owner.login = "attacker-org"` (an org onboarded to this Shipit instance with a blank/unset `webhook_secret`, a state explicitly produced by the shipped templates/docs) while setting `repository.full_name = "victim-org/victim-repo"`. Verification succeeds unconditionally for `"attacker-org"` due to the `return true unless webhook_secret` branch, yet the handler mutates the `PullRequest` belonging to `victim-org/victim-repo`. No existing guard closes this gap: `drop_unhandled_event` only filters by event type, the `ExplicitParameters` schema only validates field *types/presence*, not cross-field consistency, and there is no code anywhere that asserts `repository.full_name`'s owner segment matches `repository.owner.login`.

### Impact Explanation
A successful request lets an attacker overwrite a victim `PullRequest` row's `title`, `state`, `additions`/`deletions`, `assignees`, `labels`, and `head` commit pointer for any repository/PR-number pair they can name, as long as they can satisfy signature verification for *any* org onboarded to the same Shipit instance (most simply, one with no `webhook_secret` configured — a supported and templated configuration). This is repeatable against arbitrary repositories and PR numbers tracked by the instance, is not limited to a single tenant, and can corrupt which commit a review-stack/deploy pipeline treats as canonical for that PR. This matches the "payload for one repository mutating another's stack/commit" Critical impact category, though the write is confined to `PullRequest` metadata (not a full stack/branch takeover) unless combined with review-stack workflows that key off PR title/labels/head.

### Likelihood Explanation
Exploitation requires: (1) the target Shipit instance already tracks a `PullRequest` for the victim repo/PR number (an existing `ReviewStack`/`Stack` + `PullRequest`), and (2) at least one org configured in `Shipit.github` for which the attacker can produce a request that passes `verify_webhook_signature` — trivially satisfied if any onboarded org has no `webhook_secret` set, which the shipped `config/secrets.development.shopify.yml` and `template.rb` examples leave blank by default. No Shipit session, API token, or GitHub credentials are required; the attacker directly `POST`s to `/webhooks` with a crafted body and matching (or absent) signature. This is highly feasible in any multi-org deployment where at least one org's webhook secret is unset, and is fully repeatable per request.

### Recommendation
Cross-validate that the org used for signature verification matches the owner embedded in `repository.full_name` (and in any other repository-scoping field consumed later in the same handler) before dispatching to handlers; reject the request if they diverge. Additionally, treat a missing `webhook_secret` as a hard misconfiguration error rather than an implicit "skip verification" path in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "pull_request edited event cannot mutate a PR belonging to another org" do
  victim_pr = shipit_pull_requests(:review_stack_pr) # existing PR tied to a real Repository/Stack
  original_title = victim_pr.title

  # Simulate an org "no-secret-org" configured with a blank webhook_secret
  Shipit.stubs(:github).with(organization: 'no-secret-org').returns(
    Shipit::GitHubApp.new('no-secret-org', {})
  )

  request.headers['X-Github-Event'] = 'pull_request'
  body = {
    action: 'edited',
    number: victim_pr.number,
    pull_request: {
      id: victim_pr.github_id, number: victim_pr.number, url: victim_pr.api_url,
      title: 'FORGED TITLE', state: 'open', additions: 1, deletions: 1,
      head: { sha: victim_pr.head.sha, ref: 'forged-branch' },
      user: { login: 'attacker' }, assignees: [], labels: []
    },
    repository: {
      full_name: victim_pr.stack.repository.full_name, # victim repo, drives DB lookup
      owner: { login: 'no-secret-org' }                  # drives signature verification only
    },
    sender: { login: 'attacker' }
  }.to_json

  post :create, body:, as: :json

  victim_pr.reload
  assert_equal original_title, victim_pr.title, "victim PR must not be mutated by a payload verified under a different org"
end
```
Before the fix, `victim_pr.title` changes to `"FORGED TITLE"` despite the request never being signed with the victim org's `webhook_secret`, proving the equality `org(repository.owner.login) == owner(repository.full_name)` does not hold and is never enforced.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-61)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
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
