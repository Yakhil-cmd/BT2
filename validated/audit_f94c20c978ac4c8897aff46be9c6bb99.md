### Title
Assignee mutation trusts unverified `repository.full_name` while signature verification keys on `repository.owner.login`, allowing cross-org repo confusion - ([File: app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret/org used to validate the webhook via `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) , while `PullRequest::AssignedHandler#process` resolves and mutates the target repository/PullRequest via the independent `params.repository.full_name` field [3](#0-2) . If `GitHubApp#verify_webhook_signature` short-circuits to `true` for an org with no configured `webhook_secret` [4](#0-3) , an attacker who controls only that no-secret org's payload fields can set `repository.owner.login` to that org (to pass verification) while setting `repository.full_name` to an arbitrary victim repository, causing the victim's `PullRequest`/`ReviewStack` assignee state to be mutated by an unauthenticated request.

### Finding Description
The claimed binding is: `verifying_org` (`params.dig('repository','owner','login')`, used to pick the `GitHubApp` instance in `verify_signature`) **must equal** `mutated_repo_owner` (the owner encoded in `params.repository.full_name`, used by `AssignedHandler#repository`/`#pull_request` to locate and update the `Shipit::PullRequest`).

These two values are read from two *independent* JSON fields of the same unsigned/attacker-supplied body — `repository.owner.login` and `repository.full_name` — and nothing in `WebhooksController`, `Handler`, or `AssignedHandler` cross-checks that the owner in `full_name` matches `repository.owner.login`. Concretely:
- `verify_signature` calls `Shipit.github(organization: repository_owner)` and, if that org has no `webhook_secret` configured, `verify_webhook_signature` returns `true` for *any* signature/body pair [4](#0-3) .
- `AssignedHandler#repository` and `#pull_request` then use `params.repository.full_name` (a completely separate field) to look up the real `Shipit::Repository`/`Stack`/`PullRequest` and call `pull_request.update(github_pull_request: params.pull_request)` [5](#0-4) .
- `PullRequest#github_pull_request=` sets `self.assignees = github_pull_request.assignees.map { User.find_or_create_by_login!(...) }` directly from the attacker-supplied `assignees` array, with no membership/permission check [6](#0-5) .

Exploit flow: attacker crafts a JSON body with `repository.owner.login = "no-secret-org"` (an org configured in Shipit but without a `webhook_secret`) and `repository.full_name = "victim-org/victim-repo"`, `number` matching a real PR on a `ReviewStack` for `victim-org/victim-repo`, and `pull_request.assignees` containing arbitrary logins. POSTing this to `/webhooks` with header `X-Github-Event: pull_request` and any junk `X-Hub-Signature` passes `verify_signature` (because `no-secret-org` has no secret), then `AssignedHandler.process` updates the victim PR's assignees using `victim-org/victim-repo`.

Existing guards do not stop this: `drop_unhandled_event` only checks the event type exists, `verify_signature` only checks the org named in `repository.owner.login` (not `full_name`), and `ExplicitParameters` schema validates types/presence but not cross-field consistency [7](#0-6) .

### Impact Explanation
An attacker who controls (or can name) any org lacking a configured `webhook_secret` can write arbitrary GitHub logins into `assignees` of any victim `ReviewStack`'s `PullRequest`, for any repository whose owner/name they can guess, without ever authenticating as that repository. This is a cross-tenant write: a payload nominally scoped to one (unprotected) org mutates state belonging to a different, victim repository — matching the "payload for one repository mutating another's stack" category. Searching the codebase, `PullRequest#assignees` is currently only consumed by `PullRequestSerializer` for display [8](#0-7) ; no code path in this engine (`User#authorized?`, `require_permission!`, deploy/merge gating) was found that treats PR assignees as an authorization signal. The concrete, demonstrable impact is therefore data corruption/identity-association forgery on a victim's review stack, not a confirmed privilege escalation into `Shipit.github_teams` or a deploy/merge bypass — I could not find code making assignees security-relevant beyond display, so the "later flows" impact claimed in the question is speculative and unconfirmed by this repo's code.

### Likelihood Explanation
Requires: (1) a Shipit deployment configuring at least one GitHub org/app without a `webhook_secret` (a real-world misconfiguration, not guaranteed) — this is a precondition of the underlying "no-secret gap," not something AssignedHandler itself introduces; (2) the attacker knowing/guessing that org's name and a valid victim `repository.full_name` + PR `number` with an existing `ReviewStack`. Given that precondition, the attack is trivial to repeat against any number of victim repositories/PRs via unauthenticated POSTs to `/webhooks`.

### Recommendation
In `AssignedHandler` (and all other `pull_request`/handler classes sharing this pattern), verify that the owner encoded in `params.repository.full_name` matches the `repository.owner.login` that was used to select the verifying `GitHubApp`, or better, fix the root cause in `Shipit::GitHubApp#verify_webhook_signature`/`WebhooksController#verify_signature` so that: (a) a missing `webhook_secret` never causes verification to auto-pass, and (b) the org used for signature verification is derived from the same trusted source as the org whose data is later mutated. Do not allow `repository.owner.login` and `repository.full_name`'s owner segment to diverge.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/assigned_handler_test.rb (proof sketch)
test "cross-org payload mutates victim repository's PullRequest assignees" do
  # Simulate: attacker's org has no webhook_secret, but payload's repository.full_name
  # points at victim's repository/stack.
  victim_pr = shipit_pull_requests(:review_stack_review)
  payload = payload_parsed(:pull_request_assigned)
  payload["repository"]["owner"]["login"] = "attacker-org-without-secret"
  payload["repository"]["full_name"] = victim_pr.stack.repository.github_repo_name
  payload["number"] = victim_pr.number
  payload["pull_request"]["number"] = victim_pr.number
  payload["pull_request"]["assignees"] = [{ "login" => "attacker-login" }]

  # Before: victim's assignees are whatever they were pre-attack
  before = victim_pr.assignees.map(&:login)

  AssignedHandler.new(payload).process

  after = victim_pr.reload.assignees.map(&:login)
  assert_not_equal before, after
  assert_includes after, "attacker-login"
end
```
Note: this test demonstrates the handler-level binding failure in isolation (it does not exercise `verify_signature`/`GitHubApp` directly, since that requires config fixtures for an org without `webhook_secret`); a full end-to-end proof would additionally need a controller-level test hitting `POST /webhooks` with such an org configured, confirming `verify_signature` passes for the forged `X-Hub-Signature` before the handler is invoked.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-69)
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

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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

**File:** app/models/shipit/pull_request.rb (L36-47)
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
```

**File:** app/serializers/shipit/pull_request_serializer.rb (L8-10)
```ruby
    has_one :user
    has_one :head, serializer: ShortCommitSerializer
    has_many :assignees, serializer: UserSerializer
```
