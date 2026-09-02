### Title
Cross-repository webhook forgery allows unauthenticated write of arbitrary PR metadata via `EditedHandler#process` - (File: app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb)

### Summary
`EditedHandler#process` resolves the target `Shipit::PullRequest` purely from the payload's `repository.full_name` and `number`, and unconditionally writes `params.pull_request` (title, state, labels, assignees, etc.) into it with no authorization check. Because webhook signature verification is keyed off a *different* payload field (`repository.owner.login`/`organization.login`) than the field used to select the record to mutate (`repository.full_name`), an attacker who owns their own GitHub org/app registered in Shipit can sign a payload with their own webhook secret while pointing `repository.full_name` at a victim repository, causing the update to succeed against the victim's `PullRequest` row.

### Finding Description
The broken binding, stated as an equality that must hold but does not:
`signing_org (used in WebhooksController#verify_signature via repository_owner = params.dig('repository','owner','login')) == target_repository_owner (used in EditedHandler#repository via Repository.from_github_repo_name(params.repository.full_name))`.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-30` computes `github_app = Shipit.github(organization: repository_owner)` from `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`), and verifies the HMAC signature against that org's `webhook_secret`. Nothing else in the request is validated against this org. [1](#0-0) [2](#0-1) 
- `EditedHandler#repository` independently derives the target repository from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name`, a plain string lookup against existing rows, with no tie back to whichever org's secret validated the signature. [3](#0-2) 
- `EditedHandler#process` then finds the `PullRequest` by `number` + resolved `repository.id` and calls `pull_request.update(github_pull_request: params.pull_request)` with no `authorized?`/`require_permission!`/team check anywhere in the handler. [4](#0-3) 
- `PullRequest#github_pull_request=` stores `title`, `state`, `labels`, `assignees`, etc. verbatim from the attacker-controlled hash with no sanitization or validation. [5](#0-4) 

Exploit flow: attacker registers/controls a GitHub org (`attacker-org`) configured in Shipit with a known `webhook_secret` (their own, legitimately configured integration). They send `POST /webhooks` with `X-Github-Event: pull_request`, a body where `repository.owner.login = "attacker-org"` / `organization.login = "attacker-org"` (so `verify_signature` picks their own app config and their self-computed HMAC validates), but `repository.full_name = "victim-org/victim-repo"` and `pull_request.number` matching an existing open PR on the victim stack, with `pull_request.title`, `.state`, `.labels[].name`, `.assignees[].login` set to arbitrary strings. `drop_unhandled_event`/`check_if_ping` do not block this. The `ExplicitParameters` schema only enforces types/presence, not cross-field consistency between `repository.owner.login` and `repository.full_name`, nor ties either to the verified signing org. No `authorized?`, `require_permission!`, or `Shipit.github_teams` check gates the update in `EditedHandler#process` or `PullRequest#github_pull_request=`.

### Impact Explanation
Any attacker who controls a GitHub org/app entry configured in Shipit (their own, unprivileged w.r.t. the victim) can write arbitrary attacker-chosen `title`, `state`, `labels`, and `assignees` into a victim repository's `Shipit::PullRequest` row for any known/guessable PR number, without belonging to `Shipit.github_teams` or having any Shipit session/token. This is a payload from one repository/org mutating another's record — matching the explicitly listed Critical category "a payload for one repository mutating another's stack, commit, task or team." Since Shipit UI/API surfaces `PullRequest#title`/`state`/`labels`/`assignees`, this can be used to spoof PR state (e.g., mark it merged/closed) or inject content into rendered views, and is repeatable against any repository whose `full_name` and PR numbers the attacker can guess (both are typically public/predictable GitHub identifiers).

### Likelihood Explanation
Requires the attacker to have a working "cross-org bypass" precondition (their own org/app entry registered in Shipit, giving them a valid webhook secret for signing), which is the scenario referenced/assumed by this question as already established. Given that precondition holds, the additional cost is trivial: craft a JSON body with mismatched `repository.owner.login` vs `repository.full_name`, no GitHub secrets, sessions, or API tokens of the victim are needed. Fully repeatable and scriptable per request.

### Recommendation
In `WebhooksController#verify_signature`/`create`, or in each handler's `repository` resolution, ensure the org used to select the webhook secret matches the org embedded in `repository.full_name` (i.e., `repository.full_name.split('/').first == repository_owner`) before dispatching to handlers. Additionally, `EditedHandler#process` (and sibling handlers) should confirm the resolved `Repository` actually belongs to the same organization that produced a valid signature, and reject/no-op otherwise.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure two orgs in `Shipit.github_configs`: `"attacker-org"` with `webhook_secret: "attacker-secret"`, and `"victim-org"` with a different/no known secret.
2. Create a `Shipit::Repository` `victim-org/victim-repo`, a `Stack`, and a `PullRequest` with `number: 42`, `title: "original"`.
3. Build a payload: `action: "edited"`, `repository: { full_name: "victim-org/victim-repo", owner: { login: "attacker-org" } }`, `pull_request: { number: 42, title: "PWNED", state: "closed", labels: [{name: "evil"}], assignees: [{login: "attacker"}], ... }`.
4. Sign it with `attacker-secret` (HMAC-SHA1) and POST to `/webhooks` with `X-Github-Event: pull_request`.
5. Assert response is `200`/`204` (not `422`), then reload the `PullRequest` and assert `title == "PWNED"`, `state == "closed"`, `labels == ["evil"]`, `assignees.map(&:login) == ["attacker"]` — proving the write succeeded on the victim's row using the attacker's own org's signature, with no `authorized?`/`require_permission!` check ever invoked (grep confirms absence in `EditedHandler` and `PullRequest#github_pull_request=`).

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
