### Title
Cross-tenant ReviewStack archival via divergent `repository.owner.login` vs `repository.full_name` in `pull_request` webhook - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb`, `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to validate the HMAC signature using `params.dig('repository','owner','login')`, but `ClosedHandler` (and other `pull_request` handlers) resolve the target `Repository`/`ReviewStack` using `params.repository.full_name`, an independently attacker-controlled field in the same JSON body. In a multi-tenant Shipit deployment (`Shipit.github_apps` configured with multiple orgs), an attacker who legitimately owns one org's `webhook_secret` can sign a payload where `repository.owner.login` is their own org (passing verification) while `repository.full_name` names a victim org's stack, causing that victim stack to be archived/deprovisioned.

### Finding Description
The binding that must hold is: `repository_owner used for verify_webhook_signature (params.dig('repository','owner','login'))` == `owner segment parsed from params.repository.full_name used by Repository.from_github_repo_name`. No code enforces this equality.

- `WebhooksController#verify_signature` computes `repository_owner` strictly from `params.dig('repository', 'owner', 'login')` (or `organization.login` fallback), and uses it to pick the per-org `GitHubApp`/`webhook_secret` via `Shipit.github(organization: repository_owner)`, then HMAC-verifies the raw body against that secret. [1](#0-0) [2](#0-1) 

- `ClosedHandler#repository` (and `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `AssignedHandler`, `EditedHandler`) resolve the repository purely from `params.repository.full_name`, via `Repository.from_github_repo_name`, which just splits on `/` and does a DB lookup — it has no relationship to `repository.owner.login`. [3](#0-2) [4](#0-3) 

- `ClosedHandler#process` then constructs a `ReviewStackAdapter` scoped to that (attacker-chosen) repository's `review_stacks` and calls `archive!`, which looks up the stack by `environment` (`"pr#{number}"`) and calls `stack.archive!(user, ...)` where `user` is derived from `params.sender.login` (also attacker-controlled, any string). [5](#0-4) [6](#0-5) 

- The `params do ... end` schema (`ExplicitParameters`) on `ClosedHandler` only requires presence/type of `repository.full_name`; it never cross-checks it against `repository.owner.login` (which isn't even declared as a required field on this handler, since verification happens in the controller, upstream of the handler). [7](#0-6) 

**Exploit flow:** Attacker controls org `attacker-org`'s real `webhook_secret` (a legitimately registered GitHub App/org in `Shipit.github_apps`, per the attacker model). They construct a JSON body:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": {...},
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker-org" }
}
```
They compute `X-Hub-Signature` using `attacker-org`'s real `webhook_secret` over this exact raw body, and POST to `/webhooks` with `X-Github-Event: pull_request`. `verify_signature` reads `repository.owner.login == "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC matches — verification succeeds. Downstream, `ClosedHandler` uses `repository.full_name == "victim-org/victim-repo"` to find the victim's `Repository`/`ReviewStack` scoped to that PR number's environment and archives/deprovisions it.

Existing guards do not prevent this: `verify_signature` never compares its chosen `repository_owner` against the owner segment of `full_name`; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema only validates types/presence, not cross-field consistency; and `Repository.from_github_repo_name`/model validations only constrain character format, not tenant ownership.

### Impact Explanation
An attacker with no relationship to the victim org can cause the victim's `ReviewStack` to be `archive!`-ed and `deprovision`-ed — a real state-mutating action (`stack.remove_from_provisioning_queue`, `stack.deprovision`, `stack.archive!(user)`) triggered by a payload for a repository the attacker never authenticated against. This matches the "payload for one repository mutating another's stack" Critical category: it is a cross-tenant authentication-boundary bypass because the webhook signature check is bound to the wrong field. The attack is repeatable against any victim stack whose `pr{number}` environment name and repo full_name the attacker can guess/enumerate (PR numbers are small sequential integers), across all tenants sharing the same Shipit instance. Other `pull_request` handlers sharing the same `repository.full_name`-based lookup (`LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `AssignedHandler`, `EditedHandler`) are similarly reachable, allowing unarchive, provisioning, or PR-metadata mutation on victim stacks too.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured multi-tenant (`Shipit.github_apps` with 2+ orgs) — a documented, supported deployment mode; (2) attacker legitimately controls at least one org/app registration's `webhook_secret`, which per the stated attacker model they are entitled to have for their own org; (3) knowledge of the victim's `owner/repo` full name (public info) and a plausible PR number (small integer, easily brute-forced/enumerated). No GitHub session, Shipit session, or victim secrets are needed. This is a single crafted HTTP POST, fully deterministic and repeatable — cost and complexity are low.

### Recommendation
In `WebhooksController#verify_signature` (or upstream in each handler before acting), enforce that the owner segment parsed from `params.dig('repository','full_name')` equals `params.dig('repository','owner','login')` (case-insensitively), rejecting the request with `422` otherwise. Additionally, harden handlers to independently verify the resolved `Repository#owner` matches the app organization actually used to authenticate the request (pass `repository_owner` down into the handler context and assert equality with `repository.owner` before performing any mutation), rather than trusting `full_name` alone.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, or a new integration test):
1. Set up two orgs in `Shipit.github_apps`/test secrets: `org-a` (attacker, with real `webhook_secret_a`) and `org-b` (victim), each with a `Repository`("org-a/repo-a", "org-b/repo-b") and `org-b` having an existing `ReviewStack` for PR number `1` (environment `"pr1"`), not archived.
2. Build body:
```ruby
body = {
  action: "closed", number: 1,
  pull_request: { id: 1, number: 1, url: "...", title: "t", state: "closed",
    additions: 1, deletions: 1, head: { sha: "abc", ref: "branch" },
    user: { login: "org-a" }, assignees: [], labels: [] },
  repository: { owner: { login: "org-a" }, full_name: "org-b/repo-b" },
  sender: { login: "org-a" }
}.to_json
signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", "webhook_secret_a", body)
```
3. `post :create, body:, as: :json`, with `X-Github-Event: pull_request` and `X-Hub-Signature: signature`.
4. Assert both sides of the binding to show divergence: `repository_owner` used for verification (`"org-a"`) vs. owner segment of `full_name` used by handler (`"org-b"`) — they differ.
5. Assert response is `:ok` (verification passed using `org-a`'s real secret) AND `Shipit::ReviewStack.find_by(environment: "pr1", repository: org_b_repo).reload.archived?` is `true` — proving org-a's signature archived org-b's stack despite no relationship between them.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L8-39)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-53)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
```
