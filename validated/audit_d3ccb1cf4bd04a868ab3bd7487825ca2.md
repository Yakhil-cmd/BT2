### Title
Cross-tenant webhook signature confusion in `WebhooksController#verify_signature` allows one organization's webhook secret to authorize mutation of another organization's `ReviewStack` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC `webhook_secret`) using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')`. `Shipit::Webhooks::Handlers::PullRequest::LabeledHandler#repository`, however, resolves the target `Shipit::Repository`/`ReviewStack` using a completely separate field, `params.repository.full_name`. Nothing in the controller or the handler cross-checks that these two values refer to the same repository, so a request signed with `evil-org`'s own secret can carry a `repository.full_name` of `victim-org/victim-repo` and cause `stack.archive!`/`unarchive!` to run against `victim-org`'s real `ReviewStack`.

### Finding Description
The broken binding: the organization whose secret verifies the signature (`repository_owner = params.dig('repository','owner','login')`) is asserted to equal the organization that owns the repository being mutated (`Repository.owner` derived from `params.repository.full_name`). These are two independently attacker-controlled fields in the same JSON body.

Trace:
- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against `request.raw_post` using that organization's `webhook_secret` [1](#0-0)  where `repository_owner` is `params.dig('repository', 'owner', 'login')` [2](#0-1) .
- If verification succeeds, `create` re-parses the raw body and dispatches it, unmodified, to all registered handlers for the event [3](#0-2) .
- `LabeledHandler#repository` resolves the target repository from `params.repository.full_name` — a different JSON field than the one used for signature verification — via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) .
- `Repository.from_github_repo_name` simply splits the `"owner/name"` string and looks up the record by `owner`/`name`, with no relation at all to the `owner.login` used for signature verification [5](#0-4) .
- `LabeledHandler#handle` then calls `stack.archive!`/`stack.unarchive!` on the `ReviewStack` scoped from that resolved repository [6](#0-5) .

Attacker request: attacker owns `evil-org`, configured in `Shipit.github`, and knows/controls `evil-org`'s `webhook_secret` (since it's their own GitHub App/org config, or more simply they can trigger a real webhook from their own repo and then replay/craft the body). They POST to `/webhooks` with header `X-Github-Event: pull_request`, HMAC-signed with `evil-org`'s webhook secret, and a JSON body where `repository.owner.login == "evil-org"` (satisfies signature-org selection) but `repository.full_name == "victim-org/victim-repo"` (used by the handler) along with a `pull_request.number` matching an existing PR/`ReviewStack` in `victim-org/victim-repo`, and a `labels` array containing/excluding the provisioning label to trigger `archive?`/`unarchive?`.

This passes `verify_signature` because the HMAC is valid for `evil-org` and `repository_owner` resolves to `evil-org` — the check only proves "this body was signed by whoever owns `evil-org`," not "this body concerns a repository in `evil-org`." Existing guards do not catch the divergence: `verify_signature` never inspects `full_name`; `ExplicitParameters` schema in `LabeledHandler` only requires `repository.full_name` to be a String, with no format constraint tying it to `owner.login` [7](#0-6) ; `drop_unhandled_event` and `check_if_ping` are unrelated to this check.

### Impact Explanation
A malicious org/repo owner can, using only their own webhook secret, cause `Shipit::ReviewStack#archive!`/`#unarchive!` to execute against any other tenant's repository and PR number as long as `review_stacks_enabled` and a matching `ReviewStack` exists — a payload signed by one repository's credentials mutating another repository's stack. This is repeatable for any repository/organization pair configured in the same Shipit instance and any PR number, giving the attacker persistent ability to archive/unarchive arbitrary victim review stacks (disrupting or hijacking deploy/review provisioning), which matches the Critical category "a payload for one repository mutating another's stack."

### Likelihood Explanation
Preconditions are modest and attacker-achievable: the attacker only needs to own an organization/repo already configured in `Shipit.github` (i.e., is a legitimate onboarded but unprivileged tenant of the Shipit instance) and know its own `webhook_secret` — which is entirely plausible since it's their own GitHub App/organization integration, or they can capture a legitimately triggered webhook from their own repo and reuse the valid signature with a crafted body/replayed request against `/webhooks` (the signature only binds to raw bytes, and the attacker controls the raw bytes they send in the first place since it's their own secret). The victim just needs `review_stacks_enabled` and an active PR-based `ReviewStack`, which is a normal configuration. No Shipit session, API token, or victim secrets are required.

### Recommendation
In `WebhooksController#verify_signature`, and/or in the base `Handler`/`Repository.from_github_repo_name` resolution path, enforce that the `owner.login` used to select the webhook secret matches the owner segment of `repository.full_name` (case-insensitively) before dispatching to handlers, rejecting (422) on mismatch.

### Proof of Concept
Minitest plan (no live GitHub, stub `Shipit.github`):
1. Fixtures: create `Shipit::Repository` for `victim-org/victim-repo` with `review_stacks_enabled: true` and `provisioning_behavior: allow_with_label`; create a `Shipit::ReviewStack` for pull request number `N` under that repository, unarchived.
2. Configure `Shipit.github` for both `evil-org` (with `webhook_secret: "evil-secret"`) and `victim-org`.
3. Build the JSON body: `{"action":"labeled","number":N,"pull_request":{...,"number":N,"state":"open","labels":[{"name":"<provisioning_label_name>"}],...},"repository":{"full_name":"victim-org/victim-repo","owner":{"login":"evil-org"}},"sender":{"login":"attacker"}}`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest("sha1", "evil-secret", body)`.
5. POST to `/webhooks` with header `X-Github-Event: pull_request` and the above signature.
6. Assert response is `200`/`:ok` (signature accepted).
7. Reload the `victim-org/victim-repo` `ReviewStack` and assert `stack.archived?` (or `unarchived?`, per label config) changed as expected — proving `evil-org`'s secret mutated `victim-org`'s stack.
8. Equality check before/after: assert `repository_owner (== "evil-org")` used for signing != `Repository.from_github_repo_name(params.repository.full_name).owner (== "victim-org")`, both before the request (statically true) and after (state changed despite mismatch), demonstrating the missing binding enforcement.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-63)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
