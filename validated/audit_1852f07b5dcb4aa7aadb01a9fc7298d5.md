### Title
Signature verification keys off `repository.owner.login` while record resolution keys off `repository.full_name`, letting a "no-secret org" payload write into a victim's `PullRequest`/`ReviewStack` — (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `params.dig('repository','owner','login')`, while `LabelCapturingHandler` resolves the actual `Shipit::Repository`/`ReviewStack` to mutate using the independent `params.repository.full_name` field. Because these two fields are never cross-checked, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's `webhook_secret` is blank, an attacker who owns/controls a Shipit-configured "no-secret" organization can forge a `pull_request`/`unlabeled` webhook whose `repository.owner.login` names that no-secret org (bypassing all signature checks) but whose `repository.full_name` names a victim's real repo, causing `LabelCapturingHandler` to update the victim's `PullRequest#labels`.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces:

`organization_used_for_signature_verification (params.dig('repository','owner','login'))` **==** `organization_owning_the_record_that_gets_mutated (params.repository.full_name.split('/').first)`

Trace:
1. `Shipit::WebhooksController#verify_signature` picks the GitHub App config purely from `repository_owner`: [1](#0-0) , with `repository_owner` defined as [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` short-circuits to `true` when the selected org's `webhook_secret` is blank — no HMAC is computed at all: [3](#0-2) .
3. Once `head(422)` is skipped, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs the handler on the raw, forged JSON body: [4](#0-3) .
4. `LabelCapturingHandler#repository` resolves the actual DB `Repository` from `params.repository.full_name` — a field that is completely independent of the `repository.owner.login` used in step 1 — via `Repository.from_github_repo_name`: [5](#0-4) , and `Repository.from_github_repo_name` simply splits the attacker-supplied string on `/`: [6](#0-5) .
5. The `params` schema only `requires :repository do requires :full_name, String end`; it never requires or validates `repository.owner.login` against `full_name`: [7](#0-6) .
6. For `action == "unlabeled"` on an existing, non-archived stack, `capture_labels` fetches the victim's real `stack.pull_request` (via `ReviewStackAdapter#stack`, which does `scope.find_by(environment: "pr#{params.number}")` on the victim repository's `review_stacks`) and overwrites its `labels`: [8](#0-7) [9](#0-8) [10](#0-9) .
7. Those persisted labels later become uppercased environment variables merged into the victim `ReviewStack#env`, which downstream is merged into task/command execution environment: [11](#0-10) .

Attacker's exact request: `POST /webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` needed, and a JSON body such as:
```json
{
  "action": "unlabeled",
  "number": <victim PR number>,
  "pull_request": { ..., "labels": [{"name":"MALICIOUS_ENV"}], "head": {"sha":"...", "ref":"..."} },
  "repository": { "owner": {"login": "attacker-no-secret-org"}, "full_name": "victim-org/victim-repo" },
  "sender": {"login": "attacker"}
}
```
`verify_signature` authenticates against `attacker-no-secret-org` (trivially, since its `webhook_secret` is blank) while the handler mutates `victim-org/victim-repo`'s `ReviewStack`/`PullRequest`.

Regarding the "shared commit SHA" element of the question: `LabelCapturingHandler`/`ReviewStackAdapter` resolve the target stack by `environment: "pr#{params.number}"` and repository `full_name`, not by commit SHA — the SHA fields in the schema (`pull_request.head.sha`) are stored on the `PullRequest`/`Commit` for other purposes but are not the resolution key for this handler. The actual root cause and exploitable divergence is the owner/full_name mismatch described above, not a SHA collision; the SHA-collision framing in the question does not apply to this specific handler's code path.

Existing guards do not close this gap: `verify_signature` only guards against organizations with a configured secret; there is no requirement that the signing org matches the org embedded in `repository.full_name`, and `ExplicitParameters` never cross-validates the two.

### Impact Explanation
An unauthenticated attacker who merely owns a GitHub org that happens to be configured in Shipit without a `webhook_secret` (a legitimate, low-privilege configuration state, not requiring attacker to compromise anything) can overwrite the `labels` column of any other tenant's `PullRequest` record tied to any active `ReviewStack`, for any repository/PR number they can guess or observe. Because `ReviewStack#env` converts those labels into uppercased env vars merged into the deploy/task execution environment, this is a **payload for one repository mutating another's stack/commit state**, matching the Critical impact category "a payload for one repository mutating another's stack, commit, task or team." The action is repeatable against arbitrary victim repos/PRs as long as the attacker knows `full_name` and PR `number`, with no rate limiting on this path in scope.

### Likelihood Explanation
Preconditions: (1) Shipit must have at least one organization configured with no `webhook_secret` (the "no-secret organization" gap is a real, documented misconfiguration path per the question's setup), and (2) the victim must have an existing, non-archived `ReviewStack` for a known PR number. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body — no GitHub webhook delivery, no valid HMAC, no session, and no API token is required. This is highly feasible and fully repeatable.

### Recommendation
Do not trust `repository.owner.login` independently from `repository.full_name`. Either (a) derive the signature-verification organization from the same `full_name` field used for record resolution, or (b) after selecting the `Repository`/`Stack` for mutation, assert that `repository.full_name.split('/').first` equals the organization whose secret verified the signature, rejecting the request (422) on mismatch. Additionally, treat a blank/missing `webhook_secret` as a configuration error that should fail closed (reject unsigned webhooks) rather than as an implicit "trust everything" bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Minitest plan (webhooks controller integration test), no live GitHub:
1. Seed `Rails.application.credentials.github` (or stub `Shipit.secrets.github`) with two orgs: `attacker-org` (no `webhook_secret` key) and `victim-org` (has a `webhook_secret`).
2. Create `victim_repo = Shipit::Repository.create!(owner: "victim-org", name: "victim-repo")`, a `Shipit::ReviewStack` with `environment: "pr42"`, and its `pull_request` with `labels: []`.
3. Build binding-check values before the request: `before_labels = victim_stack.pull_request.reload.labels` → assert `== []`.
4. POST `/webhooks` with header `X-Github-Event: pull_request`, no/garbage `X-Hub-Signature`, and JSON body:
   `{"action":"unlabeled","number":42,"pull_request":{...,"labels":[{"name":"PWNED"}],"head":{"sha":"deadbeef","ref":"whatever"}},"repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"},"sender":{"login":"attacker"}}`.
5. Assert response is `200 OK` (not `422`), proving `verify_signature` passed via the no-secret `attacker-org`.
6. Assert `victim_stack.pull_request.reload.labels == ["PWNED"]`, i.e. `after_labels != before_labels` and `after_labels` was written by a request authenticated under `attacker-org`, not `victim-org` — proving the equality `signing_org == full_name_org` is violated and the victim record was mutated by an unauthenticated payload for a different organization.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L66-68)
```ruby
          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```
