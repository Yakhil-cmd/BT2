### Title
Cross-org webhook signature scope (`repository.owner.login`) is not bound to the repository resolution field (`repository.full_name`) used by `LabelCapturingHandler#capture_labels` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a request against using `params.dig('repository', 'owner', 'login')`, while every `pull_request` handler (including `LabelCapturingHandler`) resolves the target `Repository`/`Stack` using the independent `params.repository.full_name` field via `Repository.from_github_repo_name`. Nothing in the request pipeline enforces that these two fields refer to the same organization, so a request whose raw JSON body is crafted with a mismatched `owner.login` vs `full_name` can pass signature verification scoped to one org while mutating a `Stack`/`PullRequest` belonging to a completely different org.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`org_used_for_signature_verification (params.repository.owner.login)` == `org_used_for_repository_resolution (params.repository.full_name.split('/').first)`

Trace:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and does `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`. [1](#0-0) 
- This selects the `GitHubApp` instance (and its `webhook_secret`) purely by `repository.owner.login`. [2](#0-1) 
- `GitHubApp#verify_webhook_signature` HMACs the *entire raw body* with that org's secret - it never inspects or validates `repository.full_name` itself. [3](#0-2) 
- Once signature passes, `LabelCapturingHandler#repository` resolves the acting `Repository` using a *different* field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name`, which simply splits the string on `/` and does a DB lookup by `owner`/`name` columns - with no reference back to `repository.owner.login` or to whichever org's secret validated the request. [4](#0-3) [5](#0-4) 
- `stack` is then found within that resolved repository's `review_stacks` scope by `environment` (`"pr#{params.number}"`) via `ReviewStackAdapter`. [6](#0-5) [7](#0-6) 
- `capture_labels` then persists attacker-controlled strings verbatim: `pull_request.update!(labels: params.pull_request.labels.map(&:name))`, with no sanitization of label content. [8](#0-7) 

Root cause: `repository.owner.login` (used for authentication/signature-org selection) and `repository.full_name` (used for authorization/target-resolution) are two independent keys inside the same attacker-suppliable `repository` JSON object. GitHub itself always keeps these consistent when it generates real webhook deliveries, but nothing in this engine enforces that consistency on the server side. Because the rules of engagement permit an attacker to POST directly to `/webhooks` with an arbitrary raw body (not necessarily proxied through GitHub), the attacker can pick `repository.owner.login` = an org whose webhook signature they can produce (e.g. an org they administer, or - notably - any org configured in `secrets.yml` with a blank/`nil` `webhook_secret`, for which `verify_webhook_signature` unconditionally `return true unless webhook_secret`) while setting `repository.full_name` = the victim's tracked repository name.

Exploit flow:
1. Attacker identifies (or controls) an org "A" onboarded to the same Shipit instance whose `webhook_secret` is blank/known to them (per `verify_webhook_signature`'s `return true unless webhook_secret` bypass, or because they legitimately administer org A's GitHub App and know its secret).
2. Attacker crafts a `pull_request` "labeled" JSON body: `repository.owner.login = "orgA"`, `repository.full_name = "orgB/victim-repo"`, `number` = victim PR's `environment` number, `pull_request.labels = [thousands of near-duplicate strings]`.
3. Attacker computes/omits `X-Hub-Signature` consistent with org A's (possibly absent) secret and POSTs to `/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "orgA")` and passes.
5. `LabelCapturingHandler` resolves `Repository.from_github_repo_name("orgB/victim-repo")` → org B's actual `Repository`/`Stack`/`PullRequest`, and calls `pull_request.update!(labels: [...])`, persisting the attacker's payload into org B's row.

Why existing guards don't stop this: `drop_unhandled_event` only checks the event name exists; the `ExplicitParameters` schema only enforces types/presence of `repository.full_name`, `sender.login`, etc., never cross-field consistency; `verify_signature` never re-derives `repository_owner` from `full_name` nor checks that the two match; `capture_labels` performs no sanitization or repository/org check before `update!`.

### Impact Explanation
A crafted webhook can overwrite the `labels` column of an arbitrary victim `PullRequest`/`ReviewStack` belonging to a different, unrelated organization from the one whose signature validated the request - a cross-repository/cross-tenant data write matching the "payload for one repository mutating another's stack" Critical category. The blast radius spans every org hosted on a shared multi-org Shipit instance (see `docs/setup.md`'s "Using Multiple Github Applications" and the double-org fixtures), and is repeatable per request against any tracked review-stack PR number, with the attacker fully controlling label array size/content (thousands of near-duplicate strings, unsanitized).

### Likelihood Explanation
Preconditions: (1) a multi-org Shipit deployment (or a single org with a blank `webhook_secret`), (2) attacker able to reach `POST /webhooks` directly with an arbitrary raw body (explicitly permitted per this audit's threat model), (3) attacker knows/controls a signing path for at least one onboarded org (their own, or one with no secret configured). Given those, exploitation cost is a single crafted HTTP POST; no GitHub session, Shipit session, or Shipit secret is required beyond what the attacker already legitimately has for org A. Feasibility is high in any deployment supporting multiple GitHub orgs or any org left with a blank `webhook_secret` (a documented, supported configuration in `config/secrets.development.shopify.yml`/`test/dummy/config/secrets_double_github_app.yml`).

### Recommendation
Bind webhook signature-org derivation to the same field used for repository resolution, or validate consistency explicitly: after `verify_signature` succeeds, re-check that `repository_owner` (used to pick the `GitHubApp`) equals the owner segment parsed from `params.repository.full_name` before any handler runs (e.g., in `WebhooksController#create` or centrally in `Handler#initialize`), rejecting the request (422) on mismatch. Additionally, do not allow `verify_webhook_signature` to silently succeed when `webhook_secret` is blank in production-like environments; require an explicit "unsigned webhooks allowed" opt-in per org.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "cross-org repository.full_name is not bound to repository.owner.login used for signature verification" do
  org_a_repo = shipit_repositories(:org_a_repo) # e.g. owner: "orga", webhook_secret blank/known
  victim_stack = shipit_stacks(:review_stack)   # owned by a different org, e.g. "shopify/shipit-engine"
  victim_pr = victim_stack.pull_request

  payload = JSON.parse(payload(:pull_request_labeled))
  payload["action"] = "labeled"
  payload["number"] = victim_stack.environment.delete_prefix("pr").to_i
  payload["repository"]["owner"]["login"] = "orga"          # picks org A's (blank) secret
  payload["repository"]["full_name"] = victim_stack.github_repo_name # targets victim org's repo
  attacker_labels = Array.new(3000) { |i| { "name" => "label-#{i}" } }
  payload["pull_request"]["labels"] = attacker_labels

  request.headers['X-Github-Event'] = 'pull_request'
  # no valid X-Hub-Signature for the victim org; org A has blank webhook_secret so verification passes

  post :create, body: payload.to_json, as: :json

  assert_response :ok
  assert_equal attacker_labels.map { |l| l["name"] }, victim_pr.reload.labels
end
```
Equality asserted both sides: before, `repository_owner ("orga") != full_name_owner ("shopify")` yet request is accepted; after, `victim_pr.labels == attacker_supplied_array`, proving the write for org B succeeded despite verification being scoped to org A.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L104-118)
```ruby
          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
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
