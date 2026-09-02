## Finding: Confirmed vulnerability

### Title
Webhook signature verification authenticates on `repository.owner.login` while `UnlabeledHandler` mutates the stack identified by the attacker-controlled, independent `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `params.dig('repository','owner','login')`, but `UnlabeledHandler` resolves the target `Repository`/`Stack` using the independent field `params.repository.full_name`. Because these two fields are never cross-checked, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has no configured `webhook_secret`, an attacker can pick a "no-secret" org to pass authentication while pointing `repository.full_name` at an unrelated victim stack.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`authenticated_owner (params.repository.owner.login used in verify_signature) == mutated_repository_owner (params.repository.full_name.split('/').first used in UnlabeledHandler#repository)`

Trace:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and fetches `github_app = Shipit.github(organization: repository_owner)`. [1](#0-0) [2](#0-1) 
2. `GitHubApp#verify_webhook_signature` returns `true` immediately if that org's config has no `webhook_secret`, skipping HMAC validation entirely: `return true unless webhook_secret`. [3](#0-2) 
3. The controller then dispatches the raw, attacker-supplied JSON body to `UnlabeledHandler.call(params)` without ever re-checking that the body's owner matches anything meaningful for the actual mutation target. [4](#0-3) 
4. `UnlabeledHandler#repository` (and thus `#stack`) resolves the target purely from `params.repository.full_name`, a completely separate JSON field from the one used for authentication: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. [5](#0-4) 
5. `handle` then calls `stack.archive!` or `stack.unarchive!` on whatever review stack that lookup finds. [6](#0-5) 

Exploit flow: attacker finds (or registers) an org configured in Shipit with a blank `webhook_secret` — call it `no-secret-org`. They craft a `pull_request`/`action=unlabeled` webhook body with `repository.owner.login = "no-secret-org"` (used only for signature selection) but `repository.full_name = "victim-org/victim-repo"` (the real, unrelated target with review stacks enabled). They POST this to `/webhooks` with `X-Github-Event: pull_request` and an arbitrary/garbage `X-Hub-Signature` header. `verify_signature` selects `no-secret-org`'s `GitHubApp`, which has no secret, so `verify_webhook_signature` returns `true` regardless of the header value or body content. The forged body is then processed as legitimate, and `UnlabeledHandler` archives or unarchives `victim-org/victim-repo`'s review stack based on the attacker-forged labels/state, entirely independent of the org used to pass authentication.

The `ignore_ci: true` / `Commit#deployable?` detail amplifies impact once the stack is unarchived: `Commit#deployable? = !locked? && (stack.ignore_ci? || (success? && !blocked?))` means any commit becomes shippable without needing real CI success, so an unarchived review stack immediately becomes eligible for `trigger_continuous_delivery`/deploy if continuous deployment is also enabled. [7](#0-6) 

Existing guards do not prevent this: `verify_signature` never compares `repository.owner.login` against `repository.full_name`'s owner segment, `ExplicitParameters` only validates types/presence (not cross-field consistency), and there is no `require_permission!`/session check on this unauthenticated webhook endpoint by design (it's meant to be authenticated purely by the per-organization HMAC).

### Impact Explanation
An unprivileged internet attacker can archive or unarchive any review stack belonging to any repository configured in Shipit — a repository they do not own, control, or have any relationship to — as long as any single org configured in the same Shipit instance lacks a `webhook_secret`. This is a "payload for one repository mutating another's (a `no-secret-org`'s webhook) stack (`victim-org/victim-repo`)" cross-tenant write, matching the Critical impact category. Because unarchiving flips `stack.archived_since` to `nil` and re-enables provisioning/GithubSync, and because `ignore_ci: true` stacks treat any commit as `deployable?`, this can cascade into unauthorized deploys via `trigger_continuous_delivery` if `continuous_deployment` is also set on the victim stack. The attack is repeatable against any repository/stack in the instance, for as long as one no-secret org configuration exists, with no rate limiting relevant to Shipit's own authorization logic.

### Likelihood Explanation
Preconditions: (1) at least one GitHub organization is registered in Shipit's config without a `webhook_secret`; (2) the victim repository/stack has `review_stacks_enabled` and a `provisioning_behavior` (`allow_with_label`/`prevent_with_label`) that responds to label changes. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body; no GitHub account interaction with the victim repo is required at all since the entire payload, including `repository.full_name`, `pull_request.labels`, and `pull_request.state`, is attacker-controlled JSON, not verified against real GitHub state. This is fully reproducible with a minitest hitting `Shipit::WebhooksController#create` directly, no live GitHub needed.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, after selecting the `github_app` by `repository_owner`, additionally verify that `params.dig('repository','full_name')&.split('/')&.first&.downcase == repository_owner&.downcase` (and reject/`head(422)` on mismatch) before dispatching to handlers. Additionally, `GitHubApp#verify_webhook_signature` should not silently permit unsigned traffic when `webhook_secret` is blank for organizations that have webhook-driven mutation handlers registered — at minimum, require an explicit opt-in flag (e.g., `allow_unsigned_webhooks: true`) rather than defaulting to `true`.

### Proof of Concept
```ruby
test "unlabeled webhook forged with no-secret org owner mutates unrelated victim stack" do
  # Setup: 'no-secret-org' registered in Shipit.github_apps with webhook_secret blank
  # Setup: victim repository 'victim-org/victim-repo' with review_stacks_enabled: true,
  #        provisioning_behavior: :prevent_with_label, provisioning_label_name: 'wip'
  victim_repo = shipit_repositories(:shipit) # or a repo built with owner: 'victim-org', name: 'victim-repo'
  victim_stack = create_review_stack(repository: victim_repo, archived_since: nil)

  payload = payload_parsed(:pull_request_unlabeled)
  payload['repository']['owner']['login'] = 'no-secret-org'   # selects org w/ blank webhook_secret
  payload['repository']['full_name'] = victim_repo.github_repo_name # "victim-org/victim-repo"
  payload['pull_request']['labels'] = [{ 'name' => 'wip' }]   # triggers archive? per prevent_with_label
  payload['pull_request']['head']['ref'] = victim_stack.branch

  post shipit.webhooks_path,
    params: payload.to_json,
    headers: {
      'X-Github-Event' => 'pull_request',
      'X-Hub-Signature' => 'sha1=deadbeef', # garbage, unverifiable signature
      'Content-Type' => 'application/json'
    }

  assert_response :ok
  # Binding broken: authenticated_owner ('no-secret-org') != mutated_repository_owner ('victim-org')
  assert victim_stack.reload.archived?, "victim stack was mutated by a payload authenticated under a different org"
end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-69)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
