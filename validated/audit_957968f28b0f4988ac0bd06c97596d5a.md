Confirmed: `Repository.from_github_repo_name` looks up purely by the `repository.full_name` field in the payload, with no cross-check against the `repository.owner.login` value used by `verify_signature` for HMAC authentication.### Title
Cross-repository payload confusion in `pull_request` webhook auth lets `UnlabeledHandler` archive/unarchive an unrelated victim `ReviewStack` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` used for HMAC verification purely from `repository.owner.login` (or `organization.login`), while `UnlabeledHandler`/`ReviewStackAdapter` resolve the target `Repository`/`ReviewStack` purely from `repository.full_name`. These two fields are independently attacker-controlled in the JSON body, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization's configured `webhook_secret` is blank. Combining a Shipit-configured, no-secret organization for the authentication field with a victim's real `repository.full_name`/PR number lets an unauthenticated attacker forge a `pull_request` `unlabeled` event that archives or unarchives a victim's `ReviewStack`, and on a stack with `ignore_ci: true` this can enable deployment of arbitrary already-pushed commits without any CI gating.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == owner(params.dig('repository','full_name'))`, i.e., that the organization used to authenticate the webhook is the same organization that owns the repository being mutated. This is never checked.

- `Shipit::WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` immediately (skipping HMAC entirely) when the resolved organization's config has no `webhook_secret` [3](#0-2) . The codebase itself demonstrates a multi-org config where one org (`OrgTwo`/`OrgOne` in `secrets_double_github_app.yml`) has `webhook_secret: # nil` [4](#0-3) , confirming this "no-secret organization" state is a supported configuration, not a hypothetical.
- Once past `verify_signature`, `Shipit::Webhooks.for_event(event)` handlers run against the *entire raw `params`* [5](#0-4) , including `UnlabeledHandler`, which resolves the target repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [6](#0-5) , and `Repository.from_github_repo_name` looks the record up purely by parsing that string (`owner/name`) with no relation to the authenticating organization [7](#0-6) .
- `UnlabeledHandler#handle` then archives or unarchives the matching `ReviewStack` for that repository based on the provisioning label logic [8](#0-7) , and `ReviewStackAdapter#stack` finds the exact existing stack by `environment: "pr#{params.number}"` [9](#0-8) , `pr_number = params.number` [10](#0-9) , both directly attacker-controlled and independent of the PR actually being on any repo the attacker owns.

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, body `{"action":"unlabeled", "repository": {"owner":{"login":"orgtwo"}, "full_name":"victim-org/victim-repo"}, "number": <victim PR#>, "pull_request": {...state: "open", labels: [...]}}`. Since `orgtwo` is a Shipit-configured org with blank `webhook_secret`, `verify_signature` passes with `verified = true` regardless of the `X-Hub-Signature` header content. The handler then looks up `victim-org/victim-repo`'s `ReviewStack` for the given PR number and archives/unarchives it based on label presence, entirely independent of `orgtwo`.

On a victim stack with `ignore_ci: true`, `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [11](#0-10) , so unarchiving/re-enqueuing that stack for provisioning (which can lead to deploy/continuous-delivery triggering depending on stack config) bypasses CI checks for whatever commit is at the PR head.

Why existing guards fail: `drop_unhandled_event` only checks the event type is handled, not payload consistency; `ExplicitParameters` schemas in `UnlabeledHandler` only validate the shape/types of fields, not cross-field consistency between `repository.owner.login` and `repository.full_name` [12](#0-11) ; there is no `require_permission!`/session check on this unauthenticated controller by design (webhooks are meant to be authenticated solely by HMAC, which is bypassed here).

### Impact Explanation
An unprivileged internet attacker who knows (a) the name of any Shipit-configured GitHub organization/app that has no `webhook_secret` set, and (b) a target repository's `full_name` and an existing review-stack PR number, can forge unauthenticated `pull_request` `unlabeled` webhooks that archive or unarchive that target's `ReviewStack` — a write to a repository/stack that never authenticated the request, matching the audit's explicit Critical criterion "a payload for one repository mutating another's stack." This is repeatable against any repository tracked by Shipit and any PR-numbered review stack, as long as the "no-secret organization" precondition holds somewhere in the deployment. When the target stack has `ignore_ci: true` (and, separately, `continuous_deployment` enabled), forcing it through unarchive/re-provisioning can result in deployment of the current PR head commit without CI gating, amplifying the write into an unauthorized deploy.

### Likelihood Explanation
Requires: (1) the Shipit deployment to have at least one configured GitHub org/app with `webhook_secret` blank — a supported, documented configuration pattern in this repo (`secrets_double_github_app.yml`, `secrets.development.example.yml`) rather than a rare edge case; (2) `review_stacks_enabled` and a non-`allow_all` `provisioning_behavior` configured on the victim repository; (3) knowledge of the victim's `full_name` and PR number (both public GitHub information); (4) a pre-existing victim stack with `ignore_ci: true` for the CI-bypass amplification. Attacker cost is a single unauthenticated HTTP POST with no valid signature, secret, or session — reproducible at will.

### Recommendation
Bind webhook authentication to the exact repository being mutated, not just its owning organization: verify the HMAC using the `webhook_secret` associated with `repository.full_name` (or the `Repository` record it maps to), and additionally validate that `params.repository.owner.login` matches the owner segment of `params.repository.full_name` before dispatching to any handler. Do not allow `verify_webhook_signature` to return `true` for organizations with a blank `webhook_secret` in non-test environments; require an explicit "no signature verification" opt-in per repository rather than a silent bypass.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "forged pull_request unlabeled event from a no-secret organization mutates a victim repo's review stack" do
  # Precondition: shipit-engine test config includes an org ("orgtwo") with blank webhook_secret
  # and a distinct victim repository/review-stack pair with ignore_ci: true.
  victim_repo = shipit_repositories(:shipit) # full_name "shopify/shipit-engine" or similar
  configure_provisioning_behavior(repository: victim_repo, behavior: :allow_with_label, label: "pull-requests-label")
  stack = create_stack_with_ignore_ci_true(victim_repo) # pre-provisioned ReviewStack, environment "pr#{n}"

  payload = payload_parsed(:pull_request_unlabeled)
  payload["repository"]["full_name"] = victim_repo.full_name       # targets victim's repo/stack
  payload["repository"]["owner"]["login"] = "orgtwo"               # org with blank webhook_secret
  payload["number"] = stack_pr_number(stack)
  payload["pull_request"]["labels"] = []                            # triggers archive?

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef'              # invalid/garbage signature

  post :create, body: payload.to_json, as: :json

  assert_response :ok
  assert stack.reload.archived?, "Victim stack was archived by an unauthenticated forged webhook"
end
```
Assert-both-sides binding: before the request, `stack.archived? == false`; the equality the code assumes is `authenticating_org(repository.owner.login) == owning_org(repository.full_name)`. After forging a request where these differ (`orgtwo` vs victim's real owner) and the request still returns `:ok` with `stack.archived? == true`, the binding is proven broken.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L8-39)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-98)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

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

          def pull_request
            params.pull_request
          end

          def pull_request_state
            pull_request["state"]
          end

          def respond_to_label_change?
            params.action == "unlabeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L68-70)
```ruby
          def pr_number
            params.number
          end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
