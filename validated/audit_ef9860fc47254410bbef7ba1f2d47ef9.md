### Title
Cross-org webhook forgery lets an attacker archive a victim's review stack via `UnlabeledHandler#process` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')`, a value taken directly from the attacker-supplied JSON body, while `UnlabeledHandler#repository` (mirroring `LabeledHandler#repository`) resolves the actual `Repository` record to act on using the independently attacker-controlled `params.repository.full_name`. Because these two fields are never cross-checked, an attacker who legitimately owns an onboarded org can sign a payload with their own valid webhook secret while claiming, via `full_name`, to describe a completely different (victim) repository, causing the victim's active review-stack to be archived.

### Finding Description
The broken binding is: `repository_owner` used to select the verifying `GitHubApp` in `verify_signature` MUST equal the owning org of the `Repository` resolved and mutated by the handler — i.e. `params.dig('repository','owner','login') == owner_of(Repository.from_github_repo_name(params.repository.full_name))`. This does not hold.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` purely from the raw JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and uses it to fetch the corresponding `GitHubApp`/webhook secret for signature verification [2](#0-1) .
2. An attacker who owns/administers their own org (`attacker-org`) legitimately onboarded to this multi-tenant Shipit instance knows (or can trigger delivery of) a validly-signed webhook for that org, because GitHub computes the HMAC over the exact raw body the attacker crafts, including a `repository.owner.login` of `attacker-org` — this passes `verify_signature`.
3. In the same JSON body, the attacker sets `repository.full_name` to the victim's repo (e.g. `"victim-org/victim-repo"`), independent of `repository.owner.login`.
4. `Shipit::Webhooks.for_event(event)` dispatches to `UnlabeledHandler.call(params)` [3](#0-2) , whose `repository` method resolves the record purely from `params.repository.full_name`, with no dependency on the verified `repository_owner`: [4](#0-3) .
5. `respond_to_label_change?` and `archive?` then evaluate purely against the victim repository's `provisioning_behavior_allow_with_label?` config and the attacker-declared (absent) label in the payload [5](#0-4) , and `handle` calls `stack.archive!` on the victim's `ReviewStackAdapter`-resolved stack [6](#0-5) .

No existing guard closes this gap: `ExplicitParameters` only validates types/presence of fields, not cross-field/cross-record consistency [7](#0-6) ; `drop_unhandled_event` only checks the event name is registered; `verify_signature` never re-derives or checks `repository_owner` against the `full_name` used later by the handler.

### Impact Explanation
A payload for one organization/repository (attacker-controlled, correctly signed) mutates another organization's stack — this is exactly the "payload for one repository mutating another's stack" Critical category. The attacker can archive (kill) any victim review-stack whose repo full_name and PR number they can guess/know, using only their own legitimate webhook credentials, repeatably against arbitrary target repositories/stacks configured on the same Shipit instance, as long as the target uses label-gated provisioning (`allow_with_label` or `prevent_with_label`). This is not confined to one tenant; blast radius spans every repository hosted by the Shipit instance.

### Likelihood Explanation
Preconditions: attacker must own/administer at least one GitHub org already onboarded into this Shipit instance (so `Shipit.github(organization: 'attacker-org')` resolves to a configured `GitHubApp` with a real `webhook_secret`), and the victim repo must have `review_stacks_enabled` with `allow_with_label`/`prevent_with_label` provisioning and an active provisioned stack for a known/guessable PR number. Attacker cost is low: crafting a JSON body with mismatched `repository.owner.login` vs `repository.full_name` and signing it with their own known secret requires no privileged credentials, no session, and no knowledge of the victim's secrets. This is fully repeatable per request.

### Recommendation
Bind the verified organization to the repository the handler acts on: after `verify_signature` succeeds, require that the resolved `Repository.from_github_repo_name(payload.repository.full_name)`'s owner matches `repository_owner` used for verification (or, simpler, derive the owner used for both signature verification and repository lookup from the *same* parsed `full_name`, and reject if `repository.owner.login` disagrees with the owner segment of `full_name`). Add this check centrally in `Shipit::Webhooks::Handlers::Handler` (or in the controller) so all handlers, including `UnlabeledHandler` and `LabeledHandler`, are protected.

### Proof of Concept
Minitest plan (webhooks controller/integration test, `test/controllers/webhooks_controller_test.rb` pattern, no live GitHub — signature computed locally with the attacker org's configured `webhook_secret`):
```ruby
test "cross-org forged unlabeled webhook archives a victim stack it did not authenticate" do
  # victim org/repo with an active, provisioned review stack under allow_with_label
  victim_repository = shipit_repositories(:shipit) # full_name "shipit/shipit", owner "shipit"
  configure_provisioning_behavior(repository: victim_repository, behavior: :allow_with_label, label: "pull-requests-label")
  stack = create_stack # active/unarchived review stack owned by victim_repository, PR number N

  payload = payload_parsed(:pull_request_unlabeled)
  payload["repository"]["full_name"] = victim_repository.github_repo_name   # claims victim repo
  payload["repository"]["owner"]["login"] = "attacker-org"                 # attacker's own onboarded org
  payload["pull_request"]["labels"] = []                                  # provisioning label absent

  body = payload.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_org_webhook_secret, body)

  assert_equal "attacker-org", payload.dig("repository", "owner", "login") # side A: verifying org
  assert_equal victim_repository.owner, Shipit::Repository.from_github_repo_name(payload["repository"]["full_name"]).owner # side B: acted-on org
  assert_not_equal payload.dig("repository", "owner", "login"),
                    Shipit::Repository.from_github_repo_name(payload["repository"]["full_name"]).owner
  # side A != side B before the fix

  post "/webhooks", params: body, headers: { "X-Github-Event" => "pull_request", "X-Hub-Signature" => signature, "CONTENT_TYPE" => "application/json" }

  assert_response :ok
  assert stack.reload.archived?, "Victim stack was archived by a request never authenticated by the victim org"
end
```
This demonstrates request forged/signed under `attacker-org` credentials successfully archives `victim_repository`'s stack, confirming the equality `repository_owner (verification) == owner(repository resolved for mutation)` is false and unenforced.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-89)
```ruby
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
```
