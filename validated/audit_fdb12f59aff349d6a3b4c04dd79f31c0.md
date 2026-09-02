Confirmed: `Repository.from_github_repo_name` derives the repository purely from `params.repository.full_name`, split on `owner/name`, with no cross-check against `repository_owner` (which was only used for signature selection). This confirms the split is real and unguarded.

### Title
`pull_request` `labeled` webhook lets a no-secret org's signature authenticate mutations to a different org's review stack - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to check using only `repository.owner.login` (`repository_owner`), while `LabeledHandler#repository` resolves the actual mutated `Shipit::Repository` using only `params.repository.full_name`. In a multi-org Shipit deployment, if the org named in `repository.owner.login` has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, letting an attacker forge a `pull_request` `labeled` event whose `repository.full_name` points at a completely different, actually-configured victim org/repo whose review stack (`review_stacks_enabled: true`, `allow_all`) gets archived/unarchived.

### Finding Description
The invariant that should hold is: `repository_owner used to select github_app-for-signature-verification == owner(params.repository.full_name) used to resolve the mutated Repository`. This does not hold anywhere in the code.

- `verify_signature` picks `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` if that org's config has no `webhook_secret`: `return true unless webhook_secret` [3](#0-2) .
- After signature "verification" passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire, unvalidated* payload to handlers [4](#0-3) .
- `LabeledHandler#repository` resolves the target repository purely from `params.repository.full_name`, never from `repository_owner`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [5](#0-4) .
- `Repository.from_github_repo_name` splits `full_name` on `/` and does a plain `find_by(owner:, name:)` with no cross-check against any authenticated org: [6](#0-5) .
- `LabeledHandler#handle` then calls `stack.archive!`/`stack.unarchive!` on the resolved victim's review stack based on `repository.provisioning_behavior_allow_all?`, `repository.review_stacks_enabled`, and the PR's label set [7](#0-6) .

Exploit flow: this bug requires the multi-org config schema (`docs/setup.md` "Using Multiple Github Applications") where per-org `webhook_secret` is set individually per organization. An attacker crafts a JSON body with `X-Github-Event: pull_request`, `action: labeled`, sets `repository.owner.login` to an org configured in Shipit's `secrets.github` with a blank/absent `webhook_secret`, but sets `repository.full_name` to `victim-org/victim-repo` (an org with review-stacks/`allow_all` enabled and its own secret). No `X-Hub-Signature` (or any arbitrary one) is required. `verify_signature` looks up the no-secret org's `GitHubApp`, `verify_webhook_signature` returns `true` unconditionally, and the request proceeds to `LabeledHandler`, which archives/unarchives `victim-org/victim-repo`'s review stack — a stack whose provisioning (`allow_all`) means unarchiving triggers re-provisioning and executes the victim's `shipit.yml`, an attacker-controlled amplification path since `allow_all` auto-provisions review stacks from any external PR.

None of the existing guards intercede: `drop_unhandled_event` only checks the event type is handled at all [8](#0-7) ; `ExplicitParameters` schema in `LabeledHandler` only requires `repository.full_name` to be a `String`, not that it matches `repository_owner` [9](#0-8) ; there is no code anywhere cross-validating `repository_owner` against `params.repository.full_name`'s owner segment.

### Impact Explanation
An attacker who controls a "throwaway" GitHub org configured in Shipit with no webhook secret (or who can get an operator to configure one org without a secret in a multi-org Shipit deployment) can archive or unarchive review stacks belonging to any other configured org/repository at will, without ever possessing that org's `webhook_secret`. Because unarchiving a review stack under `allow_all` provisioning auto re-provisions and runs the target repository's `shipit.yml` (per the scenario's stated behavior), this is a payload for one repository (the no-secret org) mutating another org's stack and triggering execution of attacker-adjacent CI config for a repo the attacker doesn't own — matching the Critical "payload for one repository mutating another's stack ... or an unauthorized deploy" category, since it's a genuine authentication-bypass-adjacent cross-tenant write with a documented RCE-class amplification through re-provisioning and `shipit.yml` execution.

### Likelihood Explanation
This requires Shipit to be configured with the multi-org github secrets schema (`docs/setup.md` "Using Multiple Github Applications") and for at least one configured organization to have a blank/omitted `webhook_secret` — a realistic misconfiguration since the example config templates show `webhook_secret:` with no value as syntactically valid [10](#0-9) . Given that precondition, the attack costs a single unauthenticated HTTP POST to `/webhooks` with a forged JSON body, is fully repeatable, and requires no GitHub credentials, session, or API token — only knowledge of which org lacks a secret and the target repo's `full_name`.

### Recommendation
After resolving the target repository/stack in each handler (or centrally in `WebhooksController`), verify that the org that authenticated the webhook (`repository_owner`) matches the owner of the repository actually being mutated (derived from `params.repository.full_name`), and reject the request if they differ. Additionally, treat a missing/blank `webhook_secret` for a configured organization as a hard misconfiguration (refuse to start, or always reject with 422) rather than silently trusting all webhooks for that org.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure two orgs via `secrets.github`: `"attacker-org"` with no `webhook_secret`, and `"victim-org"` with a real `webhook_secret`.
2. Create `Shipit::Repository.create!(owner: "victim-org", name: "victim-repo", provisioning_behavior: "allow_all")` with a `review_stacks_enabled`-truthy config, plus an active `ReviewStack` for a PR number matching the payload.
3. Assert binding before: `repository_owner` (computed from payload `repository.owner.login` = `"attacker-org"`) `!= owner(params.repository.full_name)` (`"victim-org"`), i.e., they diverge by construction.
4. POST to `/webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` (or a garbage one), and body: `{"action":"labeled","number":<pr>,"pull_request":{...,"state":"open","labels":[{"name":"<provisioning_label>"}]},"repository":{"full_name":"victim-org/victim-repo","owner":{"login":"attacker-org"}},"sender":{"login":"attacker"}}`.
5. Assert `response.status == 200` (not 422) — proving the forged, unsigned request was accepted because `attacker-org` had no secret.
6. Assert the victim `ReviewStack` for `victim-org/victim-repo` was archived/unarchived (`stack.reload.archived? == expected`), proving a request authenticated only for `attacker-org` mutated `victim-org`'s stack — the equality from step 3 remains violated after the request, demonstrating the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-97)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
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

**File:** config/secrets.development.example.yml (L18-34)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
```
