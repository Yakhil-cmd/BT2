Based on my analysis, this Shipit deployment confirms multi-tenant, per-organization GitHub App configuration: `Shipit.github_app_config(organization)` looks up a distinct config (including a distinct `webhook_secret`) per organization key in `secrets.github` [1](#0-0) , and `Shipit.github(organization:)` instantiates a `GitHubApp` scoped to that organization's own secret [2](#0-1) .

### Title
Webhook organization used for signature verification is not bound to the repository the handlers act on - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the per-organization webhook secret from `repository_owner`, which is computed independently of the `repository.full_name` value later trusted by every webhook handler to locate and mutate `Stack`/`Repository`/`PullRequest`/`MergeRequest` records.

### Finding Description
`verify_signature` derives the signing organization as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) , and uses it solely to select which per-org `webhook_secret` HMAC to validate against via `Shipit.github(organization: repository_owner)` and `verify_webhook_signature` [4](#0-3) . Once the signature check passes, the entire raw JSON body is dispatched unmodified to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) . Handlers such as the generic `Handler` base class then resolve the target `Repository`/`Stack` using a *different* payload field, `payload.dig('repository', 'full_name')` [6](#0-5) , and pull-request handlers do the same via `params.repository.full_name` [7](#0-6) .

Because `Shipit.github_app_config` looks up configuration per-organization key from `secrets.github`, in any multi-org Shipit deployment (multiple orgs onboarded, each with their own `webhook_secret`) [1](#0-0) , the field used to select the verifying secret (`repository.owner.login`, falling back to `organization.login`) is not cryptographically or structurally tied to the field the handlers trust to decide which `Stack`/`Repository`/`PullRequest` gets written (`repository.full_name`). The binding that should hold is: `organization_that_signed == organization_of_repository_written`. If an attacker who legitimately controls a GitHub organization/repository already onboarded onto this Shipit instance (and therefore can produce a validly-signed webhook using their own org's `webhook_secret`, e.g. by pushing to their own repo or editing their own PR) crafts a `repository` object whose `full_name` points at a different, victim organization's repository while `owner.login` is omitted or manipulated to fall back to their own controlled `organization.login`, `verify_signature` still validates successfully against the attacker's own valid secret, yet the handler dispatch proceeds to look up and mutate the victim repository's `Stack`/`PullRequest`/`MergeRequest` records using `full_name`.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary named in the rules. A successful exploit lets an attacker with control of one onboarded organization forge webhook events (e.g. `pull_request` `edited`/`closed`, `push`, `status`) that are accepted as validly-signed but cause writes against a completely different, victim repository's Shipit-tracked entities — e.g. archiving a review stack (`review_stack.archive!` in `closed_handler.rb`) or overwriting `PullRequest#github_pull_request` state (`edited_handler.rb`), corresponding to unauthorized cross-repository writes.

### Likelihood Explanation
This requires the Shipit instance to be configured for multiple GitHub organizations with independent `webhook_secret`s (the multi-tenant schema explicitly supported by `github_app_config`) and requires the attacker to already control at least one onboarded organization capable of emitting a validly-signed webhook. Whether GitHub itself would ever populate `repository.owner.login` differently from `repository.full_name`'s owner in a legitimately-relayed webhook is unclear from the code alone — this analysis identifies that the code does not itself enforce consistency between the two fields, but I could not verify from the available files whether GitHub's own webhook delivery guarantees would prevent an attacker from directly crafting such a mismatched raw body and having it delivered as a webhook (vs. needing an actual proxy/replay mechanism). This uncertainty affects the practical likelihood and should be validated further.

### Recommendation
After `verify_signature` succeeds, re-derive/assert that the organization used for signature verification matches the owner embedded in `repository.full_name` (or any other field a handler will use to locate the target `Stack`) before dispatching to handlers, so the two are cryptographically bound to the same value rather than independently derived from attacker-controlled JSON.

### Proof of Concept
Conceptual sequence (not verified end-to-end against live GitHub delivery, since that depends on infrastructure outside this codebase):
1. Attacker controls `attacker-org/attacker-repo`, onboarded on the same multi-tenant Shipit instance, and its own `webhook_secret`.
2. Attacker triggers a real GitHub event on `attacker-org/attacker-repo` (e.g., edits a PR) so the webhook is HMAC-signed with `attacker-org`'s secret and delivered/replayed with a body where `repository.owner.login` is omitted (falling through to `organization.login` = `attacker-org`) but `repository.full_name` is rewritten to `victim-org/victim-repo`.
3. `verify_signature` computes `repository_owner` as `attacker-org` (via the `organization.login` fallback) and validates successfully against `attacker-org`'s secret [8](#0-7) .
4. `Handler#repository_name`/handler-specific lookups use `repository.full_name` = `victim-org/victim-repo` to locate and mutate the victim's `Stack`/`PullRequest` [6](#0-5) .

### Citations

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-34)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
