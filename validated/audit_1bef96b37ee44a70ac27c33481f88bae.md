### Title
Webhook signature is bound only to `repository.owner.login` (used to select the org's secret), not to the `repository.full_name` / commit `sha` that handlers actually act on, allowing cross-repository status/sync forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This is the same class of bug as the ERC1410 report: a value that is trusted/verified (the signing organization) does not cover all the data that downstream code consumes (the repository and commit acted upon), so an attacker can supply out-of-scope data that a signature check never validated.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which HMAC `webhook_secret`) to use for verifying `X-Hub-Signature` purely from `repository_owner`, which is read straight out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` supports one distinct `webhook_secret` per organization, keyed by the organization name in `secrets.github`: [3](#0-2) 

The HMAC itself is only a signature over the raw POST body computed with `webhook_secret`; it says nothing about which organization "owns" that body other than what the body claims: [4](#0-3) 

Once the signature is “verified” with the org’s own secret, the actual repository/commit acted on is derived from *other, uncorrelated* fields of the same attacker-controlled JSON body:

- The generic `Handler` base class resolves stacks from `repository.full_name`, a completely separate field from `repository.owner.login`: [5](#0-4) 

- `StatusHandler` goes even further and does not scope by repository at all — it matches by commit `sha` globally across the whole database: [6](#0-5) 

- A successful/pending status write on a `Commit` can trigger the target stack’s merge queue: [7](#0-6) 

- `PushHandler` similarly resolves stacks via `repository.full_name` and forces a GitHub sync to an attacker-chosen `expected_head_sha`: [8](#0-7) 

The trust binding that should hold is:
`organization whose secret verified the signature == organization that owns the repository/commit the handler mutates`

Before the fix state (current code), the equality is never enforced: `repository_owner` (used only for secret selection) and `repository.full_name` / commit `sha` (used by every handler) are independent, attacker-supplied strings inside the same JSON body. Nothing cross-checks them, exactly like `_getDestinationPartition` trusting `data.length` implicitly instead of validating the region it reads.

### Impact Explanation
Any principal who legitimately administers *one* GitHub organization already onboarded into this Shipit instance (i.e., who knows that organization's `webhook_secret`, because they configured GitHub's webhook delivery to Shipit for their own org/repos) can:
1. Set `repository.owner.login` to their own organization, so `verify_signature` selects their own known secret and the HMAC check passes trivially (they compute it themselves).
2. Set `repository.full_name` (for `push`/`pull_request` handlers) or `sha` (for `status`, unscoped) to reference a stack/commit belonging to a **different** organization/repository entirely.
3. Cause `PushHandler#process` to call `stack.sync_github(expected_head_sha: ...)` on someone else's stack, or `StatusHandler#process` to write a forged `success`/`pending` `Status` onto someone else's commit, which can trigger `stack.schedule_merges` — an unauthorized merge/deploy path on a repository the attacker never had write access to.

This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope, and the resulting impact (forged CI status feeding the merge queue, forced sync to an attacker-chosen SHA) maps to "cross-repository writes / an unauthorized deploy, rollback or merge" — Critical/High impact per the rules.

### Likelihood Explanation
Requires only that the attacker control one legitimately configured GitHub organization/webhook_secret in this Shipit instance (a normal, unprivileged tenant in any multi-org Shipit deployment) — no access to the victim repository, no GitHub App private key, and no Shipit session/API token. The `full_name`/`sha` fields are ordinary JSON body fields with no additional integrity binding, so crafting the forged payload is trivial once the attacker's own secret is known.

### Recommendation
Bind the verified signature to the same identity the handlers act on:
- After signature verification, require that `repository.owner.login` (and ideally `repository.full_name`) matches the actual `Repository`/`Stack` record resolved by handlers, rejecting payloads where they diverge.
- In `StatusHandler`, scope `Commit.where(sha: params.sha)` by the repository/organization that was authenticated for the request, not by a bare SHA lookup across all stacks.
- Consider binding the HMAC check to the resolved `Repository` object itself (verify secret for the resolved repository's stack owner, not an unrelated field of the same untrusted payload).

### Proof of Concept
1. Attacker administers `org-attacker`, onboarded in this Shipit instance with `webhook_secret = S`.
2. Attacker crafts a `status` webhook POST body:
```json
{
  "sha": "<victim_commit_sha_belonging_to_other_org's_stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "org-attacker" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S, body)>` themselves (they know `S`).
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-attacker")` and successfully verifies the signature against the attacker's own secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit regardless of organization — and calls `create_status_from_github!`, which can flip commit status to `success` and invoke `stack.schedule_merges` on a stack the attacker never had access to.

Note: I could not fully verify from the index whether `schedule_merges`/the auto-merge pipeline unconditionally acts on a forged "success" status without additional required checks (e.g., number of required statuses, branch protection re-check via GitHub API) — this would need to be confirmed in a live/dynamic test, since `Commit#add_status` and `MergeRequest` logic may add further gating not fully visible in the indexed snippets.

### Citations

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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
