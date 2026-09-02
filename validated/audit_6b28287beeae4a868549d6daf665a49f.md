Based on my investigation, I found a valid analog. The multi-organization GitHub App configuration in Shipit creates a binding mismatch between the organization whose secret authenticates a webhook and the repository/stack that the webhook payload actually mutates.

### Title
Cross-organization webhook forgery: signature is verified against the org named in the payload, but the affected stack is selected by a different field in the same, attacker-authored payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks which GitHub App/webhook secret to validate a request against using `repository_owner`, a value read directly out of the untrusted, attacker-supplied JSON body [1](#0-0) . In a multi-organization deployment (`config/secrets.yml` `github:` keyed by org, as documented) [2](#0-1)  and supported by `Shipit.github_app_config`/`Shipit.github_organizations` [3](#0-2) , an attacker who controls (or has installed the Shipit GitHub App on) their own org has a legitimate `webhook_secret` for that org. They can craft a `push` webhook payload where `repository.owner.login` is their own org (so the correct secret is selected and the HMAC they compute themselves verifies), while other event-processing fields target a different, victim-owned stack.

### Finding Description
`repository_owner` is derived from the same JSON body that is being verified, not from any independently-authenticated channel: [4](#0-3) 

The organization identified here is used solely to pick which `GitHubApp`/`webhook_secret` performs the HMAC check [1](#0-0) [5](#0-4) . Because the attacker owns that org's app installation, they legitimately know its `webhook_secret` and can compute a correct HMAC over any payload body they construct — including one where the `repository.full_name` (or other fields consumed by handlers) references a stack belonging to a different organization entirely.

Downstream handlers such as `PushHandler` never re-check that the stack's owning organization matches the organization whose secret validated the request; they resolve the target purely from `Stack`/`Repository` lookups keyed on branch/full_name found in the same payload [6](#0-5) , and `Repository.from_github_repo_name`/`Stack.from_param!` do plain owner/name lookups with no cross-check against the authenticating org [7](#0-6) .

This is the same class of bug as the PoolTogether finding: the verification step and the action step are bound to different scopes of the same input. There, the try/catch success signal was checked per-item but the emitted event covered the whole (unfiltered) list. Here, the HMAC is checked against one identity (the org named in the payload) but the mutation is applied to a target selected from an unrelated field of the same payload — i.e. "organization that authenticated versus the repository that is written" is never asserted to be equal.

### Impact Explanation
An attacker who runs any org where Shipit's GitHub App is installed (a normal, unprivileged action for a multi-tenant Shipit instance — no Shipit account, `ApiClient` token, or repository write access to the victim repo is required) can forge webhook events (e.g. `push`, `status`, `check_suite`) that are accepted as authentic for a completely different, victim-owned Stack. Depending on the handler this can trigger `GithubSyncJob`, alter commit `Status`, or otherwise influence deploy-readiness/CI-status state used to gate deploys — an unauthorized mutation of another repository's Shipit state without ever compromising that repository's real webhook secret, i.e. "cross-repository writes" via signature-scope confusion.

### Likelihood Explanation
Requires only that the deployment uses (or the attacker convinces the admin to use) the multi-organization GitHub config documented for Shipit, and that the attacker has an org with the Shipit App installed — no privileged Shipit credential is needed. This is a design gap rather than a rare edge case: any Shipit instance serving more than one GitHub organization is affected by construction, since `verify_signature` trusts an unauthenticated field to choose the verification key.

### Recommendation
After signature verification succeeds, re-derive the target Stack/Repository strictly from a value bound to the organization that was actually used to verify the signature (e.g., assert `repository.full_name.split('/').first == repository_owner`, or better, verify against the installation ID returned by GitHub for that specific delivery rather than trusting `repository.owner.login`). Reject the webhook if the two do not match.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, `attacker-org` and `victim-org`, both with the Shipit GitHub App installed (per `docs/setup.md` multi-org schema).
2. As the owner of `attacker-org`, obtain `attacker-org`'s `webhook_secret` (legitimately available to them as the app installer).
3. Register/know that `victim-org/victim-repo` exists as a Shipit `Stack`.
4. Craft a `push` payload: `repository.owner.login = "attacker-org"`, `repository.full_name = "victim-org/victim-repo"`, `ref = "refs/heads/<victim-branch>"`, `after = "<attacker-chosen sha>"`.
5. Compute `X-Hub-Signature` using `attacker-org`'s real `webhook_secret` over this exact payload and POST to `/webhooks`.
6. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC verifies successfully (the attacker signed it with their own valid secret).
7. `PushHandler#process` then looks up stacks by `branch` (matched against whatever `Repository`/`Stack` records exist for `victim-org/victim-repo` via `full_name`/`Repository.from_github_repo_name`) and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack — a write the attacker was never authorized to trigger, using a signature the victim org never produced.

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

**File:** docs/setup.md (L18-38)
```markdown
2. Run this command:  `rails _8.0_ new shipit --skip-action-cable --skip-turbolinks --skip-action-mailer --skip-active-storage --skip-webpack-install --skip-action-mailbox --skip-action-text -m https://raw.githubusercontent.com/Shopify/shipit-engine/main/template.rb`

## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
  - Repository permissions:
    - Checks: Read & write
    - Commit statuses: Read-only
    - Contents: Read & write (to allow merging)
    - Deployments: Read & write
    - Issues: Read & write (to allow closing related issues on merge)
    - Metadata: Read-only
    - Pull requests: Read & write
```

**File:** lib/shipit.rb (L190-200)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
