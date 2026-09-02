### Title
Webhook signature verified against `repository.owner.login`/`organization.login`, but handlers act on the unchecked `repository.full_name` — cross-organization stack sync/deploy trigger - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to HMAC-verify the inbound payload against by reading `repository_owner`, which is derived from the payload itself: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0) [2](#0-1) 

Shipit explicitly supports configuring multiple GitHub organizations, each with its own distinct `webhook_secret`, as documented in `docs/setup.md` and the multi-org secrets fixtures. [3](#0-2) [4](#0-3) 

Once signature verification succeeds, the event is dispatched to handlers (e.g. `Shipit::Webhooks::Handlers::PushHandler`) which independently derive the *acted-upon* repository from `payload.dig('repository', 'full_name')` via the base `Handler#repository_name`/`#stacks` methods — a **different JSON field** than the one used to pick the verifying secret. [5](#0-4) [6](#0-5) 

Because the entire request body is HMAC-signed, the signature does mathematically cover both `repository.owner.login` and `repository.full_name` — but the *choice of which secret to check against* is attacker-controlled, since it is read from the same untrusted payload. An operator of Organization A (who has legitimately installed the Shipit GitHub App on their own org and thus genuinely knows Org A's `webhook_secret`) can therefore construct and self-sign an arbitrary payload where:
- `repository.owner.login` = `"orgA"` (so `verify_signature` selects Org A's secret, which the attacker knows and can correctly HMAC with), and
- `repository.full_name` = `"orgB/some-private-repo"` (an entirely unrelated organization/repository Shipit also manages).

`Repository.from_github_repo_name` splits `full_name` on `/` and looks up the `owner`/`name` independent of the org used for signature verification. [7](#0-6) 

This breaks the intended binding: **organization authenticated (Org A) ≠ repository written/acted upon (Org B)**.

### Impact Explanation
`PushHandler#process` will resolve `Repository.from_github_repo_name("orgB/some-private-repo")`, then iterate over that repository's non-archived stacks matching the (attacker-supplied) branch and call `stack.sync_github(expected_head_sha: params.after)`, enqueuing `GithubSyncJob` for Org B's stack with an attacker-chosen `expected_head_sha`. [6](#0-5) 

This is an unauthorized cross-organization write into another organization's Stack/sync/deploy pipeline: an actor who only controls Org A's webhook secret can force actions (GitHub sync, and depending on continuous-deployment settings, deploy triggering) against Org B's stacks, which they have no authorization over. This falls squarely in the specified impact category of "cross-repository writes" / "an unauthorized deploy."

Other handlers keyed the same way (`stacks` helper in `Handler`) are similarly exposed — e.g. `status`, `check_suite`, `membership`/`pull_request` handlers that use `repository_name`/`full_name` to resolve the target Stack, all while trust in the request was established using the `repository.owner.login` (or `organization.login`) field instead. [5](#0-4) 

### Likelihood Explanation
Exploitability requires the attacker to legitimately control at least one organization configured on the shared Shipit instance (and thus know that org's real `webhook_secret`), which is a realistic scenario for any Shipit deployment serving multiple tenant organizations (explicitly documented and tested as a supported configuration: `test/dummy/config/secrets_double_github_app.yml`). Given that, forging the payload is trivial — no GitHub-side controls prevent an org owner from sending arbitrary webhook payloads with any `repository.full_name` value directly to Shipit's `/webhooks` endpoint, since Shipit's controller does not check that the two fields refer to the same organization. [8](#0-7) 

### Recommendation
In `WebhooksController#verify_signature`, and/or in `Handler#repository_name`, enforce that the organization used to select the verifying `webhook_secret` matches the owner encoded in `repository.full_name` (and `organization.login` for org-level events) before processing. Reject the webhook (422) if they diverge. Alternatively, resolve the target `Repository`/`Stack` first, derive its canonical owner from the Shipit database record, and verify the signature using that resolved owner's secret rather than trusting attacker-supplied owner fields for secret selection.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` and `orgB`, each with a distinct `webhook_secret` (per `docs/setup.md` multi-org config).
2. The attacker legitimately administers `orgA` and knows `orgA`'s `webhook_secret` (e.g., they set up the GitHub App on their own org).
3. The attacker crafts a JSON `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/private-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac_sha1(orgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, fetches `Shipit.github(organization: "orgA")`, and successfully verifies the signature (since the attacker signed with the correct secret for `orgA`).
6. `PushHandler#process` runs using `repository_name = "orgB/private-repo"`, resolves `orgB`'s `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha: "deadbeef...")`, queuing a `GithubSyncJob` against `orgB`'s stack — an org the attacker has no legitimate relationship to — despite the webhook only having been authenticated for `orgA`.

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

**File:** docs/setup.md (L17-30)
```markdown
1. If you don't have Rails installed, run this command: `gem install rails -v 8.0`
2. Run this command:  `rails _8.0_ new shipit --skip-action-cable --skip-turbolinks --skip-action-mailer --skip-active-storage --skip-webpack-install --skip-action-mailbox --skip-action-text -m https://raw.githubusercontent.com/Shopify/shipit-engine/main/template.rb`

## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
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
