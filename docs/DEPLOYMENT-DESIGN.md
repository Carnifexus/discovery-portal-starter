# Production direction (not implemented in the loopback demo)

Start with one firm per deployment. Portable design: web service, maintained identity service with MFA for counsel, transaction-backed assignment/response database, private immutable object storage, independent scanner, and protected audit trail. An office worker can scan over an outbound connection or a firm can operate the scanner alongside its private hosting. No case data or credentials belong in the template or the downloadable package. Do not bundle any scanner binaries or libraries; install approved upstream software separately and review its own license.

Before launch configure TLS, identity, least-privilege access, timeouts, retention and holds, confidential logging, and encrypted backup. Test restoration and access isolation with entirely invented materials; then remove demo access and issue fresh operator-controlled accounts. Add a managed patch and incident plan and document a single usable reference deployment before adding additional cloud recipes.

See the [Azure setup guide](AZURE-SETUP.md) for one generic managed-hosting reference. It does not make the loopback demo deployable.

## Optional provider boundary

The default works without API keys. The proposed counsel-side adapter is a different service identity, with no direct client database, file or portal access. Initially restrict it to knowingly approved invented or public text. Report which provider and model will see the exact previewed input. A missing provider policy means no call. Never log prompts or outputs by default. Do not claim that no training is the same as zero retention or that an account type confers privilege.

- [OpenAI API data controls](https://developers.openai.com/api/docs/guides/your-data)
- [Anthropic API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)

## Public release gate

Start private; release only a clean tree with fresh history and a wholly fictional demonstration. Review every file, git object, screenshot, CI artifact and release archive manually and with secret scanners. Confirm licensing and attribution, preserve the public release hash, test the install at a second small firm, and confirm no provider traffic occurs on client or scanner routes. Do not publish this draft as production-ready.
