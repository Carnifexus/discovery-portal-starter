# Discovery Portal Starter

**Lawyers: [Start here](START-HERE.md).**

An early, local-only prototype of a firm-controlled discovery questionnaire. It includes a wholly invented demo, separate client and counsel accounts, per-person assignments, private replies, document-search status, and a retained history. It permits small, invented PDF or text uploads in a local quarantine demonstration; it does not connect to any AI provider. It does not produce, serve, or file discovery responses. **Do not enter real client or matter information.**

## Choose what you want to run

- The root loopback demo is a small local illustration. It is intentionally not deployable.
- The separate [portable Azure runtime](azure-runtime/) is a source template with authenticated respondent/counsel views, encrypted state, private quarantine and an independent worker. It requires a fresh fictional seed and your own staging resources. Do not point it at an existing firm's state or copy anyone's deployment settings. The portable code passed the isolated workflow tests; you must verify it on your own host before using real matter data.

## Try the local demo

Requires Python 3.11 or later; no external services or package installation.

    python3 portal_demo.py

Open the exact 127.0.0.1 URL printed in the terminal. The application generates temporary demo credentials for counsel, a witness, and a records custodian. These are for the invented exercise only. Press Ctrl+C when finished. Demo responses live in a temporary directory and are removed on normal exit. Uploads are viewable by counsel only after a clean verdict from an independently installed, current local scanner. With no scanner, files stay in quarantine. Do not expose the loopback demo through a reverse proxy, tunnel, container port mapping, or public host.

    python3 -m unittest discover -s tests -v

Respondents can open the interrogatory, production, and admission views in any order. Relevant terms are highlighted beside the request, with the exact source definition and a separately labeled plain-English gloss. The original wording remains the reference.

## Try quarantine with a separate scanner

Start an independently installed ClamAV daemon on a local Unix socket, with current signatures, an 8-second scan timeout, and at least a 2 MiB INSTREAM limit. Run the daemon in UTC with the C locale for freshness checks. Never expose its socket to other users or open a TCP listener for this demo. Restart the demo with:

    DEMO_CLAMD_SOCKET=/absolute/path/to/clamd.sock python3 portal_demo.py

Sign in as the records custodian and submit an invented file under a document request. Or sign in as the witness, send the interrogatory answer on its own, and use **Supporting documents (optional)** to attach one or more files under that specific interrogatory. In a separate browser profile sign in as counsel, check that the file is still pending, and click **Check with local scanner**. Counsel can download the exact original only after the scanner reports it clean. The demo deliberately has no background scanner, scanner binaries, uploads to model providers, or permission to run on a public server.

## Why we built it

[Build a Private Path to Counsel](docs/WHITE-PAPER.md) explains the problem, the architecture, and the argument that a correctly used collection channel need not itself waive an existing protection.

## Work with your own AI assistant

Copy [docs/BUILD-WITH-YOUR-AI.md](docs/BUILD-WITH-YOUR-AI.md) into your AI assistant, and give it this source tree only. That is for building software, not processing your clients' material. It assumes access to a coding assistant and standard hosting tools or comparable alternatives. Read [docs/DEPLOYMENT-DESIGN.md](docs/DEPLOYMENT-DESIGN.md) first. For a provider-specific, independently reproducible outline, see the [Azure setup guide](docs/AZURE-SETUP.md).

## License status

Proposed license for the public release: Apache 2.0. This private review package is not a public release. Confirm ownership of copyrightable contributions and any third-party obligations before distribution. No branding, confidential records, or private deployment code is part of this starter.
