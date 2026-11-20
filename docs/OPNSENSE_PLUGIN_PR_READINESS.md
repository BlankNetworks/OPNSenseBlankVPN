# OPNsense plugins pull request readiness

This checklist records the work needed to propose Blank VPN & Proxy to
`opnsense/plugins`. It is preparation for an upstream discussion, not a claim
that the current standalone release is already suitable for merging there.

## Upstream requirements checked

- New plugins should be discussed in an issue before a pull request.
- The proposal must use the latest `opnsense/plugins` master, explain the
  problem and solution, and comply with the BSD 2-Clause contribution terms.
- A plugin integrating service executables must use software available in
  FreeBSD ports. Precompiled executables must not be committed to the plugin
  tree.
- New plugins should have a reviewable initial scope, follow the existing MVC,
  API, model, ACL, and configd patterns, and name a maintainer who will support
  the plugin over time.
- AI assistance must be disclosed in the submission.

References: [plugin contribution guide](https://github.com/opnsense/plugins/blob/master/CONTRIBUTING.md),
[plugin build framework](https://github.com/opnsense/plugins/blob/master/Mk/plugins.mk),
[development guidelines](https://docs.opnsense.org/development/guidelines/basics.html),
[development workflow](https://docs.opnsense.org/development/workflow.html),
[support tiers](https://docs.opnsense.org/support.html).

## Current repository fit

- The maintained OPNsense application is under `src/` in the standard
  `/usr/local` file layout. It contains MVC controllers, models, ACL and menu
  definitions, configd actions, templates, scripts, and service hooks.
- Standalone packages are currently built by `build/package.py`; the root does
  not yet have the upstream category `Makefile` that includes
  `../../Mk/plugins.mk`. The standalone package flow must remain separate from
  the upstream port build.
- The source tree does not commit core executables. The standalone core manager
  downloads pinned release archives from Blank-hosted GitHub releases. The
  upstream plugin must instead depend on supported OPNsense package origins
  and use the installed binaries, or submit/coordinate any missing ports first.
- The core projects have FreeBSD Ports entries (`net/mihomo`, `net/sing-box`,
  `security/xray-core`, and `net/tun2socks`), but their exact package names,
  architecture support, availability in OPNsense's package repositories, and
  version compatibility must be verified in the target OPNsense branch before
  declaring `PLUGIN_DEPENDS`.
- China Rules snapshots and their upstream data carry separate licenses and
  notices. Keep that data out of an initial upstream contribution unless the
  OPNsense maintainers approve the licensing and update arrangement.
- The project license is BSD 2-Clause. Third-party executables, data, and
  certificates retain their own licenses, documented in `THIRD_PARTY.md` and
  `data/china-rules/NOTICE.md`; the upstream patch must preserve these
  distinctions.

## Work before opening the PR

1. Open an issue in `opnsense/plugins` describing the feature and proposed
   scope; wait for maintainer feedback before preparing the upstream patch.
2. Fork and update a clean clone of `opnsense/plugins` to its current master.
   Start with the maintainers' agreed minimal feature set; the current product
   contains a broad feature set and should not be submitted as one unreviewed
   initial code drop.
3. Add the agreed category directory (likely `net/blank-vpn`) with a
   `Makefile` using `PLUGIN_NAME`, `PLUGIN_VERSION`, `PLUGIN_COMMENT`,
   `PLUGIN_MAINTAINER`, `PLUGIN_WWW`, `PLUGIN_LICENSE=BSD2CLAUSE`, and the
   supported package dependencies, plus a concise `pkg-descr`.
4. Build the plugin through the upstream `plugins.mk` targets (`check`,
   `manifest`, `plist`, `package`) on the supported OPNsense build environment.
   Check install, upgrade, removal, MVC registration, configd permissions,
   package dependencies, and all supported architectures.
5. Remove the Blank-hosted core downloader from the upstream build, or agree
   with OPNsense maintainers on a package-based design. Do not bundle or
   download prebuilt service binaries as a way around the ports requirement.
6. Scope third-party rule datasets, certificates, and update jobs separately;
   retain source attribution, licenses, checksums, and reproducible update
   behavior for anything proposed upstream.
7. Add the required AI disclosure to the issue/PR text: AI assistance was
   provided by OpenAI Codex (GPT-6 model family); the project maintainer must
   review and accept responsibility for the submitted code.
8. Include a concise manual test matrix and package build results in the PR.

## Draft issue text

**Title:** `Blank VPN & Proxy: discuss a community plugin for policy-based VPN and proxy routing`

**Problem:** OPNsense users who need VPN or proxy egress for selected LAN
devices, the whole LAN, or domain-based traffic currently have to assemble
multiple services and firewall rules themselves. That is difficult to operate
and verify safely.

**Proposal:** Discuss whether a community plugin is appropriate and what scope
OPNsense maintainers would accept for an initial contribution. The project
provides a WebGUI for policy-based VPN/proxy routing, device selection,
failover, and DNS/firewall integration. The standalone project is maintained at
`https://github.com/BlankNetworks/OPNSenseBlankVPN`.

The initial submission would follow the upstream plugin build framework, use
only supported package dependencies, omit bundled binaries and separately
licensed China Rules data, and target the current supported OPNsense branch.
We will split or reduce functionality according to maintainer feedback.

**Maintenance:** The project maintainer is prepared to maintain the plugin,
respond to issues, and test it against supported OPNsense changes. AI
assistance disclosure: OpenAI Codex (GPT-6 model family) was used during
development; the maintainer will review and take responsibility for the patch.

## Submission blockers

- The upstream issue and maintainer feedback are still required.
- The agreed initial feature scope is not yet defined.
- Package names and OPNsense repository availability for every core dependency
  are not yet confirmed against the target branch.
- The source has not yet been staged in an upstream category directory and
  built with `opnsense/plugins`'s `plugins.mk` workflow.
- The user/maintainer must confirm the ongoing support commitment and final AI
  disclosure wording before posting externally.
