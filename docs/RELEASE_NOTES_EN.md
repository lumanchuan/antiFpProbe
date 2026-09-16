# Release and Provenance Notes

English | [简体中文](发布说明.md)

## License scope

As selected by the authors, author-owned code and the deployment scripts and documentation added for this release use Apache-2.0. The complete text is in the root `LICENSE` file. The author line currently says OSDisguise contributors and can be updated with the official authors, institution, and contact information before publication. A root Apache license does not relicense third-party content; see `NOTICE`.

## Shared helper header

At the author's request, the complete reproducibility handoff retains `common/util.p4` without removing or rewriting its vendor notice. A comparison with the local SDE 9.7.0 `tna_counter/common/util.p4` found only line-formatting differences in the `TofinoIngressParser` declaration. The author states that the notice was pasted by mistake, but redistribution rights should still be confirmed before public release.

Do not mark this file as Apache-2.0 automatically. The conservative source exporter excludes it by default. A user can copy the matching helper from a legally obtained SDE into `common/util.p4` before building. This project consulted `tna_counter/tna_counter.p4` and its shared helpers but does not distribute the vendor's SDK source tree or binaries.

## Fingerprints and third-party assets

- `HTML/profiles/`, `HTML/profiles_p0f/`, `test_nmap/fps.json`, the `test_p0f` examples, and `HTML/validation/catalog/candidates.json` contain existing experiment records and candidates. Names, fields, and candidate metadata are retained, but their presence does not claim that every record has passed an end-to-end hardware test.
- Nmap fingerprint data is subject to the terms associated with its data files. Use the LICENSE/COPYING file from the actual Nmap/database version used, rather than assuming that the newest license applies to an older database. See [Nmap Legal Notices](https://nmap.org/book/man-legal.html) and the [Nmap Public Source License](https://nmap.org/npsl/).
- p0f signatures likewise require verification against the source distribution and database used. See the [official p0f page](https://lcamtuf.coredump.cx/p0f3/).
- `HTML/static/vendor/lucide.min.js` retains its ISC notice. The publisher should confirm rights to the bitmap under `HTML/static/images/`.
- Flask and other Python dependencies are installed from `requirements.txt`; vendored packages and wheel caches from the development tree are not included as project source.

## What this release changed

The release preserves the original P4 and fingerprint algorithms, separates build outputs, brings the monitoring-forwarding source into the project, replaces installation-specific absolute paths with relative project paths and a local deployment configuration, adds initialization, read-only diagnostics, checked manual launchers, web process management, and Chinese/English documentation, and removes previous tokens, databases, old builds, backups, and packet captures. `docs/source-hashes.json` records SHA-256 hashes for the initially selected source files; an export manifest can verify the migrated release.

The operating procedures were based on the author's OSDisguise Notion experiment notes and corrected to match the actual paths and launch code. Access tokens, private image URLs, and personal credentials from those notes were not copied.

## Export and publication checks

The complete local handoff is intended for reproduction in an authorized lab. Before publishing, use the conservative exporter and finish the provenance review:

```bash
/usr/bin/python3 scripts/export_source.py --output /tmp/OSDisguise-source.tar.gz
```

The default export excludes runtime state, private deployment configuration, the SDK helper, and fingerprint JSON/artwork whose redistribution has not been confirmed. `PUBLIC_SETUP.md` in the archive lists files that users must supply. The conservative archive is therefore not an all-database, zero-setup package.

After the publisher confirms the relevant rights, `--include-profiles`, `--include-sdk-helper`, and `--include-artwork` can include those materials. Selecting an option records the publisher's packaging decision; it is not a legal review. Runtime credentials and historical state are always excluded.

Before release, verify license scope, profile and artwork provenance, absence of tokens/SSH keys/real packet captures, successful source builds, complete hardware prerequisites in the README, and clear separation between candidate and end-to-end validated profiles.

The preparation process itself did not publish credentials, expose the testbed to the Internet, or install a system service. The GitHub publication records the source snapshot, not a production deployment.
