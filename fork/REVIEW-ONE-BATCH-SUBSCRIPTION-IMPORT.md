# Explicit four-protocol text/Base64 node subscriptions

Source branch feature/tcp-mkcp-additive-review-20261017; parent 65d3df9b6f7b829e42f7fd42f42c0032085f2f3f.

New opt-in reader formats `sub` and `subscription` accept a line-delimited list of URI nodes, or a strict Base64 encoding of that complete list. No implicit change to the existing single-node `uri` or `node` formats and no network fetch. Only the retained VLESS, VMess, Trojan and Shadowsocks schemes pass through the unchanged `conf.ParseNodeURI` path. Every profile is individually bounded, the complete list is limited to 1 MiB and 128 nodes, and all-or-nothing rejection prevents skipping malformed or fifth-protocol links. Generated deterministic unique outbound tags prevent duplicate labels. Private URI contents and credentials are not included in errors.

The feature is registered with `ReaderDecoderByFormat`, so it is available through explicit format selection; filename auto-detection was not changed. The resulting outbound entries are ordinary Xray configurations; it does not automatically choose an active node, invent routing policies, fetch URLs or subscribe on a schedule.

Repository tests were authored for four-protocol plain and Base64 inputs, original .uri default preservation, strict rejection and redacted errors; complete Go1.27.1 build and actual routing/connection acceptance are NOT_VERIFIED. This is a bounded reader for one common subscription dialect, **not** a claim that all external subscription formats are supported.
