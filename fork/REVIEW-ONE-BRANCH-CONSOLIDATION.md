# Consolidation of three older additive groups

Destination: feature/obfs-sip003-quic-additive-20261018
Target parent SHA: 47297edddf7c1b6aa452a41108173afa8bbfea95
Source branch: feature/tcp-mkcp-additive-review-20261017
Source HEAD: a93369505b10bbc9d767766c42aa921f526a56cc
Features from old commits: a20016e8bdd13b317877ce070877e863f9ab04ce, 2025be6f8ca85ff39f8e9669ab9ea5a5966209d1, a93369505b10bbc9d767766c42aa921f526a56cc.

Moved:
1. Bounded XHTTP independent download session/uplink controls.
2. Strict {version:1,nodes:[...]} JSON subscription envelope.
3. Trusted local-app-owned XDrive profile selection for four protocols.

The existing current code in infra/conf/node_xhttp_download.go and infra/conf/serial/node_list_json.go was kept, adding only the two old branches' opt-in feature deltas. A whitespace-normalized structural equality check against the old feature versions passed for both files after inserting new sections. Eight added implementation, test and review files were carried over verbatim. No files from the author's integrated Shadowsocks, SIP003 or QUIC changes were modified here.

Evidence: CODE_VERIFIED from GitHub refs; full Xray Go 1.27.x build/race/CI and real peer tests remain NOT_VERIFIED. The original branch and the old feature branch were not moved or deleted. This is review consolidation only, not a release or merge into the owner's original branch.
