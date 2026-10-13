# Go core

Current build, SDK, native TUN and component instructions: [GO-NATIVE-CORE.md](GO-NATIVE-CORE.md).

Historical acceptance reports describe the C++ main implementation.

Hysteria 2 uses the official MIT protocol components, core/v2 and extras/v2
2.13.0, and their pinned QUIC fork. Their source and licenses are preserved in
vendor; modifications carry original/replacement checksums. See
[HYSTERIA2.md](HYSTERIA2.md) for provenance, integration and acceptance limits.
This is protocol-library reuse inside the Go engine, with no separate proxy
process. Original project ownership does not extend to these upstream files.
