# Go core

Current build, SDK, native TUN and component instructions: [GO-NATIVE-CORE.md](GO-NATIVE-CORE.md).

Historical acceptance reports describe the C++ main implementation.

Hysteria 2 uses the official MIT protocol components, core/v2 and extras/v2
2.13.0, and their pinned QUIC fork. Their source and licenses are preserved in
vendor; modifications carry original/replacement checksums. See
[HYSTERIA2.md](HYSTERIA2.md) for provenance, integration and acceptance limits.
This is protocol-library reuse inside the Go engine, with no separate proxy
process. Original project ownership does not extend to these upstream files.

WireGuard encrypted endpoints use the already pinned official MIT wireguard-go
module, with checksummed worker/queue/virtual-stack ownership changes. See
[WIREGUARD.md](WIREGUARD.md). Algorithm and protocol-library ownership remains
with WireGuard LLC and its contributors.

TUIC v5 uses the existing quic-go transport and a project-authored wire layer;
see [TUIC.md](TUIC.md). ShadowTLS v2/v3 follows the MIT ihciah design, with its
notice preserved in third_party and binary license snapshots; see
[SHADOWTLS.md](SHADOWTLS.md). Neither links or launches a separate proxy engine.
