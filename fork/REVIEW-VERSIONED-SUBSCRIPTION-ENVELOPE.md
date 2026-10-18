# Versioned JSON subscription envelope
Parent: a20016e8bdd13b317877ce070877e863f9ab04ce

New explicit subjson/node-list input accepts either the previous flat NodeDescription array or a strict object with exactly {version:1,nodes:[...]} including case-insensitive duplicate key rejection.
All nodes still pass the original ParseNodeJSON validator and the existing 128 node / 1 MiB bounds. Old URI/node/sub decoders are unchanged. No new remote protocols, arbitrary routing or local files.
Added four-protocol and rejection fixtures; full Go1.27.1/third-party tests NOT_VERIFIED.
