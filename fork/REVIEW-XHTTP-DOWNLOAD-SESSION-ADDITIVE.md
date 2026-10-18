# Bounded XHTTP download session metadata
Parent: ea89e85630f611c3a80ad198364b832150941d49

New opt-in independent download settings: uplinkHTTPMethod, sessionIDPlacement/sessionIDKey, seqPlacement/seqKey, uplinkDataPlacement/uplinkDataKey, and uplinkChunkSize.
Methods POST/GET only; placement and key naming validated; chunks 1024..262144. Existing native SplitHTTPConfig.Build provides final mode and transport semantics.
No generic headers/proxy overrides, local files, certificate bypass or recursive stream settings. Added four-protocol parity and negative regression tests. Full Go1.27.1 and independent wire tests NOT_VERIFIED.
