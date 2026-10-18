# Explicit trusted XDrive profile selection, separate from untrusted node import
Parent: 2025be6f8ca85ff39f8e9669ab9ea5a5966209d1

This is an opt-in application API, not general URI support. A four-protocol node requests type=xdrive but supplies only its normal protocol credentials/metadata. ParseNodeURIWithTrustedXDrive and ResolveNodeWithTrustedXDrive require a local application-owned XDriveConfig argument that supplies backend, folder and secrets. Ordinary ParseNodeURI and ParseNodeJSON continue to reject XDrive.
Only the existing local and Google Drive backends are admitted. The approved profile is cloned; unknown templates/local file/service/secret keys in a link are rejected. The four-protocol native Outbound/StreamConfig Build path still selects the existing XDrive engine, no new wire transport or process spawning.
This provides an explicit trust boundary for app-integrated XDrive; it is not automatic use of XDrive from subscriptions. Four-protocol parity, untrusted-default rejection and key isolation tests were authored. Full Go1.27.1 build and real backend tests NOT_VERIFIED.
