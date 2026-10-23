# Security and privacy

PocketLatch exchanges encrypted messages locally over Bluetooth. It does not collect a Windows password, use analytics, or require a cloud account. Phone keys live in Android Keystore-protected storage or iOS Keychain. The Windows relay carries encrypted messages and does not persist phone signing keys. Local diagnostic logs contain event/status metadata, not pairing secrets.

Pair only by scanning a QR displayed on your own PC or entering its manual code. Every enrollment requires phone authentication and Windows Hello. Unlock proof uses fresh challenges and a device-bound, short-lived, single-use approval. A Bluetooth connection alone is not approval unless you explicitly enable automatic approval without biometrics.

The automatic-approval/no-biometrics combination intentionally lets a paired PC unlock when the phone is reachable. It is not a distance or presence guarantee. Keep it disabled if you need to review each request.

This initial preview has not had an independent security audit. The legacy Windows CDF API and VBS-protected Windows Hello impose compatibility limits. Keep your Windows PIN and existing security protections.

Report vulnerabilities privately through GitHub's security-advisory reporting if enabled. Do not include real keys, pairing codes, or PINs in issues. Public issues are appropriate for non-sensitive compatibility problems.
