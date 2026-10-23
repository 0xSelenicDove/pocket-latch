# PocketLatch

Approve a Windows sign-in from your phone over Bluetooth. No account or cloud service.

**First public preview — compatibility is limited.** PocketLatch uses the legacy Windows Hello Companion Device Framework. Microsoft [deprecated this API in Windows 10 version 2004](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-companion-device-framework). A Windows version number alone does not guarantee that it works. Run the app's PC checks before pairing. VBS-protected Windows Hello was incompatible in development testing; PocketLatch does not change those protections or machine policy.

[Download releases](https://github.com/0xSelenicDove/pocket-latch/releases) · [Install and pair](INSTALL.md) · [Security and privacy](SECURITY.md)

## What it does

- Pair by scanning a short-lived QR code, or use a manual code.
- Approve or deny a sign-in from a phone notification.
- Require biometrics/device authentication, or opt into automatic approval.
- Keep Windows Bluetooth available through a small background companion, even with the window closed.
- Keep your Windows PIN as the fallback.

The main screen shows pairing or the current request. Approval preferences and manual setup live in settings. There is no simulator, test-arming button, Wi-Fi listener, or Mac bridge in this distribution. Automated tests remain in the source tree.

## Requirements

| Platform | Requirements |
|---|---|
| Windows | x64 or ARM64 desktop, Windows Hello PIN, working CDF enrollment, policy allowing companion sign-in, BLE adapter/driver supporting peripheral mode. Minimum package OS: Windows 10 build 17763. |
| Android | Android 11+, Bluetooth LE, screen lock, Nearby devices and notification permissions. Android 11 also needs location permission for scanning. |
| iPhone | iOS 16+, Bluetooth, notifications, device passcode, and your own Apple signing setup. The IPA is **unsigned**, not a one-tap install or TestFlight build. |

Bluetooth transport has been exercised on phones and a Windows VM during development. This cleaned public build and the new persistent Windows host still need broader device testing. It is not a replacement for your normal Windows sign-in method.

## Approval settings

By default, each request needs approval and device authentication. With **automatic approval on and biometrics off**, your paired PC can unlock whenever the phone is reachable, including while it is locked. With both on, open the notification and authenticate. Enrollment always requires device authentication.

Keep the phone app in the background; do not force-stop it. Open it after a reboot. On iOS, unlock the phone once after restarting. Allow notifications in Focus/DND when using manual approval. Android battery management can interrupt the connection.

## Build

Windows builds run in [GitHub Actions](.github/workflows/package.yml) with Visual Studio UWP tools and Windows SDK 19041. Run `packaging/Build-Package.ps1` on a matching Windows build machine. The resulting installer bundles the Bluetooth host runtime.

Android: Java 17, Android SDK 35, then `cd Android && ./gradlew testDebugUnitTest lintRelease assembleRelease`. The local release APK is unsigned until signed with your own key. The release workflow uses repository signing secrets.

iOS: open `iPhone/CdfCompanion.xcodeproj`, select your signing team, and run on your device. Protocol checks: `swift test --package-path iPhone`. The [iOS workflow](.github/workflows/ios.yml) builds an unsigned device IPA without a provisioning profile.

The Windows `CdfProbe` and iOS `CdfCompanion` source project names are internal implementation names. Installed apps are named PocketLatch.

## License

MIT. Dependency notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
