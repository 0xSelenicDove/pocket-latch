# PocketLatch

Unlock Windows and approve compatible Windows Hello requests from your phone over Bluetooth—without storing your Windows password. No account or cloud service.

**First public preview — compatibility is limited.** PocketLatch uses the legacy Windows Hello Companion Device Framework. Microsoft [deprecated this API in Windows 10 version 2004](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-companion-device-framework). A Windows version number alone does not guarantee that it works. Run the app's PC checks before pairing. VBS-protected Windows Hello was incompatible in development testing; PocketLatch does not change those protections or machine policy.

[Download releases](https://github.com/0xSelenicDove/pocket-latch/releases) · [Install and pair](INSTALL.md) · [Security and privacy](SECURITY.md)

## What it does

- Pair by scanning a short-lived QR code, or use a manual code.
- Approve or deny a sign-in from a phone notification.
- Require biometrics/device authentication, or opt into automatic approval.
- Keep Windows Bluetooth available through a small background companion, even with the window closed.
- Keep your Windows PIN as the fallback.

The main screen shows pairing or the current request. Approval preferences and manual setup live in settings. There is no simulator, test-arming button, Wi-Fi listener, or Mac bridge in this distribution. Automated tests remain in the source tree.

## Windows Hello support

CDF can participate in authentication beyond the lock screen on compatible Windows configurations. We have tested Windows unlock, app unlocking, Microsoft Store purchase authentication, and saving a passkey. Compatibility still depends on the Windows configuration and the application’s Windows Hello integration.

| Scenario | Test status |
|---|---|
| Windows unlock | Verified during development on compatible configurations. |
| App unlocking with Windows Hello | Tested successfully with a Windows Hello-enabled app. |
| Microsoft Store purchase authentication | Tested successfully. |
| Saving a passkey through Windows Hello | Tested successfully in a Windows VM running on a Mac. |
| UAC elevation | Not supported according to the linked GoTrust field report; not claimed by PocketLatch. |
| Other Windows Hello requests | Compatibility varies; additional apps and flows need testing. |

The passkey result covers approving the Windows Hello prompt when saving a passkey. Using that passkey for subsequent sign-ins has not yet been verified.

Microsoft's [CDF guide](https://learn.microsoft.com/en-us/windows/uwp/security/companion-device-unlock) still describes post-unlock authentication as future work. That wording does not capture the broader behavior observed above. A [GoTrust ID field report](https://blog.csdn.net/weixin_46583461/article/details/125708231) independently describes application and Store purchase authentication, excluding UAC; it is corroboration about GoTrust, not a PocketLatch compatibility certification.

Phone prompts distinguish Windows sign-in from general Windows Hello authentication when Windows supplies the scenario. Older clients and unknown scenarios receive generic authentication wording. CDF's [stage information](https://learn.microsoft.com/en-us/uwp/api/windows.security.authentication.identity.provider.secondaryauthenticationfactorauthenticationstageinfo) exposes the scenario but no requesting application name or purchase details. PocketLatch asks you to check the requesting app on the PC; it does not guess an app name from the foreground window.

## Similar projects

Comparison based on project documentation, not independent security audits:

| Project | Approach | Difference from PocketLatch |
|---|---|---|
| [PC Bio Unlock / PulseUnlock](https://github.com/MeisApps/pcbu-desktop) | Android approval over Bluetooth/network, multiple desktop platforms; PC password stored encrypted with its decryption key on the phone. | Broader desktop coverage. PocketLatch supports Android and iOS and authenticates through CDF without storing the Windows password. |
| [WinUnlock](https://github.com/imabd645/WinUnlock) | Android over Bluetooth RFCOMM, custom Windows credential provider and service; documents DPAPI-protected password storage. | PocketLatch uses BLE and Windows' companion authentication provider rather than a custom password-submitting provider. |
| [GoTrust ID](https://go-trust.com/gotrust-id/) | Current enterprise platform includes desktop login, SSO and MFA integrations. The older consumer app used CDF. | PocketLatch is a local MIT-licensed project without a service account. GoTrust's current enterprise coverage should not be attributed solely to CDF. |

PocketLatch's distinguishing combination is local Bluetooth, Android and iOS source, no stored Windows password, and compatible Windows Hello app authentication. Its main constraints are deprecated CDF compatibility, limited hardware testing, and iOS signing requirements.

## Requirements

| Platform | Requirements |
|---|---|
| Windows | x64 or ARM64 desktop, Windows Hello PIN, working CDF enrollment, policy allowing companion sign-in, BLE adapter/driver supporting peripheral mode. Minimum package OS: Windows 10 build 17763. |
| Android | Android 11+, Bluetooth LE, screen lock, Nearby devices and notification permissions. Android 11 also needs location permission for scanning. |
| iPhone | iOS 16+, Bluetooth, notifications, device passcode, and your own Apple signing setup. The IPA is **unsigned**, not a one-tap install or TestFlight build. |

Bluetooth transport has been exercised on phones and a Windows VM during development. This cleaned public build and the new persistent Windows host still need broader device testing. It is not a replacement for your normal Windows sign-in method.

## Approval settings

By default, each request needs approval and device authentication. With **automatic approval on and biometrics off**, your paired PC can unlock whenever the phone is reachable, including while it is locked. This also applies to compatible app authentication and purchase prompts; automatic approval does not distinguish their purpose. With both on, open the notification and authenticate. Enrollment always requires device authentication.

Keep the phone app in the background; do not force-stop it. Open it after a reboot. On iOS, unlock the phone once after restarting. Allow notifications in Focus/DND when using manual approval. Android battery management can interrupt the connection.

## Build

Windows builds run in [GitHub Actions](.github/workflows/package.yml) with Visual Studio UWP tools and Windows SDK 19041. Run `packaging/Build-Package.ps1` on a matching Windows build machine. The resulting installer bundles the Bluetooth host runtime.

Android: Java 17, Android SDK 35, then `cd Android && ./gradlew testDebugUnitTest lintRelease assembleRelease`. The local release APK is unsigned until signed with your own key. The release workflow uses repository signing secrets.

iOS: open `iPhone/CdfCompanion.xcodeproj`, select your signing team, and run on your device. Protocol checks: `swift test --package-path iPhone`. The [iOS workflow](.github/workflows/ios.yml) builds an unsigned device IPA without a provisioning profile.

The Windows `CdfProbe` and iOS `CdfCompanion` source project names are internal implementation names. Installed apps are named PocketLatch.

## License

MIT. Dependency notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
