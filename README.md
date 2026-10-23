# PocketLatch

Unlock Windows with your phone.

PocketLatch lets you approve Windows sign-in and Windows Hello prompts from your Android phone or iPhone, over Bluetooth. Tap approve, confirm with Face ID, fingerprint, or your phone's screen lock — and you're in.

It never stores your Windows password, and there's no account to create and no cloud service in the middle. Everything stays between your phone and your PC. Your Windows PIN still works as a backup, just like before.

[Download the latest release](https://github.com/0xSelenicDove/pocket-latch/releases) · [Install and pair](INSTALL.md) · [Security and privacy](SECURITY.md)

> **This is a first public preview, so please read this part:** PocketLatch is built on Microsoft's older Windows Hello Companion Device Framework (CDF). Microsoft [deprecated that framework in Windows 10 version 2004](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-companion-device-framework), which means it works on some PCs and not others — and a Windows version number alone won't tell you which. Run the PC checks in the app before you pair. If your PC uses VBS-protected Windows Hello, it won't work — that combination was incompatible in our testing. PocketLatch won't try to change those protections or your PC's policies to force it.

## How it works

1. **Install PocketLatch on your PC and your phone.**
2. **Pair them once** by scanning the QR code shown on your PC (there's a manual code too, if you prefer).
3. **Next time Windows asks, your phone buzzes.** Approve or deny it from the notification.

That's the everyday experience. A small companion app keeps Bluetooth available on Windows in the background, so you can close the PocketLatch window and forget about it.

By default, every request needs your approval and your phone's authentication. You can change that in settings — more on that below, because the trade-off matters.

## More than just unlocking

On PCs where CDF works, Windows Hello isn't only for the lock screen. In our testing, PocketLatch also handled:

| What we tried | How it went |
|---|---|
| Unlocking Windows | Works on compatible PCs |
| Unlocking an app that uses Windows Hello | Worked |
| Approving a Microsoft Store purchase | Worked |
| Saving a passkey with Windows Hello | Worked — tested in a Windows VM on a Mac |
| UAC elevation prompts | Not supported |
| Other Windows Hello prompts | It depends on the app and your Windows setup — more testing needed |

Two honest caveats: saving a passkey worked, but signing back in later with that same passkey hasn't been verified yet. And when a prompt comes in, PocketLatch can usually tell a Windows sign-in apart from a general Hello request, but Windows doesn't tell it which app is asking or what you're buying. So glance at your PC screen before you approve — PocketLatch won't guess for you.

## Will it work on my PC?

Maybe — and the app will tell you quickly. You'll need:

**Windows**
- A 64-bit or ARM64 PC with a Windows Hello PIN set up
- Bluetooth LE that supports peripheral mode (some adapters and drivers don't)
- Windows settings/policy that allow companion-device sign-in
- Minimum: Windows 10 build 17763

**Android**
- Android 11 or newer, with a screen lock set
- Bluetooth LE, plus Nearby devices and notification permissions
- On Android 11, you'll also need to allow location permission for Bluetooth scanning

**iPhone**
- iOS 16 or newer, with a passcode set
- Bluetooth and notification permissions
- Your own Apple signing setup in Xcode — the iOS download is an **unsigned** IPA, so it's not a tap-to-install or TestFlight build

Bluetooth was tested on real phones and a Windows VM during development, but this public build — and its new always-on Windows companion — still need testing on a wider range of hardware. Think of PocketLatch as an extra way in, not a replacement for your usual one.

Full step-by-step setup is in [INSTALL.md](INSTALL.md).

## Before you turn on automatic approval

Settings give you two switches: automatic approval, and requiring biometrics/device authentication.

If you turn **automatic approval on and authentication off**, your PC can unlock whenever your phone is simply nearby and reachable — even if the phone itself is locked. That also applies to app and purchase prompts, not just sign-in, and PocketLatch can't tell them apart in that mode.

Some people will love that convenience. Just turn it on knowing exactly what it does. Leaving it off is the safer default.

A few habits help either way:

- Keep the phone app running in the background. Don't force-stop it, and open it once after a reboot. On iPhone, unlock your phone once after restarting it too.
- Allow PocketLatch notifications through Focus / Do Not Disturb if you approve requests manually.
- If Android's battery management keeps putting the app to sleep, exempt PocketLatch from it — otherwise the connection can drop.

## How it compares

There are other good projects in this space. The short version of how PocketLatch differs — based on each project's own documentation, not independent audits:

- **[PC Bio Unlock / PulseUnlock](https://github.com/MeisApps/pcbu-desktop)** covers more desktop platforms and works over Bluetooth or network. It stores your PC password (encrypted, with the key on your phone). PocketLatch doesn't store your Windows password at all, and works with both Android and iOS.
- **[WinUnlock](https://github.com/imabd645/WinUnlock)** is Android-only over Bluetooth, with its own custom Windows credential provider and DPAPI-protected password storage. PocketLatch uses BLE and Windows' built-in companion authentication instead of a custom password-submitting provider.
- **[GoTrust ID](https://go-trust.com/gotrust-id/)** is an enterprise platform today — desktop login, SSO, and MFA, with an account behind it. The older consumer app used CDF, like PocketLatch does. PocketLatch is a small, local, MIT-licensed project with no service account.

So PocketLatch's niche is pretty specific: local Bluetooth only, Android *and* iOS, no stored Windows password, and — where your PC supports it — Hello prompts beyond the lock screen. Its limits are just as specific: a deprecated Windows framework, limited hardware testing so far, and extra signing steps on iOS.

## Building from source

**Windows:** Builds run in [GitHub Actions](.github/workflows/package.yml). To build locally, you'll need a Windows machine with Visual Studio's UWP tools and Windows SDK 19041, then run `packaging/Build-Package.ps1`. The installer bundles the Bluetooth host runtime.

**Android:** You'll need Java 17 and Android SDK 35.

```sh
cd Android && ./gradlew testDebugUnitTest lintRelease assembleRelease
```

A local build is unsigned until you sign it with your own key. The release workflow signs with the repository's signing secrets.

**iOS:** Open `iPhone/CdfCompanion.xcodeproj` in Xcode, pick your own signing team, and run it on your device. To run the protocol checks: `swift test --package-path iPhone`. The [iOS workflow](.github/workflows/ios.yml) builds an unsigned IPA, with no provisioning profile.

One bit of housekeeping if you're poking around the code: the Windows project is still called `CdfProbe` and the iOS project `CdfCompanion` internally. The installed app is PocketLatch on both.

## License

MIT. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for dependency notices.
