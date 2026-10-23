# Install PocketLatch

Download assets from the [release page](https://github.com/0xSelenicDove/pocket-latch/releases). Compare their SHA-256 hashes with `SHA256SUMS.txt` if verifying a download.

## Windows

1. Choose the **Windows-x64** ZIP for Intel/AMD PCs, or **Windows-ARM64** for Windows on Arm.
2. Extract the ZIP completely, then run `Install.cmd`. The included installer may ask you to trust the included self-signed PocketLatch certificate and install runtime dependencies. Inspect `BUILD-INFO.txt` for the package hash, signing-certificate thumbprint, and expiration before trusting it. This is a community-signed preview, not a Microsoft Store package.
3. Open **PocketLatch**. Choose **Check PC & pair your phone**. The checks cover Bluetooth, Windows Hello, companion policy, and VBS/Hello protection. The app does not alter policy or disable security features. If the PC is incompatible, continue using your normal sign-in method.
4. Keep the pairing QR open while setting up the phone. Approve enrollment on the phone and complete Windows Hello when prompted.
5. Background access and phone unlock are enabled after successful enrollment. Open the app once after an update so its persistent Bluetooth companion can start. You can then close the window.

PocketLatch uses a distinct app identity from the development prototype. Pair it as a new app. Unpair or pause another companion app before testing so two apps do not compete for Bluetooth/sign-in requests.

For a VM, the guest needs a real Bluetooth adapter passed through exclusively and a compatible driver. A shared/emulated Bluetooth device may not support advertising. USB 2.0 passthrough helped in development testing, but is not a universal fix.

## Android

1. Transfer `PocketLatch-Android.apk` to the phone and open it. Android may ask you to allow installation from the app opening the APK; this release is not from Google Play.
2. Open PocketLatch and grant Bluetooth/Nearby devices and notification permissions. Allow camera access when scanning. Set a screen-lock PIN/password or biometric first.
3. Tap **Pair your PC**, scan Windows' QR, confirm it is your PC, and authenticate. Complete Windows Hello on the PC.
4. Keep the foreground Bluetooth service running. Its persistent notification is expected. Allow background activity if your device's battery manager stops the app.

Updates from this repository use a dedicated release key. Android will reject an APK signed by a different key with the same app ID.

## iPhone

`PocketLatch-iOS-unsigned.ipa` is a device build **without a signature or provisioning profile**. It cannot be installed directly by tapping it. No private signing identity or registered-device list is included.

The supported source-install route is:

1. On a Mac with Xcode, download this release's source and open `iPhone/CdfCompanion.xcodeproj`.
2. In Xcode Settings → Apple Accounts, add your own Apple account. Select the CdfCompanion target → Signing & Capabilities, choose your team, and enable automatic signing. Use a bundle identifier unique to your team if required.
3. Connect/unlock the iPhone, select it as the run destination, enable Developer Mode if requested, and run the app. Follow Apple's device trust prompts. Personal-team signing has restrictions and may require periodic rebuilding.
4. Allow Bluetooth, camera and notifications. Scan Windows' pairing QR, confirm, and complete device authentication plus Windows Hello.

See Apple's [device build instructions](https://developer.apple.com/documentation/Xcode/running-your-app-on-simulated-or-physical-devices). If using the unsigned IPA with your own signing/distribution tools, supply a valid matching profile, bundle identifier and capabilities; this project does not provide a signing service.

## Everyday use

Lock Windows, open the sign-in screen, and approve the phone notification. Leave the phone app in the background. With Focus/DND, allow PocketLatch alerts. Biometrics and automatic approval are optional settings; automatic approval without biometrics permits silent unlock while the phone is locked.

If a request is denied, expires, or the phone is unavailable, use your Windows PIN. Repeated prompts for that sign-in are suppressed. Windows → Settings → Unpair removes enrollment. Keep diagnostic reports private if they contain device-specific details; never share pairing codes or PINs.
