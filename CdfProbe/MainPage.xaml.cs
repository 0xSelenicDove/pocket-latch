using System;
using System.Linq;
using System.Threading;
using System.Net;
using Windows.Data.Json;
using System.Threading.Tasks;
using CdfProbe.Shared;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Background;
using Windows.Foundation.Metadata;
using Windows.Security.Authentication.Identity.Provider;
using Windows.Security.Cryptography;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System.Profile;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace CdfProbe
{
    public sealed partial class MainPage : Page
    {
        private string PairingHost => NativeBleTransport.Endpoint;
        private bool phoneRegistered;
        private bool pairingChecked;
        private bool pairingUnavailable;
        private bool hasPairingSetup;
        private readonly DispatcherTimer statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };

        public MainPage()
        {
            InitializeComponent();
            statusTimer.Tick += (s, e) => RefreshStatus();
            Loaded += async (s, e) => { statusTimer.Start(); await RunAsync("Background setup", async () => {
                await RefreshPairingAsync();
                if (phoneRegistered) {
                    await EnableBackgroundAsync();
                    if (ProbeState.PhoneHost == NativeBleTransport.Endpoint)
                        await BluetoothRelay.StartAsync(System.Threading.CancellationToken.None);
                }
            }); };
            Unloaded += (s, e) => statusTimer.Stop();
            ProbeState.Disarm();
            var version = Package.Current.Id.Version;
            ProbeState.Write($"App {version.Major}.{version.Minor}.{version.Build}.{version.Revision} opened; manual attempt disarmed.");
            Refresh();
        }

        private void RefreshStatus()
        {
            ConnectionStatus.Text = "Bluetooth stays available between sign-ins. Keep PocketLatch running in the background on your phone.";
            var access = BackgroundExecutionManager.GetAccessStatus();
            var backgroundEnabled =
                (access == BackgroundAccessStatus.AlwaysAllowed || access == BackgroundAccessStatus.AllowedSubjectToSystemPolicy) &&
                BackgroundTaskRegistration.AllTasks.Values.Any(t => t.Name == ProbeState.TaskName);
            bool automatic = ProbeState.AutomaticUnlock != null;
            SetupBackgroundButton.Visibility = phoneRegistered && !backgroundEnabled ? Visibility.Visible : Visibility.Collapsed;
            AutomaticUnlockButton.Visibility = phoneRegistered && (backgroundEnabled || automatic) ? Visibility.Visible : Visibility.Collapsed;
            AutomaticUnlockButton.Content = automatic ? "Pause phone unlock" : "Enable phone unlock";
            UnlockHeading.Text = !pairingChecked ? "Checking setup…" : !phoneRegistered ? "Pair your phone to get started"
                : !backgroundEnabled ? "Finish setting up" : automatic ? "Phone unlock is on" : "Phone unlock is paused";
            Status.Text = !pairingChecked ? "Checking your Windows pairing."
                : !phoneRegistered ? "Connect your phone to approve Windows sign-ins. Manage an existing or incomplete pairing in Settings."
                : !backgroundEnabled ? "Allow background access so your phone can receive sign-in requests."
                : automatic ? "Lock your PC, then approve the sign-in notification on your phone. You can close this window."
                : "Enable phone unlock when you’re ready. Your Windows PIN remains available.";
            if (pairingUnavailable)
            {
                UnlockHeading.Text = "Setup needs attention";
                Status.Text = "Could not check your pairing. Open Support and choose Check compatibility to retry.";
            }
            else if (pairingChecked && !phoneRegistered && hasPairingSetup)
            {
                UnlockHeading.Text = "Review your pairing";
                Status.Text = "Open Settings to remove the existing setup, then pair your phone again.";
            }

        }

        private void Refresh()
        {
            RefreshStatus();
            Log.Text = ProbeState.Report();
        }

        private async Task RunAsync(string name, Func<Task> action)
        {
            if (!IsEnabled) return;
            IsEnabled = false;
            ActionError.Visibility = Visibility.Collapsed;
            try { await action(); }
            catch (Exception error)
            {
                ProbeState.Error(name, error);
                ActionError.Text = name + " failed: " + error.Message + " (0x" + error.HResult.ToString("X8") + ")";
                ActionError.Visibility = Visibility.Visible;
            }
            finally
            {
                await RefreshPairingAsync();
                IsEnabled = true;
                Refresh();
            }
        }

        private async Task RefreshPairingAsync()
        {
            phoneRegistered = false;
            pairingChecked = false;
            pairingUnavailable = false;
            PairControls.Visibility = UnpairButton.Visibility = Visibility.Collapsed;
            try
            {
                var devices = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(
                    SecondaryAuthenticationFactorDeviceFindScope.User);
                var registered = devices.Any(d => d.DeviceId == ProbeState.DeviceId);
                phoneRegistered = registered && ProbeState.PhoneMode;
                pairingChecked = true;
                // Only clear local setup after Windows confirms there is no enrollment.
                // A completed enrollment survives later background-access failures.
                if (!registered && (ProbeState.DeviceId != null || ProbeState.PhoneMode))
                {
                    foreach (var task in BackgroundTaskRegistration.AllTasks.Values.Where(t => t.Name == ProbeState.TaskName).ToArray())
                        task.Unregister(true);
                    ProbeState.ClearDevice();
                    ProbeState.Write("Incomplete pairing cleared. Pair your phone again to retry.");
                    if (ActionError.Visibility != Visibility.Visible)
                    {
                        ActionError.Text = "The previous pairing did not finish and has been cleared. Pair your phone again.";
                        ActionError.Visibility = Visibility.Visible;
                    }
                }
                var hasSetup = registered || ProbeState.DeviceId != null || ProbeState.PhoneMode;
                hasPairingSetup = hasSetup;
                PairingStatus.Text = registered
                    ? "Phone paired with this Windows account."
                    : hasSetup ? "Pairing is incomplete. Unpair to clear it before trying again." : "No companion paired.";
                PairControls.Visibility = hasSetup ? Visibility.Collapsed : Visibility.Visible;
                UnpairButton.Visibility = hasSetup ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception error)
            {
                pairingUnavailable = true;
                PairingStatus.Text = "Could not check pairing. Open Support and choose Check compatibility to retry.";
                ProbeState.Error("Pairing status", error);
            }
        }

        private async void Check_Click(object sender, RoutedEventArgs e)
        {
            await RunAsync("Environment", async () =>
            {
                var version = ulong.Parse(AnalyticsInfo.VersionInfo.DeviceFamilyVersion);
                ProbeState.Write("OS=" + ((version >> 48) & 65535) + "." + ((version >> 32) & 65535) + "." +
                    ((version >> 16) & 65535) + "." + (version & 65535) +
                    "; family=" + AnalyticsInfo.VersionInfo.DeviceFamily + "; architecture=" + Package.Current.Id.Architecture);
                foreach (var type in new[] {
                    "Windows.Security.Authentication.Identity.Provider.SecondaryAuthenticationFactorRegistration",
                    "Windows.Security.Authentication.Identity.Provider.SecondaryAuthenticationFactorAuthentication",
                    "Windows.ApplicationModel.Background.SecondaryAuthenticationFactorAuthenticationTrigger" })
                    ProbeState.Write(type + " present=" + ApiInformation.IsTypePresent(type));
                ProbeState.Write("Native Bluetooth: " + (await NativeBleTransport.CheckAdapterAsync() ?? "Peripheral role supported; radio on."));
                ProbeState.Write("Background access=" + BackgroundExecutionManager.GetAccessStatus());
                ProbeState.Write("Probe background task registered=" + BackgroundTaskRegistration.AllTasks.Values.Any(t => t.Name == ProbeState.TaskName));
                var devices = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(
                    SecondaryAuthenticationFactorDeviceFindScope.User);
                ProbeState.Write("CDF enumeration succeeded; this probe registered=" + devices.Any(d => d.DeviceId == ProbeState.DeviceId));
            });
        }

        private async Task<JsonObject> ReadMachineChecksAsync()
        {
            var folder = ApplicationData.Current.LocalFolder;
            var id = Guid.NewGuid().ToString();
            var request = await folder.CreateFileAsync("setup-request.txt", CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteTextAsync(request, id);
            await FullTrustProcessLauncher.LaunchFullTrustProcessForCurrentAppAsync();
            for (int i = 0; i < 100; i++)
            {
                try {
                    var file = await folder.GetFileAsync("setup-result.json");
                    var result = JsonObject.Parse(await FileIO.ReadTextAsync(file));
                    if (result.GetNamedString("request", "") == id) return result;
                } catch (Exception) { /* The helper may still be writing. */ }
                await Task.Delay(100);
            }
            throw new TimeoutException("The read-only Windows setup check did not respond. Close and retry.");
        }

        private async Task<bool> CheckBeforePairingAsync()
        {
            var rows = new StackPanel { Spacing = 16 };
            var heading = new TextBlock { Text = "A quick check before you pair", FontSize = 24,
                FontWeight = Windows.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
            rows.Children.Add(heading);
            rows.Children.Add(new TextBlock { Text = "After pairing, background access and phone unlock will be enabled. Each sign-in requires your phone’s approval. You can pause it anytime.",
                TextWrapping = TextWrapping.Wrap });
            var dialog = new ContentDialog { Title = "Set up phone unlock",
                Content = new ScrollViewer { Content = rows, MaxHeight = 460 },
                PrimaryButtonText = "Continue & enable phone unlock", CloseButtonText = "Cancel", IsPrimaryButtonEnabled = false };
            var bluetooth = new TextBlock { Text = "Checking…", TextWrapping = TextWrapping.Wrap };
            var pin = new TextBlock { Text = "Checking…", TextWrapping = TextWrapping.Wrap };
            var policy = new TextBlock { Text = "Checking…", TextWrapping = TextWrapping.Wrap };
            var protection = new TextBlock { Text = "Checking…", TextWrapping = TextWrapping.Wrap };
            foreach (var row in new[] {
                new { Title = "01   Bluetooth LE", Body = bluetooth },
                new { Title = "02   Windows Hello PIN", Body = pin },
                new { Title = "03   Companion sign-in policy", Body = policy },
                new { Title = "04   VBS / Windows Hello protection", Body = protection } })
            {
                rows.Children.Add(new Border { Padding = new Thickness(16), CornerRadius = new CornerRadius(8),
                    Background = (Windows.UI.Xaml.Media.Brush)Application.Current.Resources["SystemControlBackgroundBaseLowBrush"],
                    Child = new StackPanel { Spacing = 6, Children = {
                        new TextBlock { Text = row.Title, FontWeight = Windows.UI.Text.FontWeights.SemiBold }, row.Body } } });
            }
            dialog.Opened += async (sender, args) => {
                try {
                    var bleError = await NativeBleTransport.CheckAdapterAsync();
                    bluetooth.Text = bleError ?? "Ready — Bluetooth peripheral mode is supported.";
                    var hello = await Windows.Security.Credentials.UI.UserConsentVerifier.CheckAvailabilityAsync();
                    bool helloReady = hello == Windows.Security.Credentials.UI.UserConsentVerifierAvailability.Available;
                    pin.Text = helloReady ? "Windows Hello is available. Windows will confirm your PIN during enrollment."
                        : "Needs attention — " + hello + ". Set up a Windows Hello PIN in Settings → Accounts → Sign-in options, then retry.";
                    var machine = await ReadMachineChecksAsync();
                    bool policyRead = machine.GetNamedBoolean("policyRead", false);
                    uint? allowed = null;
                    foreach (var name in new[] { "policy", "mdmPolicy" }) {
                        if (machine.ContainsKey(name) && machine[name].ValueType == JsonValueType.Number) {
                            var value = (uint)machine[name].GetNumber();
                            if (value == 0 || allowed != 0) allowed = value;
                        }
                    }
                    policy.Text = policyRead ? SetupChecks.PolicyText(allowed)
                        : "Could not read policy: " + machine.GetNamedString("policyError", "Unknown error");
                    protection.Text = machine.ContainsKey("vbs")
                        ? SetupChecks.ProtectionText(machine.GetNamedNumber("vbs") == 2)
                        : "Could not verify VBS: " + machine.GetNamedString("vbsError", "No Device Guard result.");
                    if (machine.ContainsKey("helloProtection") && machine["helloProtection"].ValueType == JsonValueType.Number
                        && machine["helloProtection"].GetNumber() == 1)
                        protection.Text += " Protected Windows Hello is configured; companion sign-in may be unavailable.";
                    dialog.IsPrimaryButtonEnabled = bleError == null && helloReady && policyRead && allowed != 0;
                    heading.Text = dialog.IsPrimaryButtonEnabled ? "Ready to continue — review the checks" : "Resolve these checks, then try again";
                    ProbeState.Write("Setup checks: BLE=" + (bleError ?? "ready/bridge") + "; Hello=" + hello + "; machine=" + machine.Stringify());
                } catch (Exception error) {
                    heading.Text = "Could not finish setup checks. Close and retry.";
                    ProbeState.Error("Setup checks", error);
                }
            };
            return await dialog.ShowAsync() == ContentDialogResult.Primary;
        }

        private async void QrPair_Click(object sender, RoutedEventArgs e)
        {
            await RunAsync("QR pairing", async () =>
            {
                if (ProbeState.DeviceId != null)
                    throw new InvalidOperationException("Remove the existing registration before pairing.");
                if (!await CheckBeforePairingAsync()) return;
                var host = PairingHost;
                var secret = ProbeState.Bytes(CryptographicBuffer.GenerateRandom(32));
                var device = Guid.NewGuid().ToString("N");
                var expiry = DateTimeOffset.UtcNow.AddMinutes(2);
                var payload = new JsonObject {
                    ["version"] = JsonValue.CreateNumberValue(1),
                    ["transport"] = JsonValue.CreateStringValue(host == NativeBleTransport.Endpoint ? "windows-ble" : "mac-ble"),
                    ["deviceId"] = JsonValue.CreateStringValue(device),
                    ["secret"] = JsonValue.CreateStringValue(Convert.ToBase64String(secret)),
                    ["expires"] = JsonValue.CreateNumberValue(expiry.ToUnixTimeSeconds())
                };
                var picture = new Image { Width = 300, Height = 300 };
                var countdown = new TextBlock { Text = "Expires in 2:00", FontWeight = Windows.UI.Text.FontWeights.SemiBold };
                var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                var detected = false;
                bool manual = false;
                var detection = Task.CompletedTask;
                using (var bluetooth = await NativeBleTransport.OpenAsync(host, CancellationToken.None))
                using (var cancellation = new CancellationTokenSource())
                {
                    var dialog = new ContentDialog {
                        Title = "Scan in PocketLatch",
                        Content = new StackPanel { Spacing = 12, Children = { picture, countdown,
                            new TextBlock { Text = "Scan and confirm on your phone. Windows will detect it and continue automatically once Bluetooth connects. This code expires in two minutes.", TextWrapping = TextWrapping.Wrap } } },
                        PrimaryButtonText = "Use a manual code instead",
                        CloseButtonText = "Cancel"
                    };
                    dialog.Opened += (s, args) => {
                        detection = DetectScannedPhoneAsync(device, secret, expiry, host, bluetooth, cancellation.Token, () => {
                            detected = true;
                            dialog.Hide();
                        });
                    };
                    dialog.Closing += (s, args) => cancellation.Cancel();
                    timer.Tick += (s, args) => {
                        var remaining = expiry - DateTimeOffset.UtcNow;
                        countdown.Text = "Expires in " + Math.Max(0, (int)remaining.TotalSeconds / 60) + ":" +
                            Math.Max(0, (int)remaining.TotalSeconds % 60).ToString("D2");
                        if (remaining <= TimeSpan.Zero) dialog.Hide();
                    };
                    try
                    {
                        using (var generator = new QRCoder.QRCodeGenerator())
                        using (var data = generator.CreateQrCode("cdfpair:" + payload.Stringify(), QRCoder.QRCodeGenerator.ECCLevel.M))
                        using (var renderer = new QRCoder.PngByteQRCode(data))
                        using (var stream = new Windows.Storage.Streams.InMemoryRandomAccessStream())
                        {
                            var png = renderer.GetGraphic(8);
                            await stream.WriteAsync(ProbeState.Buffer(png));
                            stream.Seek(0);
                            var bitmap = new Windows.UI.Xaml.Media.Imaging.BitmapImage();
                            await bitmap.SetSourceAsync(stream);
                            picture.Source = bitmap;
                        }
                        timer.Start();
                        manual = await dialog.ShowAsync() == ContentDialogResult.Primary;
                        cancellation.Cancel();
                        await detection;
                        if (!manual && DateTimeOffset.UtcNow >= expiry)
                            throw new InvalidOperationException("The QR code expired. Show a new code and scan it again.");
                        if (!detected && !manual) return;
                        if (!manual) {
                        // Transport is selected locally, never taken from untrusted QR data.
                        await ProbeState.ConfigurePhoneAsync(host, secret);
                        ProbeState.DeviceId = device;
                        await RegisterAsync(bluetooth);
                        }
                    }
                    finally {
                        cancellation.Cancel();
                        await detection;
                        timer.Stop(); picture.Source = null; Array.Clear(secret, 0, secret.Length);
                    }
                }
                if (manual) await ManualPairAsync();
            });
        }

        private async Task DetectScannedPhoneAsync(string device, byte[] secret, DateTimeOffset expiry, string host, NativeBleTransport bluetooth,
            CancellationToken cancellation, Action detected)
        {
            var request = new JsonObject {
                ["operation"] = JsonValue.CreateStringValue("pairingReady"),
                ["deviceId"] = JsonValue.CreateStringValue(device)
            };
            try
            {
                while (DateTimeOffset.UtcNow < expiry)
                {
                    cancellation.ThrowIfCancellationRequested();
                    try
                    {
                        using (var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                        {
                            attempt.CancelAfter(TimeSpan.FromSeconds(bluetooth == null ? 3 : 15));
                            await PhoneClient.ExchangeAsync(request, host, secret, attempt.Token, bluetooth);
                        }
                        cancellation.ThrowIfCancellationRequested();
                        if (DateTimeOffset.UtcNow >= expiry) return;
                        detected();
                        return;
                    }
                    catch (Exception error) when (!cancellation.IsCancellationRequested)
                    {
                        // Keep retrying for an unscanned invitation, but retain the failure stage.
                        if (bluetooth != null) ProbeState.Write("Native Bluetooth QR detection: " + error.Message);
                    }
                    await Task.Delay(1000, cancellation);
                }
            }
            catch (Exception) when (cancellation.IsCancellationRequested) { }
        }

        private async void PhoneRegister_Click(object sender, RoutedEventArgs e)
        {
            await RunAsync("Pair phone", async () =>
            {
                if (ProbeState.DeviceId != null)
                    throw new InvalidOperationException("Unpair the existing registration before pairing.");
                if (!await CheckBeforePairingAsync()) return;
                await ManualPairAsync();
            });
        }

        private async Task ManualPairAsync()
        {
                var pairingCode = new PasswordBox { Header = "Pairing code shown on your phone" };
                var validation = new TextBlock { TextWrapping = TextWrapping.Wrap };
                var dialog = new ContentDialog {
                    Title = "Manual setup", PrimaryButtonText = "Pair", CloseButtonText = "Cancel",
                    Content = new StackPanel { Spacing = 12, Children = {
                        new TextBlock { Text = "Enter the 64-character code from your phone. Keep Bluetooth enabled.", TextWrapping = TextWrapping.Wrap },
                        pairingCode, validation } }
                };
                dialog.PrimaryButtonClick += (s, args) => {
                    var code = pairingCode.Password.Trim();
                    if (code.Length != 64 || !code.All(Uri.IsHexDigit))
                    {
                        validation.Text = "Enter all 64 hexadecimal characters shown on your phone.";
                        args.Cancel = true;
                    }
                };
                try
                {
                    if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
                    var code = pairingCode.Password.Trim();
                    var secret = Enumerable.Range(0, 32).Select(i => Convert.ToByte(code.Substring(i * 2, 2), 16)).ToArray();
                    try { await ProbeState.ConfigurePhoneAsync(NativeBleTransport.Endpoint, secret); }
                    finally { Array.Clear(secret, 0, secret.Length); pairingCode.Password = ""; }
                    using (var bluetooth = await NativeBleTransport.OpenAsync(ProbeState.PhoneHost, CancellationToken.None))
                        await RegisterAsync(bluetooth);
                }
                finally { pairingCode.Password = ""; }
        }

        private async Task RegisterAsync(NativeBleTransport bluetooth = null)
        {
                ProbeState.Write("Registration: enumerating existing CDF devices.");
                ProbeState.AutomaticUnlock = null;
                ProbeState.Disarm();
                var devices = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(
                    SecondaryAuthenticationFactorDeviceFindScope.User);
                if (devices.Any(d => d.DeviceId == ProbeState.DeviceId))
                {
                    ProbeState.Write("Probe is already registered. Remove it before re-registering.");
                    return;
                }
                if (ProbeState.DeviceId == null) ProbeState.DeviceId = Guid.NewGuid().ToString("N");
                byte[] keys;
                {
                    var request = new JsonObject {
                        ["operation"] = JsonValue.CreateStringValue("register"),
                        ["deviceId"] = JsonValue.CreateStringValue(ProbeState.DeviceId)
                    };
                    ProbeState.Write("Approve registration in the phone app.");
                    var response = await PhoneClient.ExchangeAsync(request, CancellationToken.None, bluetooth);
                    keys = PhoneClient.Get(response, "keys", 64);
                }

                SecondaryAuthenticationFactorRegistration registration = null;
                try
                {
                    ProbeState.Write("Registration: calling RequestStartRegisteringDeviceAsync (SecureStorage).");
                    var result = await SecondaryAuthenticationFactorRegistration.RequestStartRegisteringDeviceAsync(
                        ProbeState.DeviceId, SecondaryAuthenticationFactorDeviceCapabilities.SecureStorage,
                        "PocketLatch phone", "PocketLatch-1", ProbeState.Buffer(keys.Take(32).ToArray()),
                        ProbeState.Buffer(keys.Skip(32).ToArray()));
                    ProbeState.Write("RequestStartRegisteringDeviceAsync=" + result.Status);
                    if (result.Status != SecondaryAuthenticationFactorRegistrationStatus.Started)
                        throw new InvalidOperationException(result.Status == SecondaryAuthenticationFactorRegistrationStatus.DisabledByPolicy
                            ? "Windows blocked enrollment by policy. Enable Allow companion device for secondary authentication, then retry."
                            : result.Status == SecondaryAuthenticationFactorRegistrationStatus.PinSetupRequired
                            ? "Set up a Windows Hello PIN in Sign-in options, then retry." : "Windows enrollment: " + result.Status);
                    registration = result.Registration;
                    ProbeState.Write("Registration: calling FinishRegisteringDeviceAsync.");
                    await registration.FinishRegisteringDeviceAsync(CryptographicBuffer.ConvertStringToBinary(
                        "PocketLatch phone v1", BinaryStringEncoding.Utf8));
                    registration = null;
                    ProbeState.Write("FinishRegisteringDeviceAsync succeeded.");
                    {
                        await EnableBackgroundAsync();
                        ProbeState.AutomaticUnlock = Guid.NewGuid().ToString("N");
                        ProbeState.Write("Phone unlock enabled after pairing. Every sign-in still requires phone approval.");
                    }
                }
                finally
                {
                    Array.Clear(keys, 0, keys.Length);
                    if (registration != null)
                    {
                        try { await registration.AbortRegisteringDeviceAsync("Probe registration did not finish."); }
                        catch (Exception error) { ProbeState.Error("Abort registration", error); }
                    }
                }
        }

        private async void Enable_Click(object sender, RoutedEventArgs e)
        {
            await RunAsync("Enable background task", EnableBackgroundAsync);
        }

        private async Task EnableBackgroundAsync()
        {
            var access = BackgroundExecutionManager.GetAccessStatus();
            if (access != BackgroundAccessStatus.AlwaysAllowed && access != BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
                access = await BackgroundExecutionManager.RequestAccessAsync();
            ProbeState.Write("Background access=" + access);
            if (access != BackgroundAccessStatus.AlwaysAllowed && access != BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
                throw new InvalidOperationException("Windows blocked background access. Allow this app in Windows background-app settings, then retry.");
            if (!BackgroundTaskRegistration.AllTasks.Values.Any(t => t.Name == ProbeState.TaskName))
            {
                var builder = new BackgroundTaskBuilder { Name = ProbeState.TaskName, TaskEntryPoint = ProbeState.EntryPoint };
                builder.SetTrigger(new SecondaryAuthenticationFactorAuthenticationTrigger());
                builder.Register();
            }
            ProbeState.Write("Background task ready; closing the window does not unregister it.");
        }

        private async void AutomaticUnlock_Click(object sender, RoutedEventArgs e)
        {
            await RunAsync("Phone unlock", async () =>
            {
                if (ProbeState.AutomaticUnlock != null)
                {
                    ProbeState.AutomaticUnlock = null;
                    ProbeState.Disarm();
                    ProbeState.Write("Phone unlock paused by user.");
                    return;
                }
                var devices = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(
                    SecondaryAuthenticationFactorDeviceFindScope.User);
                if (!ProbeState.PhoneMode || !devices.Any(d => d.DeviceId == ProbeState.DeviceId))
                    throw new InvalidOperationException("Pair your phone first.");
                await EnableBackgroundAsync();
                var secret = await ProbeState.LoadPhoneSecretAsync();
                Array.Clear(secret, 0, secret.Length);
                ProbeState.Disarm();
                ProbeState.AutomaticUnlock = Guid.NewGuid().ToString("N");
                ProbeState.Write("Phone unlock enabled. Each Windows sign-in requires fresh phone approval.");
            });
        }

        private async void Remove_Click(object sender, RoutedEventArgs e)
        {
            var confirmation = new ContentDialog {
                Title = "Unpair your phone?",
                Content = "Phone unlock will stop on this PC. You can still sign in with your Windows PIN. To use your phone again, pair it again.",
                PrimaryButtonText = "Unpair", CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Close
            };
            if (await confirmation.ShowAsync() != ContentDialogResult.Primary) return;
            await RunAsync("Unpair phone", async () =>
            {
                ProbeState.Disarm();
                ProbeState.AutomaticUnlock = null;
                foreach (var task in BackgroundTaskRegistration.AllTasks.Values.Where(t => t.Name == ProbeState.TaskName).ToArray())
                    task.Unregister(true);
                ProbeState.Write("Probe background task removed; probe disarmed.");
                var devices = await SecondaryAuthenticationFactorRegistration.FindAllRegisteredDeviceInfoAsync(
                    SecondaryAuthenticationFactorDeviceFindScope.User);
                if (devices.Any(d => d.DeviceId == ProbeState.DeviceId))
                    await SecondaryAuthenticationFactorRegistration.UnregisterDeviceAsync(ProbeState.DeviceId);
                // Keep the ID/keys if the API throws, so removal can be retried.
                ProbeState.ClearDevice();
                ProbeState.Write("Phone pairing removed. Other companion devices were not modified.");
            });
        }

        private void DiagnosticsToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (DiagnosticsPanel != null)
                DiagnosticsPanel.Visibility = DiagnosticsToggle.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        }

        private async void Refresh_Click(object sender, RoutedEventArgs e) { await RunAsync("Refresh", () => Task.CompletedTask); }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            ProbeState.ClearLog();
            Refresh();
        }

        private async void Save_Click(object sender, RoutedEventArgs e)
        {
            await RunAsync("Save report", async () =>
            {
                var picker = new FileSavePicker { SuggestedFileName = "windows-companion-report" };
                picker.FileTypeChoices.Add("Text report", new[] { ".txt" });
                var file = await picker.PickSaveFileAsync();
                if (file != null) await FileIO.WriteTextAsync(file, ProbeState.Report());
            });
        }
    }
}
