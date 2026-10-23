using System;
using System.Linq;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using CdfProbe.Shared;
using Windows.ApplicationModel.Background;
using Windows.Security.Authentication.Identity.Provider;
using Windows.Security.Cryptography;
using Windows.Storage;
using Windows.Data.Json;

namespace CdfProbe.Background
{
    public sealed class AuthenticationTask : IBackgroundTask
    {
        public async void Run(IBackgroundTaskInstance taskInstance)
        {
            var deferral = taskInstance.GetDeferral();
            var elapsed = Stopwatch.StartNew();
            var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            BackgroundTaskCanceledEventHandler canceled = (s, reason) => {
                ProbeState.Write("Windows canceled background task: " + reason + "; elapsed=" + elapsed.Elapsed.TotalSeconds.ToString("F1") + "s");
                cancellation.Cancel();
            };
            EventHandler<SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> changed =
                (s, args) =>
                {
                    ProbeState.Write("Authentication stage changed=" + args.StageInfo.Stage);
                    ResetAttemptAfterSignIn(args.StageInfo.Stage);
                    if (args.StageInfo.Stage == SecondaryAuthenticationFactorAuthenticationStage.CollectingCredential)
                        ready.TrySetResult(true);
                    if (args.StageInfo.Stage == SecondaryAuthenticationFactorAuthenticationStage.StoppingAuthentication)
                        cancellation.Cancel();
                };
            bool subscribed = false;
            FileStream attemptLock = null;
            NativeBleTransport preparedBluetooth = null;
            taskInstance.Canceled += canceled;
            try
            {
                ProbeState.Write("BACKGROUND TRIGGER FIRED. App cutoff=45s; extendedBackgroundTaskTime declared.");
                // OS releases the exclusive handle even if Windows terminates the task.
                try { attemptLock = new FileStream(Path.Combine(ApplicationData.Current.LocalFolder.Path,
                    "authentication.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                catch (IOException) { ProbeState.Write("Another authentication task is active."); return; }
                string automatic = ProbeState.PhoneMode ? ProbeState.AutomaticUnlock : null;
                string armed = automatic != null ? AuthorizationTicket.Create(ProbeState.DeviceId, DateTime.UtcNow) : null;
                var ticket = AuthorizationTicket.Parse(armed, ProbeState.DeviceId, DateTime.UtcNow);
                if (ticket == null)
                {
                    ProbeState.Write("No valid authorization ticket; no authentication attempted.");
                    return;
                }
                SecondaryAuthenticationFactorAuthentication.AuthenticationStageChanged += changed;
                subscribed = true;
                var stage = await SecondaryAuthenticationFactorAuthentication.GetAuthenticationStageInfoAsync();
                ProbeState.Write("Initial authentication stage=" + stage.Stage);
                ResetAttemptAfterSignIn(stage.Stage);
                if (stage.Stage == SecondaryAuthenticationFactorAuthenticationStage.CollectingCredential)
                    ready.TrySetResult(true);
                if (stage.Stage == SecondaryAuthenticationFactorAuthenticationStage.StoppingAuthentication)
                    cancellation.Cancel();

                // Discover/connect during the lock-screen stage. No challenge or approval
                // request is sent until CollectingCredential and the authorization claim below.
                if (ProbeState.PhoneMode && ProbeState.PhoneHost == NativeBleTransport.Endpoint)
                {
                    preparedBluetooth = await NativeBleTransport.OpenAsync(ProbeState.PhoneHost, cancellation.Token);
                    ProbeState.Write("Bluetooth prepared before credential collection; elapsed=" + elapsed.Elapsed.TotalSeconds.ToString("F2") + "s");
                }
                using (cancellation.Token.Register(() => ready.TrySetCanceled()))
                    await ready.Task;
                cancellation.Token.ThrowIfCancellationRequested();
                if (!IsAuthorized(armed, automatic))
                    throw new InvalidOperationException("Authorization ticket expired or was revoked.");
                if (automatic != null && !ProbeState.ClaimAutomaticAttempt(automatic))
                {
                    ProbeState.Write("Phone request already sent for this sign-in. Use Windows PIN after denial or timeout; no repeat notification.");
                    await ShowPinFallbackAsync();
                    return;
                }

                ProbeState.Write("CollectingCredential; phone approval required.");
                await AuthenticateAsync(ticket, armed, automatic, cancellation.Token, preparedBluetooth);
            }
            catch (OperationCanceledException)
            {
                ProbeState.Write("Background task canceled, authentication stopped, or 45-second wait expired.");
            }
            catch (Exception error) { ProbeState.Error("Background authentication", error); }
            finally
            {
                try
                {
                    if (subscribed) SecondaryAuthenticationFactorAuthentication.AuthenticationStageChanged -= changed;
                    taskInstance.Canceled -= canceled;
                    preparedBluetooth?.Dispose();
                    attemptLock?.Dispose();
                    // A queued event can still call Cancel; do not dispose this small per-run CTS here.
                    ProbeState.Write("Background task completed.");
                }
                finally { deferral.Complete(); }
            }
        }

        private static bool IsAuthorized(string armed, string automatic) => UnlockAuthorization.IsValid(
            automatic, ProbeState.AutomaticUnlock, ProbeState.PhoneMode, armed, ProbeState.Armed,
            ProbeState.DeviceId, DateTime.UtcNow);

        private static async Task ShowPinFallbackAsync()
        {
            try
            {
                // CDF supports stock messages only; keep the device label below its length limit.
                await SecondaryAuthenticationFactorAuthentication.ShowNotificationMessageAsync(
                    SignInLabel.Phone, SecondaryAuthenticationFactorAuthenticationMessage.UnauthorizedUser);
                ProbeState.Write("Windows PIN fallback instructions displayed.");
            }
            catch (Exception error) { ProbeState.Error("Show PIN fallback instructions", error); }
        }

        private static void ResetAttemptAfterSignIn(SecondaryAuthenticationFactorAuthenticationStage stage)
        {
            // StoppingAuthentication means Windows has returned to the desktop,
            // including when the user chose PIN instead of the companion.
            if (stage == SecondaryAuthenticationFactorAuthenticationStage.CredentialAuthenticated ||
                stage == SecondaryAuthenticationFactorAuthenticationStage.StoppingAuthentication)
                ProbeState.AutomaticAttempt = null;
        }

        private static async Task ShowPhoneInstructionsAsync()
        {
            try {
                await SecondaryAuthenticationFactorAuthentication.ShowNotificationMessageAsync(
                    SignInLabel.Phone, SecondaryAuthenticationFactorAuthenticationMessage.DeviceNeedsAttention);
                ProbeState.Write("Windows phone sign-in instructions displayed.");
            } catch (Exception error) { ProbeState.Error("Show phone sign-in instructions", error); }
        }

        private static async Task AuthenticateAsync(AuthorizationTicket ticket, string armed, string automatic, CancellationToken cancellation, NativeBleTransport preparedBluetooth)
        {
            var timing = Stopwatch.StartNew();
            NativeBleTransport bluetooth = preparedBluetooth;
            SecondaryAuthenticationFactorAuthentication authentication = null;
            try
            {
                cancellation.ThrowIfCancellationRequested();
                if (!ProbeState.PhoneMode) throw new InvalidOperationException("Pair your phone first.");
                bool phone = true;
                if (phone && bluetooth == null) bluetooth = await NativeBleTransport.OpenAsync(ProbeState.PhoneHost, cancellation);
                var serviceNonce = ProbeState.Bytes(CryptographicBuffer.GenerateRandom(32));
                {
                    var prepare = new JsonObject {
                        ["operation"] = JsonValue.CreateStringValue("prepareUnlock"),
                        ["deviceId"] = JsonValue.CreateStringValue(ticket.DeviceId)
                    };
                    PhoneClient.Put(prepare, "serviceNonce", serviceNonce);
                    var instructions = ShowPhoneInstructionsAsync();
                    ProbeState.Write("Waiting for phone approval before starting CDF authentication.");
                    await PhoneClient.ExchangeAsync(prepare, cancellation, bluetooth);
                    ProbeState.Write("Phone approval received; elapsed=" + timing.Elapsed.TotalSeconds.ToString("F2") + "s");
                    await instructions;
                    cancellation.ThrowIfCancellationRequested();
                    if (!IsAuthorized(armed, automatic))
                        throw new InvalidOperationException("Authorization ticket expired or was revoked during approval.");
                }
                var result = await SecondaryAuthenticationFactorAuthentication.StartAuthenticationAsync(
                    ticket.DeviceId, ProbeState.Buffer(serviceNonce));
                ProbeState.Write("StartAuthenticationAsync=" + result.Status);
                if (result.Status != SecondaryAuthenticationFactorAuthenticationStatus.Started) return;
                authentication = result.Authentication;
                cancellation.ThrowIfCancellationRequested();

                var deviceNonce = ProbeState.Bytes(authentication.DeviceNonce);
                var sessionNonce = ProbeState.Bytes(authentication.SessionNonce);
                byte[] deviceHmac, sessionHmac;
                {
                    var request = new JsonObject {
                        ["operation"] = JsonValue.CreateStringValue("authenticate"),
                        ["deviceId"] = JsonValue.CreateStringValue(ticket.DeviceId)
                    };
                    PhoneClient.Put(request, "serviceNonce", serviceNonce);
                    PhoneClient.Put(request, "deviceNonce", deviceNonce);
                    PhoneClient.Put(request, "sessionNonce", sessionNonce);
                    PhoneClient.Put(request, "serviceHmac", ProbeState.Bytes(authentication.ServiceAuthenticationHmac));
                    ProbeState.Write("Exchanging fresh CDF challenge using the single-use phone approval.");
                    var response = await PhoneClient.ExchangeAsync(request, cancellation, bluetooth);
                    deviceHmac = PhoneClient.Get(response, "deviceHmac", 32);
                    sessionHmac = PhoneClient.Get(response, "sessionHmac", 32);
                    ProbeState.Write("Received encrypted phone response for this session.");
                }
                cancellation.ThrowIfCancellationRequested();
                if (!IsAuthorized(armed, automatic))
                    throw new InvalidOperationException("Authorization ticket expired or was revoked before finish.");
                var status = await authentication.FinishAuthenticationAsync(
                    ProbeState.Buffer(deviceHmac), ProbeState.Buffer(sessionHmac));
                authentication = null;
                ProbeState.Write("FinishAuthenticationAsync=" + status + ". Confirm desktop unlock visually.");
                // This task can finish before the final stage event arrives.
                if (status == SecondaryAuthenticationFactorFinishAuthenticationStatus.Completed)
                    ProbeState.AutomaticAttempt = null;
            }
            catch (Exception) when (ProbeState.PhoneMode && !cancellation.IsCancellationRequested)
            {
                // Deny, disconnect and timeout all fail closed; never send another phone request here.
                await ShowPinFallbackAsync();
                throw;
            }
            finally
            {
                bluetooth?.Dispose();
                if (authentication != null)
                {
                    try { await authentication.AbortAuthenticationAsync("Probe did not finish authentication."); }
                    catch (Exception error) { ProbeState.Error("AbortAuthenticationAsync", error); }
                }
            }
        }
    }
}
