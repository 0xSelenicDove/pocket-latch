using System;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Core;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Radios;
using Windows.Security.Cryptography;

namespace CdfProbe.Shared
{
    // One provider for the whole pairing/sign-in operation, including prepare + authenticate.
    internal sealed class NativeBleTransport : IDisposable
    {
        internal const string Endpoint = "ble";
        private GattServiceProvider provider;
        private GattLocalCharacteristic down, up;
        private GattSubscribedClient peer;
        private readonly object sync = new object();
        private readonly SemaphoreSlim exchangeLock = new SemaphoreSlim(1);
        private BleWire.Receiver receiver;
        private byte[] session;
        private TaskCompletionSource<byte[]> incoming;
        private byte expected;
        private bool disposed;

        internal static async Task<string> CheckAdapterAsync()
        {
            var adapter = await BluetoothAdapter.GetDefaultAsync();
            if (adapter == null) return "No Windows Bluetooth adapter is available.";
            if (!adapter.IsPeripheralRoleSupported) return "This Bluetooth adapter cannot advertise the phone-unlock service (BLE peripheral role required).";
            var radio = await adapter.GetRadioAsync();
            if (radio == null || radio.State != RadioState.On) return "Turn on Bluetooth in Windows Settings.";
            return null;
        }

        internal static async Task<NativeBleTransport> OpenAsync(string host, CancellationToken cancellation)
        {
            if (host != Endpoint) return null;
#if !BLE_HOST
            await BluetoothRelay.StartAsync(cancellation);
            ProbeState.Write("Persistent Bluetooth host ready; service survives this task.");
            return new NativeBleTransport();
#else
            string error = await CheckAdapterAsync();
            cancellation.ThrowIfCancellationRequested();
            if (error != null) throw new InvalidOperationException(error);
            var transport = new NativeBleTransport();
            try
            {
                var result = await GattServiceProvider.CreateAsync(new Guid(BleWire.Service)).AsTask(cancellation);
                if (result.Error != BluetoothError.Success) throw new InvalidOperationException("Cannot create Bluetooth service: " + result.Error);
                transport.provider = result.ServiceProvider;
                var tx = await transport.provider.Service.CreateCharacteristicAsync(new Guid(BleWire.Downlink),
                    new GattLocalCharacteristicParameters { CharacteristicProperties = GattCharacteristicProperties.Notify,
                        ReadProtectionLevel = GattProtectionLevel.Plain }).AsTask(cancellation);
                var rx = await transport.provider.Service.CreateCharacteristicAsync(new Guid(BleWire.Uplink),
                    new GattLocalCharacteristicParameters { CharacteristicProperties = GattCharacteristicProperties.Write,
                        WriteProtectionLevel = GattProtectionLevel.Plain }).AsTask(cancellation);
                if (tx.Error != BluetoothError.Success || rx.Error != BluetoothError.Success)
                    throw new InvalidOperationException("Cannot create Bluetooth characteristics: " + tx.Error + "/" + rx.Error);
                transport.down = tx.Characteristic; transport.up = rx.Characteristic;
                transport.up.WriteRequested += transport.WriteRequested;

                transport.provider.AdvertisementStatusChanged += transport.AdvertisementStatusChanged;
                transport.provider.StartAdvertising(new GattServiceProviderAdvertisingParameters { IsConnectable = true, IsDiscoverable = true });
                // Some USB-passthrough radios briefly report Aborted before Started.
                await WaitForAdvertisingAsync(() => transport.provider.AdvertisementStatus,
                    TimeSpan.FromSeconds(8), cancellation);
                ProbeState.Write("Native Bluetooth service advertising; waiting for phone subscription.");
                return transport;
            }
            catch { transport.Dispose(); throw; }
#endif
        }

        internal static async Task WaitForAdvertisingAsync(Func<GattServiceProviderAdvertisementStatus> readStatus,
            TimeSpan timeout, CancellationToken cancellation)
        {
            using (var startup = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                startup.CancelAfter(timeout);
                try
                {
                    while (true)
                    {
                        startup.Token.ThrowIfCancellationRequested();
                        if (readStatus() == GattServiceProviderAdvertisementStatus.Started) return;
                        await Task.Delay(100, startup.Token);
                    }
                }
                catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
                {
                    throw new InvalidOperationException("Windows Bluetooth did not start advertising within " +
                        timeout.TotalSeconds + " seconds; final status=" + readStatus() +
                        ". Check the adapter/driver and VM USB passthrough settings.");
                }
            }
        }

        private void AdvertisementStatusChanged(GattServiceProvider sender, GattServiceProviderAdvertisementStatusChangedEventArgs args)
        {
            ProbeState.Write("Native Bluetooth advertising=" + args.Status + "; error=" + args.Error);
        }

        private void CheckAdvertising()
        {
            var status = provider.AdvertisementStatus;
            if (status == GattServiceProviderAdvertisementStatus.Aborted ||
                status == GattServiceProviderAdvertisementStatus.Stopped ||
                status == GattServiceProviderAdvertisementStatus.StartedWithoutAllAdvertisementData)
                throw new InvalidOperationException("Windows Bluetooth advertising=" + status +
                    ". The companion service may not be discoverable. Check the passed-through adapter/driver and stop other Bluetooth advertisers before retrying.");
        }

        private Task<byte[]> Expect(byte kind)
        {
            lock (sync)
            {
                expected = kind; receiver = new BleWire.Receiver();
                incoming = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                return incoming.Task;
            }
        }

        private async void WriteRequested(GattLocalCharacteristic sender, GattWriteRequestedEventArgs args)
        {
            var deferral = args.GetDeferral();
            try
            {
                var request = await args.GetRequestAsync();
                if (request == null) return;
                lock (sync)
                {
                    var packet = ProbeState.Bytes(request.Value);
                    // Ignore other centrals and stale exchanges; never route their data to the active request.
                    if (disposed || peer == null || session == null || incoming == null || incoming.Task.IsCompleted ||
                        args.Session.DeviceId.Id != peer.Session.DeviceId.Id || request.Offset != 0 ||
                        request.Option != GattWriteOption.WriteWithResponse || packet.Length < 13 ||
                        !packet.Skip(1).Take(8).SequenceEqual(session))
                    { request.RespondWithProtocolError(0x0E); return; }
                    try
                    {
                        var message = receiver.Append(packet);
                        if (message != null)
                        {
                            if (message.Kind == 3 && message.Payload.Length == 0)
                                incoming.TrySetException(new InvalidOperationException("Phone declined or ended the Bluetooth session."));
                            else if (message.Kind != expected || (expected == 4 && message.Payload.Length != 32))
                                throw new ArgumentException("Unexpected Bluetooth message.");
                            else incoming.TrySetResult(message.Payload);
                        }
                        request.Respond();
                    }
                    catch (Exception error) { incoming.TrySetException(error); request.RespondWithProtocolError(0x0D); }
                }
            }
            catch (Exception error) { lock (sync) { incoming?.TrySetException(error); } }
            finally { deferral.Complete(); }
        }

        private async Task SendAsync(byte kind, byte[] payload, CancellationToken cancellation)
        {
            foreach (var packet in BleWire.Packets(kind, session, payload, peer.MaxNotificationSize))
            {
                var result = await down.NotifyValueAsync(ProbeState.Buffer(packet), peer).AsTask(cancellation);
                if (result.Status != GattCommunicationStatus.Success)
                    throw new InvalidOperationException("Bluetooth notification failed: " + result.Status);
            }
        }

        internal async Task<byte[]> ExchangeAsync(Func<byte[], byte[]> makeRequest, Func<byte[], byte[], byte[]> readResponse,
            CancellationToken cancellation)
        {
#if !BLE_HOST
            return await BluetoothRelay.ExchangeAsync(makeRequest, readResponse, cancellation);
#else
            var timing = Stopwatch.StartNew();
            await exchangeLock.WaitAsync(cancellation);
            try
            {
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(35));
                    var token = timeout.Token;
                    while (true)
                    {
                        token.ThrowIfCancellationRequested();
                        if (disposed) throw new ObjectDisposedException(nameof(NativeBleTransport));
                        CheckAdvertising();
                        var clients = down.SubscribedClients;
                        if (clients.Count > 1) throw new InvalidOperationException("More than one phone connected. Disconnect other companions and retry.");
                        if (clients.Count == 1) { peer = clients[0]; ProbeState.Write("Native Bluetooth phone subscribed; elapsed=" + timing.Elapsed.TotalSeconds.ToString("F2") + "s"); break; }
                        await Task.Delay(100, token);
                    }
                    lock (sync) { session = ProbeState.Bytes(CryptographicBuffer.GenerateRandom(8)); }
                    using (token.Register(() => { lock (sync) { incoming?.TrySetCanceled(); } }))
                    {
                        var challengeTask = Expect(4);
                        await SendAsync(1, new byte[0], token);
                        var challenge = await challengeTask;
                        token.ThrowIfCancellationRequested();
                        ProbeState.Write("Native Bluetooth challenge received; elapsed=" + timing.Elapsed.TotalSeconds.ToString("F2") + "s");
                        var request = makeRequest(challenge);
                        var responseTask = Expect(2);
                        await SendAsync(2, BleWire.Frame(request), token);
                        ProbeState.Write("Native Bluetooth request sent; elapsed=" + timing.Elapsed.TotalSeconds.ToString("F2") + "s");
                        var response = await responseTask;
                        ProbeState.Write("Native Bluetooth response received; elapsed=" + timing.Elapsed.TotalSeconds.ToString("F2") + "s");
                        token.ThrowIfCancellationRequested();
                        return readResponse(BleWire.Unframe(response), challenge);
                    }
                }
            }
            finally
            {
                // Explicit end makes the phone ready for the next exchange; it also has its own deadline.
                if (session != null && peer != null && !disposed)
                {
                    try { using (var end = new CancellationTokenSource(TimeSpan.FromSeconds(1))) await SendAsync(3, new byte[0], end.Token); }
                    catch { }
                }
                lock (sync) { session = null; incoming = null; receiver = null; }
                exchangeLock.Release();
            }
#endif
        }



        public void Dispose()
        {
            lock (sync) { if (disposed) return; disposed = true; incoming?.TrySetCanceled(); }

            if (up != null) up.WriteRequested -= WriteRequested;
            if (provider != null) provider.AdvertisementStatusChanged -= AdvertisementStatusChanged;
            provider?.StopAdvertising();
            // Keep references valid for any in-flight WinRT continuation; handlers are detached.
        }
    }
}
