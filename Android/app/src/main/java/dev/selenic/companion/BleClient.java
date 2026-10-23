package dev.selenic.companion;

import android.annotation.SuppressLint;
import android.bluetooth.*;
import android.bluetooth.le.*;
import android.content.*;
import android.os.*;
import android.util.Log;
import java.util.*;

@SuppressLint("MissingPermission")
class BleClient {
    interface Listener { void connectionStatus(String s); void message(Protocol.Message m); void disconnected(); default boolean busy() { return false; } }
    final Context context; final Listener listener; final Handler h=new Handler(Looper.getMainLooper());
    BluetoothAdapter adapter; BluetoothGatt gatt; BluetoothGattCharacteristic up; BluetoothGattDescriptor pendingSubscription;
    Protocol.Receiver receiver=new Protocol.Receiver();
    ArrayDeque<byte[]> queue=new ArrayDeque<>(); boolean enabled, scanning, writing, discoveryStarted, subscribed; int mtu=20; long activity, refreshGeneration; boolean refreshing;
    BleClient(Context c,Listener l) {context=c;listener=l; adapter=c.getSystemService(BluetoothManager.class).getAdapter();}
    void start() { enabled=true; scan(); }
    void stop() { enabled=false;h.removeCallbacksAndMessages(null);close(); }
    void close() {
        activity++;refreshGeneration++;refreshing=false;
        stopScan();
        if(gatt!=null) { BluetoothGatt old=gatt;gatt=null;old.disconnect();old.close(); }
        pendingSubscription=null;up=null;queue.clear();writing=false;receiver=new Protocol.Receiver();mtu=20;discoveryStarted=false;subscribed=false;listener.disconnected();
    }
    void retry() { close(); if(enabled) h.postDelayed(this::scan,2000); }
    void stopScan() { if(scanning && adapter!=null && adapter.isEnabled()) adapter.getBluetoothLeScanner().stopScan(scanCallback); scanning=false; }
    void scan() {
        if(!enabled || gatt!=null || scanning) return;
        if(adapter==null || !adapter.isEnabled()) { listener.connectionStatus("Turn on Bluetooth to connect.");h.postDelayed(this::scan,4000);return; }
        try {
            adapter.getBluetoothLeScanner().startScan(List.of(new ScanFilter.Builder().setServiceUuid(new ParcelUuid(Protocol.SERVICE)).build()),
                new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),scanCallback);
            scanning=true;listener.connectionStatus("Waiting for your PC’s next sign-in request…");
        } catch(SecurityException e) {listener.connectionStatus("Allow Nearby devices permission, then reconnect.");}
    }
    final ScanCallback scanCallback=new ScanCallback() {
        @Override public void onScanResult(int type,ScanResult result) { h.post(()->{
            if(!enabled || gatt!=null) return;
            stopScan();listener.connectionStatus("Connecting to your PC…");
            gatt=result.getDevice().connectGatt(context,false,callback,BluetoothDevice.TRANSPORT_LE);
            BluetoothGatt expected=gatt;
            h.postDelayed(()->{if(gatt==expected && !subscribed) { Log.w("CompanionBLE","Connection setup timed out"); retry(); }},12000);
        });}
        @Override public void onScanFailed(int code) {h.post(()->{scanning=false;listener.connectionStatus("Bluetooth scan unavailable ("+code+"). Retrying…");h.postDelayed(BleClient.this::scan,10000);});}
    };
    final BluetoothGattCallback callback=new BluetoothGattCallback() {
        @Override public void onConnectionStateChange(BluetoothGatt g,int status,int state) {h.post(()->{
            if(g!=gatt)return;
            if(status!=BluetoothGatt.GATT_SUCCESS || state==BluetoothProfile.STATE_DISCONNECTED) {retry();return;}
            Log.i("CompanionBLE","Link state="+state+" status="+status);
            // Android may deliver an unsolicited MTU callback before our connection callback.
            // Do not start another ATT operation from it or request a competing MTU exchange.
            if(state==BluetoothProfile.STATE_CONNECTED) discover(g);
        });}
        @Override public void onMtuChanged(BluetoothGatt g,int negotiated,int status) {h.post(()->{
            if(g!=gatt)return;
            if(status==0)mtu=Math.max(20,Math.min(512,negotiated-3));
            Log.i("CompanionBLE","Negotiated payload="+mtu+" status="+status);
            subscribe(g);
        });}
        @Override public void onServicesDiscovered(BluetoothGatt g,int status) {h.post(()->{
            if(g!=gatt)return;
            Log.i("CompanionBLE","Services discovered status="+status);
            BluetoothGattService service=g.getService(Protocol.SERVICE);
            if(status!=0 || service==null) {retry();return;}
            BluetoothGattCharacteristic down=service.getCharacteristic(Protocol.DOWN);
            up=service.getCharacteristic(Protocol.UP);
            if(down==null || up==null || !g.setCharacteristicNotification(down,true)) {retry();return;}
            BluetoothGattDescriptor cccd=down.getDescriptor(UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"));
            if(cccd==null) {retry();return;}
            pendingSubscription=cccd;
            // Finish discovery, then negotiate MTU, then subscribe: never overlap ATT operations.
            if(mtu>20 || !g.requestMtu(517))subscribe(g);
            else Log.i("CompanionBLE","Requesting larger Bluetooth packets");
        });}
        @Override public void onDescriptorWrite(BluetoothGatt g,BluetoothGattDescriptor d,int status) {h.post(()->{
            if(g!=gatt)return;
            if(status!=0){retry();return;}
            refreshing=false;subscribed=true;Log.i("CompanionBLE","Companion subscription ready");
            listener.connectionStatus("Bluetooth connected");idleWatch();
        });}
        @Override public void onCharacteristicChanged(BluetoothGatt g,BluetoothGattCharacteristic c) {
            byte[] value=c.getValue().clone();h.post(()->received(g,c,value));
        }
        @Override public void onCharacteristicChanged(BluetoothGatt g,BluetoothGattCharacteristic c,byte[] value) {
            byte[] copy=value.clone();h.post(()->received(g,c,copy));
        }
        @Override public void onCharacteristicWrite(BluetoothGatt g,BluetoothGattCharacteristic c,int status) {h.post(()->{
            if(g!=gatt)return;
            if(status!=0){retry();return;}
            queue.poll();writing=false;drain();if(queue.isEmpty()){Log.i("CompanionBLE","Outgoing message delivered");idleWatch();}
        });}
        @Override public void onServiceChanged(BluetoothGatt g) {h.post(()->{
            if(g!=gatt)return;
            if(listener.busy() || writing || !queue.isEmpty()){idleWatch();return;}
            refreshService();
        });}
    };
    void subscribe(BluetoothGatt g) {
        if(g!=gatt || pendingSubscription==null)return;
        BluetoothGattDescriptor descriptor=pendingSubscription;pendingSubscription=null;
        descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
        if(!g.writeDescriptor(descriptor))retry();
    }
    void idleWatch() {
        long expected=++activity;
        h.postDelayed(()->{
            if(expected!=activity || !enabled || gatt==null)return;
            if(listener.busy() || writing || !queue.isEmpty()) {idleWatch();return;}
            // Windows replaces its provider between sign-ins. Refresh the subscription on
            // the existing link instead of paying for a disconnect and scan every time.
            refreshService();
        },4000);
    }
    void refreshService() {
        if(gatt==null || !enabled || refreshing)return;
        refreshing=true;long generation=++refreshGeneration;
        activity++;
        discoveryStarted=false;subscribed=false;pendingSubscription=null;up=null;
        BluetoothGatt expected=gatt;
        Log.i("CompanionBLE","Refreshing Windows service on existing Bluetooth link");
        discover(expected);
        h.postDelayed(()->{
            if(gatt==expected && generation==refreshGeneration && !subscribed){Log.w("CompanionBLE","Service refresh timed out; reconnecting");retry();}
        },5000);
    }
    void discover(BluetoothGatt g) {
        if(g!=gatt || discoveryStarted)return;
        discoveryStarted=true;Log.i("CompanionBLE","Starting service discovery");if(!g.discoverServices())retry();
    }
    void received(BluetoothGatt g,BluetoothGattCharacteristic c,byte[] value) {
        if(g!=gatt || !Protocol.DOWN.equals(c.getUuid()))return;
        idleWatch();
        try {Protocol.Message m=receiver.append(value);if(m!=null)listener.message(m);}
        catch(Exception e){retry();}
    }
    void send(int kind,byte[] session,byte[] payload) {
        if(gatt==null || up==null) {listener.disconnected();return;}
        List<byte[]> parts=Protocol.packets(kind,session,payload,mtu);
        if(queue.size()+parts.size()>650){retry();return;}
        Log.i("CompanionBLE","Sending kind="+kind+" packets="+parts.size()+" payload="+mtu);
        queue.addAll(parts);drain();
    }
    void drain() {
        if(writing || queue.isEmpty() || up==null || gatt==null)return;
        writing=true;up.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);up.setValue(queue.peek());
        if(!gatt.writeCharacteristic(up))retry();
    }
}
