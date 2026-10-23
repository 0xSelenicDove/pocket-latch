package dev.selenic.companion;

import android.app.*;
import android.content.*;
import android.os.*;
import android.util.Log;
import java.util.*;
import org.json.JSONObject;

public final class CompanionService extends Service implements BleClient.Listener {
    static CompanionService instance;
    static final String CHANNEL="connection", REQUESTS="approvals";
    static final int REQUEST_NOTIFICATION=2;
    final Handler handler=new Handler(Looper.getMainLooper());
    Vault vault; BleClient ble; String status="Not connected", connectionStatus="Bluetooth stopped.";
    byte[] session,challenge; long deadline; JSONObject pending;
    String pendingId; boolean processing;
    final Protocol.Grant grant=new Protocol.Grant();
    @Override public void onCreate() {
        super.onCreate();instance=this;vault=new Vault(this);
        NotificationManager n=getSystemService(NotificationManager.class);
        n.createNotificationChannel(new NotificationChannel(CHANNEL,"Bluetooth connection",NotificationManager.IMPORTANCE_LOW));
        n.createNotificationChannel(new NotificationChannel(REQUESTS,"Windows sign-in requests",NotificationManager.IMPORTANCE_HIGH));
        ble=new BleClient(this,this);
    }
    PendingIntent open(String id,boolean approve) {
        Intent i=new Intent(this,MainActivity.class).setAction("request:"+id+":"+approve).putExtra("request",id).putExtra("approve",approve);
        return PendingIntent.getActivity(this,0,i,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
    }
    Notification connectionNotification() {
        return new Notification.Builder(this,CHANNEL).setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("PocketLatch").setContentText(status)
            .setContentIntent(open("",false)).setOngoing(true).build();
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId) {
        if(intent!=null && intent.getAction()!=null && intent.getAction().startsWith("deny:")) {
            if(Objects.equals(pendingId,intent.getStringExtra("request"))) reject("You denied the request.");
            return START_NOT_STICKY;
        }
        if(intent!=null && "stop".equals(intent.getAction())) {stopSelf();return START_NOT_STICKY;}
        startForeground(1,connectionNotification());
        try { if(vault.wake()!=null) ble.start(); else status("Pair your phone to connect."); }
        catch(Exception e) {status("Pairing could not be read. Unlock your phone and reopen the app.");}
        return START_STICKY;
    }
    @Override public IBinder onBind(Intent i){return null;}
    @Override public void onDestroy(){ble.stop();handler.removeCallbacksAndMessages(null);instance=null;super.onDestroy();}
    public void status(String s) {Log.i("CompanionRequest",s);status=s;getSystemService(NotificationManager.class).notify(1,connectionNotification());}
    @Override public void connectionStatus(String s) { connectionStatus=s;status(s); }
    @Override public boolean busy(){return session!=null || grant.pending(SystemClock.elapsedRealtime());}
    @Override public void disconnected(){clearSession();}
    void clearSession() {
        session=null;challenge=null;pending=null;pendingId=null;processing=false;
        getSystemService(NotificationManager.class).cancel(REQUEST_NOTIFICATION);
    }
    void resetPairing(){clearSession();grant.clear();ble.stop();ble.start();}
    void reject(String reason) {
        if(session!=null)ble.send(3,session,new byte[0]);
        clearSession();grant.clear();status(reason);
    }
    @Override public void message(Protocol.Message m) {
        try {
            if(m.kind()==1 && m.payload().length==0) {
                if(session!=null || vault.wake()==null){ble.send(3,m.session(),new byte[0]);return;}
                Log.i("CompanionRequest","BLE session started");
                session=m.session();challenge=Protocol.random(32);deadline=SystemClock.elapsedRealtime()+30000;processing=false;
                byte[] current=session;
                handler.postDelayed(()->{if(session==current)reject("Request expired. Try again on Windows.");},30000);
                ble.send(4,session,challenge);return;
            }
            if(session==null || !Arrays.equals(session,m.session()))return;
            if(m.kind()==3){clearSession();status("Windows ended the request.");return;}
            if(m.kind()!=2 || processing)return;
            processing=true;
            JSONObject stored=vault.wake();
            JSONObject r=new JSONObject(new String(Protocol.crypt(false,Protocol.unframe(m.payload()),
                Protocol.bytes(stored,"secret",32),challenge,"request"),java.nio.charset.StandardCharsets.UTF_8));
            String operation=r.getString("operation"),device=r.getString("deviceId");
            if(!device.matches("[a-fA-F0-9]{32}") || !Set.of("pairingReady","register","prepareUnlock","authenticate").contains(operation))
                throw new Exception("Invalid request");
            Log.i("CompanionRequest","Authenticated operation="+operation);
            boolean enrolled=stored.optBoolean("enrolled");
            boolean enrollment=!enrolled && stored.optLong("expires")>System.currentTimeMillis()/1000;
            if(operation.equals("pairingReady")) {
                if(!enrollment || !device.equals(stored.optString("deviceId")))throw new Exception("Pairing not ready");
                respond(r,new JSONObject());return;
            }
            if(operation.equals("register")) {
                if(!enrollment || (!stored.optString("deviceId").isEmpty() && !device.equals(stored.optString("deviceId"))))
                    throw new Exception("Enrollment not allowed");
            } else if(!enrolled || !device.equals(stored.optString("deviceId")))throw new Exception("PC is not paired");
            if(operation.equals("authenticate")) {
                if(!grant.consume(device,Protocol.bytes(r,"serviceNonce",32),SystemClock.elapsedRealtime()))
                    throw new Exception("No fresh approval");
                JSONObject full=matchingFull(stored);
                respond(r,Protocol.proof(r,Protocol.bytes(full,"keys",64)));return;
            }
            if(operation.equals("prepareUnlock")) {
                grant.clear();Protocol.bytes(r,"serviceNonce",32);
                if(vault.automatic()&&!vault.biometric()) {
                    matchingFull(stored);
                    grant.give(device,Protocol.bytes(r,"serviceNonce",32),SystemClock.elapsedRealtime());
                    respond(r,new JSONObject());status("Automatically approved your paired PC.");return;
                }
            }
            pending=r;pendingId=UUID.randomUUID().toString();notifyApproval();
        } catch(Exception e) {reject("Request rejected: "+e.getMessage());}
    }
    JSONObject matchingFull(JSONObject wake) throws Exception {
        JSONObject full=vault.full();
        if(full==null || !full.getString("secret").equals(wake.getString("secret")) ||
            !full.optString("deviceId").equals(wake.optString("deviceId")))throw new Exception("Pairing changed");
        return full;
    }
    void notifyApproval() {
        boolean registration=pending.optString("operation").equals("register");
        Intent deny=new Intent(this,CompanionService.class).setAction("deny:"+pendingId).putExtra("request",pendingId);
        PendingIntent no=PendingIntent.getService(this,0,deny,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        Notification n=new Notification.Builder(this,REQUESTS).setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(registration?"Pair with Windows?":"Unlock your Windows PC?")
            .setContentText("Review this request within 30 seconds.")
            .setContentIntent(open(pendingId,false)).setVisibility(Notification.VISIBILITY_PRIVATE)
            .setTimeoutAfter(Math.max(1,deadline-SystemClock.elapsedRealtime()))
            .addAction(new Notification.Action.Builder(null,"Approve",open(pendingId,true)).build())
            .addAction(new Notification.Action.Builder(null,"Deny",no).build()).build();
        getSystemService(NotificationManager.class).notify(REQUEST_NOTIFICATION,n);
        Log.i("CompanionRequest","Approval notification posted; enabled="+getSystemService(NotificationManager.class).areNotificationsEnabled());
        status(registration?"Approve pairing on your phone.":"Waiting for your approval.");
    }
    boolean current(String id) {return pending!=null && Objects.equals(id,pendingId) && SystemClock.elapsedRealtime()<deadline;}
    boolean needsAuthentication() {return pending!=null && (pending.optString("operation").equals("register") || vault.biometric());}
    void approve(String id,boolean authenticated) {
        if(!current(id))return;
        if(needsAuthentication()&&!authenticated)return;
        try {
            JSONObject r=pending,full=matchingFull(vault.wake()),out=new JSONObject();
            if(r.getString("operation").equals("register")) {
                if(full.optLong("expires")<=System.currentTimeMillis()/1000)throw new Exception("Pairing code expired");
                full.put("deviceId",r.getString("deviceId")).put("enrolled",true).remove("expires");
                vault.save(full);out.put("keys",full.getString("keys"));
            } else grant.give(r.getString("deviceId"),Protocol.bytes(r,"serviceNonce",32),SystemClock.elapsedRealtime());
            respond(r,out);
        } catch(Exception e){reject("Approval failed: "+e.getMessage());}
    }
    void respond(JSONObject request,JSONObject out) throws Exception {
        if(session==null || SystemClock.elapsedRealtime()>=deadline)throw new Exception("Request expired");
        out.put("operation",request.getString("operation")).put("deviceId",request.getString("deviceId")).put("status","approved");
        byte[] frame=Protocol.crypt(true,Protocol.text(out.toString()),Protocol.bytes(vault.wake(),"secret",32),challenge,"response");
        ble.send(2,session,Protocol.frame(frame));clearSession();status("Response sent. Check Windows.");
    }
}
