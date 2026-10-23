package dev.selenic.companion;
import android.content.*;
import android.os.SystemClock;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.*;
import org.junit.runner.RunWith;
import org.json.JSONObject;
import java.util.*;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class ServiceTest {
    static class Transport extends BleClient {
        Protocol.Message last;
        Transport(Context c,Listener l){super(c,l);}
        @Override void send(int kind,byte[] session,byte[] payload){last=new Protocol.Message(kind,session,payload);}
        @Override void stop(){}
    }
    @Test public void registrationApprovalDenyAndSingleUseUnlock() throws Exception {
        Context c=InstrumentationRegistry.getInstrumentation().getTargetContext();
        for(String permission : new String[]{"android.permission.BLUETOOTH_CONNECT","android.permission.BLUETOOTH_SCAN","android.permission.POST_NOTIFICATIONS"})
            InstrumentationRegistry.getInstrumentation().getUiAutomation().grantRuntimePermission(c.getPackageName(),permission);
        Vault vault=new Vault(c);vault.clear();vault.options(true,false);
        c.startForegroundService(new Intent(c,CompanionService.class));
        for(int i=0;i<100&&CompanionService.instance==null;i++)Thread.sleep(50);
        assertNotNull(CompanionService.instance);
        final Throwable[] error=new Throwable[1];
        InstrumentationRegistry.getInstrumentation().runOnMainSync(()->{
            try{
                CompanionService s=CompanionService.instance;s.ble.stop();
                Transport t=new Transport(s,s);s.ble=t;
                byte[] secret=Protocol.random(32),keys=Protocol.random(64),nonce=Protocol.random(32);
                String pc="a".repeat(32);
                JSONObject p=new JSONObject().put("secret",Protocol.b64(secret)).put("keys",Protocol.b64(keys))
                    .put("deviceId",pc).put("enrolled",false).put("qr",true).put("expires",System.currentTimeMillis()/1000+120);
                vault.save(p);
                exchange(s,t,secret,new JSONObject().put("operation","pairingReady").put("deviceId",pc));
                assertEquals(2,t.last.kind());assertFalse(vault.wake().getBoolean("enrolled"));
                exchange(s,t,secret,new JSONObject().put("operation","register").put("deviceId",pc));
                assertNotNull(s.pending);String id=s.pendingId;
                s.approve(id,false);assertNotNull(s.pending);assertFalse(vault.wake().getBoolean("enrolled"));
                s.approve("old-notification",true);assertNotNull(s.pending);
                s.approve(id,true);assertNull(s.pending);assertEquals(2,t.last.kind());assertTrue(vault.wake().getBoolean("enrolled"));
                JSONObject prepare=new JSONObject().put("operation","prepareUnlock").put("deviceId",pc).put("serviceNonce",Protocol.b64(nonce));
                exchange(s,t,secret,prepare);assertNotNull(s.pending);s.reject("denied");
                assertEquals(3,t.last.kind());assertFalse(s.grant.consume(pc,nonce,SystemClock.elapsedRealtime()));
                vault.options(false,true);
                exchange(s,t,secret,prepare);assertNull(s.pending);assertEquals(2,t.last.kind());
                byte[] device=Protocol.random(32),session=Protocol.random(32);
                JSONObject auth=new JSONObject().put("operation","authenticate").put("deviceId",pc)
                    .put("serviceNonce",Protocol.b64(nonce)).put("deviceNonce",Protocol.b64(device)).put("sessionNonce",Protocol.b64(session))
                    .put("serviceHmac",Protocol.b64(Protocol.hmac(Arrays.copyOfRange(keys,32,64),Protocol.join(nonce,device,session))));
                exchange(s,t,secret,auth);assertEquals(2,t.last.kind());
                exchange(s,t,secret,auth);assertEquals(3,t.last.kind());
                prepare.put("deviceId","b".repeat(32));exchange(s,t,secret,prepare);assertEquals(3,t.last.kind());
                vault.options(true,true);prepare.put("deviceId",pc);
                exchange(s,t,secret,prepare);assertNotNull(s.pending);assertTrue(s.needsAuthentication());s.reject("test done");
                vault.clear();s.stopSelf();
            }catch(Throwable e){error[0]=e;}
        });
        if(error[0]!=null)throw new AssertionError(error[0]);
    }
    void exchange(CompanionService s,Transport t,byte[] secret,JSONObject request)throws Exception{
        byte[] session=Protocol.random(8);s.message(new Protocol.Message(1,session,new byte[0]));
        assertEquals(4,t.last.kind());
        byte[] encrypted=Protocol.crypt(true,Protocol.text(request.toString()),secret,t.last.payload(),"request");
        s.message(new Protocol.Message(2,session,Protocol.frame(encrypted)));
    }
}
