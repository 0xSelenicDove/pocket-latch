package dev.selenic.companion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.json.JSONObject;

/** Wire-compatible with the Windows and iOS implementations. No Android dependency. */
final class Protocol {
    static String approvalPrompt(String operation, String scenario) {
        if ("register".equals(operation)) return "Pair this phone with Windows?";
        if ("SignIn".equals(scenario)) return "Approve Windows sign-in?";
        return "Approve Windows Hello authentication?";
    }
    static String approvalDetail(String scenario) {
        return "SignIn".equals(scenario) ? "Check the sign-in request on your PC."
            : "Check the requesting app on your PC. Windows does not provide its name to PocketLatch.";
    }

    static final UUID SERVICE = UUID.fromString("8d501100-27f0-4a65-ad64-0e42b41d6401");
    static final UUID DOWN = UUID.fromString("8d501101-27f0-4a65-ad64-0e42b41d6401");
    static final UUID UP = UUID.fromString("8d501102-27f0-4a65-ad64-0e42b41d6401");
    static byte[] random(int n) { byte[] b = new byte[n]; new SecureRandom().nextBytes(b); return b; }
    static byte[] join(byte[]... parts) {
        int n = 0; for (byte[] p:parts) n += p.length;
        ByteBuffer out = ByteBuffer.allocate(n); for (byte[] p:parts) out.put(p); return out.array();
    }
    static byte[] text(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static byte[] bytes(JSONObject o, String name, int size) throws Exception {
        byte[] b = Base64.getDecoder().decode(o.getString(name));
        if (b.length != size) throw new GeneralSecurityException("Invalid " + name);
        return b;
    }
    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    static byte[] crypt(boolean encrypt, byte[] data, byte[] secret, byte[] challenge, String direction) throws Exception {
        if (secret.length != 32 || challenge.length != 32 || !Set.of("request","response").contains(direction)
            || data.length > (encrypt ? 4068 : 4096) || (!encrypt && data.length < 28))
            throw new GeneralSecurityException("Invalid encrypted frame");
        byte[] key = MessageDigest.getInstance("SHA-256").digest(join(secret,text("cdf-wifi-v1/" + direction)));
        byte[] iv = encrypt ? random(12) : Arrays.copyOf(data,12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));
        c.updateAAD(join(challenge,text(direction)));
        byte[] result = c.doFinal(encrypt ? data : Arrays.copyOfRange(data,12,data.length));
        Arrays.fill(key,(byte)0);
        return encrypt ? join(iv,result) : result;
    }
    static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(key,"HmacSHA256")); return m.doFinal(data);
    }
    static JSONObject proof(JSONObject request, byte[] keys) throws Exception {
        if(keys.length != 64) throw new GeneralSecurityException("Missing signing keys");
        byte[] service=bytes(request,"serviceNonce",32), device=bytes(request,"deviceNonce",32),
            session=bytes(request,"sessionNonce",32), auth=Arrays.copyOfRange(keys,32,64);
        if(!MessageDigest.isEqual(bytes(request,"serviceHmac",32),hmac(auth,join(service,device,session))))
            throw new GeneralSecurityException("Windows challenge authentication failed");
        byte[] dh=hmac(Arrays.copyOf(keys,32),device);
        return new JSONObject().put("deviceHmac",b64(dh)).put("sessionHmac",b64(hmac(auth,join(dh,session))));
    }
    static JSONObject invitation(String text, long nowSeconds) throws Exception {
        if(text.length()>1024 || !text.startsWith("cdfpair:")) throw new IllegalArgumentException("Not a PocketLatch QR code");
        JSONObject o = new JSONObject(text.substring(8));
        long remaining=o.getLong("expires")-nowSeconds;
        if(o.getInt("version")!=1 || !Set.of("windows-ble","mac-ble").contains(o.getString("transport"))
            || !o.getString("deviceId").matches("[a-f0-9]{32}") || remaining<=0 || remaining>120)
            throw new IllegalArgumentException("Pairing QR is invalid or expired. Show a new code on Windows.");
        bytes(o,"secret",32); return o;
    }
    static byte[] frame(byte[] b) { return join(ByteBuffer.allocate(4).putInt(b.length).array(),b); }
    static byte[] unframe(byte[] b) throws Exception {
        if(b.length<32 || b.length>4100 || ByteBuffer.wrap(b).getInt()!=b.length-4) throw new GeneralSecurityException("Invalid frame length");
        return Arrays.copyOfRange(b,4,b.length);
    }
    record Message(int kind, byte[] session, byte[] payload) {}
    static List<byte[]> packets(int kind, byte[] id, byte[] payload, int mtu) {
        if(kind<1 || kind>4 || id.length!=8 || payload.length>4100 || mtu<20) throw new IllegalArgumentException();
        List<byte[]> out=new ArrayList<>();
        for(int off=0;off<Math.max(1,payload.length);off+=mtu-13) {
            int count=Math.min(mtu-13,payload.length-off);
            out.add(ByteBuffer.allocate(13+count).put((byte)kind).put(id).putShort((short)off)
                .putShort((short)payload.length).put(payload,off,count).array());
        } return out;
    }
    static final class Receiver {
        private byte[] id, data; private int kind, used;
        Message append(byte[] p) throws Exception {
            if(p.length<13) throw new GeneralSecurityException("Short packet");
            ByteBuffer b=ByteBuffer.wrap(p); int k=b.get()&255; byte[] s=new byte[8]; b.get(s);
            int off=b.getShort()&65535,total=b.getShort()&65535;
            if(k<1 || k>4 || total>4100 || off>total || b.remaining()>total-off || (p.length==13 && total!=0))
                throw new GeneralSecurityException("Invalid packet");
            if(data==null) { if(off!=0) throw new GeneralSecurityException("Missing packet"); id=s;kind=k;data=new byte[total];used=0; }
            if(kind!=k || !Arrays.equals(id,s) || data.length!=total || off!=used) throw new GeneralSecurityException("Out-of-order packet");
            int n=b.remaining();b.get(data,used,n);used+=n;
            if(used!=total) return null;
            Message m=new Message(kind,id,data);data=null;return m;
        }
    }
    static final class Grant {
        private String device; private byte[] nonce; private long expiry;
        boolean pending(long now) { return device!=null && now<expiry; }
        void clear() { device=null;nonce=null;expiry=0; }
        void give(String d,byte[] n,long now) { if(n.length!=32) throw new IllegalArgumentException();device=d;nonce=n.clone();expiry=now+15000; }
        boolean consume(String d,byte[] n,long now) {
            boolean ok=device!=null && device.equals(d) && MessageDigest.isEqual(nonce,n) && now<expiry;clear();return ok;
        }
    }
}
