package dev.selenic.companion;

import android.content.*;
import android.security.keystore.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.util.*;
import org.json.JSONObject;

/** Encrypted, non-backed-up preferences; wrapping keys never leave Android Keystore. */
final class Vault {
    final SharedPreferences prefs;
    Vault(Context c) { prefs=c.getSharedPreferences("companion",Context.MODE_PRIVATE); }
    boolean biometric() { return prefs.getBoolean("biometric",true); }
    boolean automatic() { return prefs.getBoolean("automatic",false); }
    private javax.crypto.SecretKey key(String alias) throws Exception {
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore");ks.load(null);
        if(!ks.containsAlias(alias)) {
            KeyGenerator g=KeyGenerator.getInstance("AES","AndroidKeyStore");
            g.init(new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUnlockedDeviceRequired(alias.endsWith(".locked")).build());
            g.generateKey();
        } return (javax.crypto.SecretKey)ks.getKey(alias,null);
    }
    private String seal(JSONObject o,String alias) throws Exception {
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,key(alias));
        return Protocol.b64(Protocol.join(c.getIV(),c.doFinal(Protocol.text(o.toString()))));
    }
    private JSONObject read(String name,String alias) throws Exception {
        String stored=prefs.getString(name,null); if(stored==null) return null;
        byte[] b=Base64.getDecoder().decode(stored);
        if(b.length<28) throw new GeneralSecurityException("Invalid stored pairing");
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE,key(alias),new GCMParameterSpec(128,Arrays.copyOf(b,12)));
        return new JSONObject(new String(c.doFinal(Arrays.copyOfRange(b,12,b.length)),java.nio.charset.StandardCharsets.UTF_8));
    }
    private String fullAlias() { return prefs.getString("fullAlias","cdf.full.locked"); }
    JSONObject wake() throws Exception { return read("wake","cdf.wake"); }
    JSONObject full() throws Exception { return read("full",fullAlias()); }
    void save(JSONObject full) throws Exception { store(full,biometric(),automatic()); }
    private void store(JSONObject full,boolean bio,boolean auto) throws Exception {
        Protocol.bytes(full,"keys",64);Protocol.bytes(full,"secret",32);
        String alias=auto&&!bio ? "cdf.full.background" : "cdf.full.locked";
        JSONObject wake=new JSONObject(full.toString());wake.remove("keys");
        if(!prefs.edit().putString("full",seal(full,alias)).putString("wake",seal(wake,"cdf.wake"))
            .putString("fullAlias",alias).putBoolean("biometric",bio).putBoolean("automatic",auto).commit())
            throw new GeneralSecurityException("Could not save pairing");
    }
    void options(boolean bio,boolean auto) throws Exception {
        JSONObject p=full();
        if(p!=null) store(p,bio,auto);
        else if(!prefs.edit().putBoolean("biometric",bio).putBoolean("automatic",auto).commit())
            throw new GeneralSecurityException("Could not save settings");
    }
    void clear() { prefs.edit().remove("wake").remove("full").remove("fullAlias").apply(); }
}
