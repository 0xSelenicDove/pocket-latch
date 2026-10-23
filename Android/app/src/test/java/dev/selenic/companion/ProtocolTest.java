package dev.selenic.companion;
import org.junit.Test;
import static org.junit.Assert.*;
import org.json.JSONObject;
import java.util.*;
public class ProtocolTest {
    byte[] seq(int start){byte[] b=new byte[32];for(int i=0;i<32;i++)b[i]=(byte)(start+i);return b;}
    byte[] hex(String h){return java.util.HexFormat.of().parseHex(h);}
    @Test public void windowsChallengeVector() throws Exception {
        JSONObject r=new JSONObject().put("serviceNonce",Protocol.b64(seq(64))).put("deviceNonce",Protocol.b64(seq(96)))
            .put("sessionNonce",Protocol.b64(seq(128))).put("serviceHmac",Protocol.b64(hex("a332454708797ad0666fdb1dfebed0ef9fe3b43cdea46c8a250e0fd9228dbaa9")));
        JSONObject proof=Protocol.proof(r,Protocol.join(seq(0),seq(32)));
        assertArrayEquals(hex("4ac2b456828fef5a81d455c1becccc592a178d9fbd85b2fc514f0f895cd65c7b"),Protocol.bytes(proof,"deviceHmac",32));
        assertArrayEquals(hex("79cb7ba18af5dec467df4f00fe15d244b38b504a6133d43fe303ba1170e034d5"),Protocol.bytes(proof,"sessionHmac",32));
        r.put("deviceNonce",Protocol.b64(seq(97)));
        assertThrows(Exception.class,()->Protocol.proof(r,Protocol.join(seq(0),seq(32))));
    }
    @Test public void independentWindowsAesVector() throws Exception {
        byte[] frame=hex("000102030405060708090a0b564911ad984e70eec1cba73944f414b63ede006859fe405329bb951cec1164b47396e4fe864d16d364d02942");
        assertArrayEquals(Protocol.text("{\"operation\":\"authenticate\"}"),Protocol.crypt(false,frame,seq(0),seq(32),"request"));
    }
    @Test public void encryptedFramesRejectTamperingDirectionAndStaleChallenge() throws Exception {
        byte[] plain=Protocol.text("hello"),key=seq(0),challenge=seq(64);
        byte[] sealed=Protocol.crypt(true,plain,key,challenge,"request");
        assertArrayEquals(plain,Protocol.crypt(false,sealed,key,challenge,"request"));
        assertThrows(Exception.class,()->Protocol.crypt(false,sealed,key,challenge,"response"));
        assertThrows(Exception.class,()->Protocol.crypt(false,sealed,key,seq(65),"request"));
        sealed[20]^=1;
        assertThrows(Exception.class,()->Protocol.crypt(false,sealed,key,challenge,"request"));
    }
    @Test public void reassemblesMaximumFrameAndRejectsReordering() throws Exception {
        byte[] payload=Protocol.random(4100),id=new byte[8];
        List<byte[]> packets=Protocol.packets(2,id,payload,20);
        Protocol.Receiver receiver=new Protocol.Receiver();Protocol.Message m=null;
        for(byte[] p:packets)m=receiver.append(p);
        assertNotNull(m);assertArrayEquals(payload,m.payload());
        assertThrows(Exception.class,()->new Protocol.Receiver().append(packets.get(1)));
        assertThrows(Exception.class,()->Protocol.unframe(new byte[5]));
        byte[] response=Protocol.random(250);
        for(int size:new int[]{20,182,512}){
            List<byte[]> fragments=Protocol.packets(2,id,response,size);
            Protocol.Receiver reader=new Protocol.Receiver();Protocol.Message result=null;
            for(byte[] fragment:fragments){assertTrue(fragment.length<=size);result=reader.append(fragment);}
            assertNotNull(result);assertArrayEquals(response,result.payload());
            if(size==512)assertEquals(1,fragments.size());
        }
    }
    @Test public void grantIsBoundExpiringAndSingleUse(){
        Protocol.Grant g=new Protocol.Grant();g.give("pc",seq(64),1000);
        assertTrue(g.pending(1001));assertFalse(g.pending(16000));
        assertTrue(g.consume("pc",seq(64),1001));assertFalse(g.pending(1001));assertFalse(g.consume("pc",seq(64),1002));
        g.give("pc",seq(64),1000);assertFalse(g.consume("other",seq(64),1001));assertFalse(g.consume("pc",seq(64),1002));
        g.give("pc",seq(64),1000);assertFalse(g.consume("pc",seq(64),16000));
    }
    @Test public void invitationValidation() throws Exception {
        JSONObject j=new JSONObject().put("version",1).put("transport","windows-ble").put("deviceId","a".repeat(32)).put("secret",Protocol.b64(seq(0))).put("expires",1100);
        assertEquals("windows-ble",Protocol.invitation("cdfpair:"+j,1000).getString("transport"));
        assertThrows(Exception.class,()->Protocol.invitation("cdfpair:"+j,1100));
        j.put("transport","http");assertThrows(Exception.class,()->Protocol.invitation("cdfpair:"+j,1000));
    }
}
