package hash;

import java.security.MessageDigest;
import java.util.Arrays;

import junit.framework.Assert;
import org.junit.Test;

public class HMAC {
    public static byte[] HMAC(byte[] data, byte[] key,
            String hash_name, int block_size) {
        byte[] result = new byte [0];
        try{
            MessageDigest md_outer = MessageDigest.getInstance(hash_name);
            MessageDigest md_inner = (MessageDigest) md_outer.clone();
            byte[] opad = new byte [block_size];
            byte[] ipad = new byte [block_size];
            Arrays.fill(ipad, (byte) 0x36);
            Arrays.fill(opad, (byte) 0x5c);
            byte[] k0   = new byte [block_size];
            Arrays.fill(k0,   (byte) 0);
            System.arraycopy(key, 0, k0, 0, key.length);
            for (int i = 0; i < block_size; i++) {
                opad[i] ^= k0[i];
                ipad[i] ^= k0[i];
            }
            md_inner.update(ipad);
            byte[] inner = md_inner.digest(data);
            md_outer.update(opad);
            result = md_outer.digest(inner);
        }catch(Exception e){
            System.out.println(e);
        }
        return result;
    }

    public static byte [] string2byte(String from){
        int i;
        byte [] to = new byte [from.length()/2];
        for (i=0; i<from.length()/2; i++){
            to[i] = (byte) (Integer.parseInt(from.substring(2*i, 2*(i+1)), 16) & 0xFF);
        }
        return to;
    }
    public static String byte2string(byte [] from){
        int i, tmp;
        String to = new String();
        for (i=0; i<from.length; i++){
             tmp = (int) from[i] & 0xFF;
             if (tmp < 16)
                 to = to + "0" + Integer.toHexString(tmp);
             else
                 to = to + Integer.toHexString(tmp);
        }
        return to;
    }

    @Test
    public void test() throws Exception {
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        byte[] data = new byte[9];
        byte[] truth= string2byte("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        data = "Hi There".getBytes();
        byte[] result = HMAC(data, key, "SHA-256", 64);
        for (int i=0; i<result.length; i++)
            Assert.assertEquals(result[i], truth[i]);
    }
}

