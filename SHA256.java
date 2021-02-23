package hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import junit.framework.Assert;

import org.junit.Test;

public class SHA256 {
    private static final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf,
            0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
            0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
            0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
            0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
            0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
            0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
            0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2 };

    private static final int[] H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
            0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    private int sigma0(int x) {
        return rotr(7, x) ^ rotr(18, x) ^ (x >>> 3);
    }

    private int sigma1(int x) {
        return rotr(17, x) ^ rotr(19, x) ^ (x >>> 10);
    }

    private int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    private int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private int sum0(int x) {
        return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
    }

    private int sum1(int x) {
        return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
    }

    private int rotr(int r, int x) {
        final int rot = r % 32;
        return (x >>> rot) | (x << (32 - rot));
    }

    private void hashBlock(int[] h_, byte[] data, int offset) {
        int[] w = new int[64];
        for (int i = 0; i < 16; i++)
            w[i] = (data[offset + i * 4] & 0xff) << 24
                    | (data[offset + i * 4 + 1] & 0xff) << 16
                    | (data[offset + i * 4 + 2] & 0xff) << 8
                    | data[offset + i * 4 + 3] & 0xff;

        for (int t = 16; t < 64; t++) {
            w[t] = sigma1(w[t - 2]) + w[t - 7] + sigma0(w[t - 15]) + w[t - 16];
        }

        int a = h_[0];
        int b = h_[1];
        int c = h_[2];
        int d = h_[3];
        int e = h_[4];
        int f = h_[5];
        int g = h_[6];
        int h = h_[7];

        for (int t = 0; t < 64; t++) {
            int temp1 = h + sum1(e) + ch(e, f, g) + K[t] + w[t];
            int temp2 = sum0(a) + maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += h;
    }

    public int[] hash(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException();
        }

        final int[] h = SHA256.H.clone();
        int i;
        for (i = 0; i <= data.length - 64; i += 64) {
            this.hashBlock(h, data, i);
        }

        final byte[] tmp = new byte[64];
        final int remains = data.length - i;
        System.arraycopy(data, i, tmp, 0, remains);
        tmp[remains] = (byte) 0x80;

        if (remains > 64 - 8 - 1) {
            Arrays.fill(tmp, remains + 1, 64, (byte) 0);
            this.hashBlock(h, tmp, 0);
            Arrays.fill(tmp, 0, 64 - 8, (byte) 0);
        } else {
            Arrays.fill(tmp, remains + 1, 64 - 8, (byte) 0);
        }

        final long len = (long) data.length * 8;
        tmp[56] = (byte) (len >> 56);
        tmp[57] = (byte) (len >> 48);
        tmp[58] = (byte) (len >> 40);
        tmp[59] = (byte) (len >> 32);
        tmp[60] = (byte) (len >> 24);
        tmp[61] = (byte) (len >> 16);
        tmp[62] = (byte) (len >> 8);
        tmp[63] = (byte) len;
        this.hashBlock(h, tmp, 0);

        return h;
    }

    @Test
    public void test1() throws NoSuchAlgorithmException {
        final String text = "The quick brown fox jumps over the lazy dog";
        final int[] hashval = new int[] { 0xd7a8fbb3, 0x07d78094, 0x69ca9abc,
                0xb0082e4f, 0x8d5651e4, 0x6d3cdb76, 0x2d02d0bf, 0x37c9e592 };

        final int[] sha256hash0 = this.hash(text.getBytes());
        Assert.assertTrue(Arrays.equals(sha256hash0, hashval));

        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text.getBytes(), 0, text.length());
        final byte[] sha256hash1 = md.digest();
        Assert.assertTrue(Arrays.equals(sha256hash1, this.toByteArray(hashval)));

    }

    @Test
    public void test2() throws NoSuchAlgorithmException {
        final String text = "The quick brown fox jumps over the lazy cog";
        final int[] hashval = new int[] { 0xe4c4d8f3, 0xbf76b692, 0xde791a17,
                0x3e053211, 0x50f7a345, 0xb46484fe, 0x427f6acc, 0x7ecc81be };

        final int[] sha256hash0 = this.hash(text.getBytes());
        Assert.assertTrue(Arrays.equals(sha256hash0, hashval));

        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text.getBytes(), 0, text.length());
        final byte[] sha256hash1 = md.digest();
        Assert.assertTrue(Arrays.equals(sha256hash1, this.toByteArray(hashval)));
    }

    @Test
    public void test3() throws NoSuchAlgorithmException {
        final String text = "";
        final int[] hashval = new int[] { 0xe3b0c442, 0x98fc1c14, 0x9afbf4c8,
                0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855 };

        final int[] sha256hash0 = this.hash(text.getBytes());
        Assert.assertTrue(Arrays.equals(sha256hash0, hashval));

        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text.getBytes(), 0, text.length());
        final byte[] sha256hash1 = md.digest();
        Assert.assertTrue(Arrays.equals(sha256hash1, this.toByteArray(hashval)));
    }

    private byte[] toByteArray(final int[] src) {
        final byte[] dst = new byte[src.length * 4];
        for (int i = 0; i < src.length; i++) {
            dst[i * 4] = (byte) (src[i] >> 24);
            dst[i * 4 + 1] = (byte) (src[i] >> 16);
            dst[i * 4 + 2] = (byte) (src[i] >> 8);
            dst[i * 4 + 3] = (byte) src[i];
        }
        return dst;
    }

    public static void main(String[] argv) throws Exception {
        byte[] buf = new byte[BUFSIZE];
        int top = 0;
        int limit = BUFSIZE;
        int len;
        while ((len = System.in.read(buf, top, limit)) != -1) {
            byte[] tmp = new byte[top + len + BUFSIZE];
            System.arraycopy(buf, 0, tmp, 0, top + len);
            buf = tmp;
            top = top + len;
            limit = BUFSIZE;
        }
        byte[] tmp = new byte[top];
        System.arraycopy(buf, 0, tmp, 0, top);

        final int[] sha256hash = new SHA256().hash(tmp);

        boolean firstElementP = true;
        for (int v : sha256hash) {
            if (firstElementP) {
                firstElementP = false;
            } else {
                System.out.print(" ");
            }
            System.out.print(Integer.toHexString(v));
        }
        System.out.println();
    }

    static final int BUFSIZE = 256;
}
