import java.math.BigInteger;
import java.util.Arrays;

public class RSAKey {
    private BigInteger exponent;
    private BigInteger modulus;
    
    private static final int oaepK0SizeBytes = 32;
	private static final int oaepK1SizeBytes = 32;

    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null)    throw new NullPointerException();
        int totallen = (maxPlaintextLength() + oaepK0SizeBytes + oaepK1SizeBytes);
        byte[] encoded = new byte[totallen];
        encoded = encodeOaep(plaintext, prgen);

        BigInteger temp1, temp2;
        temp1 = Proj2Util.bytesToBigInteger(encoded);
        temp2 = temp1.modPow(exponent, modulus);

        return Proj2Util.bigIntegerToBytes(temp2, totallen); // IMPLEMENT THIS
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null)    throw new NullPointerException();
        int totallen = (maxPlaintextLength() + oaepK0SizeBytes + oaepK1SizeBytes);
        BigInteger temp1, temp2;
        temp1 = Proj2Util.bytesToBigInteger(ciphertext);
        temp2 = temp1.modPow(exponent, modulus);
        byte[] decoded = Proj2Util.bigIntegerToBytes(temp2, totallen);
        return decodeOaep(decoded); // IMPLEMENT THIS
    }

    public byte[] sign(byte[] message, PRGen prgen) {
        // Create a digital signature on <message>. The signature need
        //     not contain the contents of <message>--we will assume
        //     that a party who wants to verify the signature will already
        //     know which message this is (supposed to be) a signature on.
    	//
    	//     Note: The signature algorithm that we discussed in class is 
    	//     deterministic, and so if you implement it, you do not need 
    	//     to use the PRGen parameter. There is, however, a signature 
    	//     algorithm that is superior to the one that we discussed that 
    	//     does use pseudorandomness. Implement it for extra credit. See
    	//     the assignment description for details.
        if (message == null)    throw new NullPointerException();
        byte[] hashed = Proj2Util.hash(message);
        byte[] paddedhash = new byte[maxPlaintextLength()];
        paddedhash = addPadding(hashed);
        return encrypt(paddedhash, prgen); // IMPLEMENT THIS
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        // Verify a digital signature. Returns true if  <signature> is
        //     a valid signature on <message>; returns false otherwise.
        //     A "valid" signature is one that was created by calling
        //     <sign> with the same message, using the other RSAKey that
        //     belongs to the same RSAKeyPair as this object.
        if ((message == null) || (signature == null))    throw new NullPointerException();
        byte[] hashed = Proj2Util.hash(message);
        byte[] paddedhash = new byte[maxPlaintextLength()];
        paddedhash = addPadding(hashed);
        return Arrays.equals(decrypt(signature), paddedhash); // IMPLEMENT THIS
    }

    public int maxPlaintextLength() {
        // Return the largest x such that any plaintext of size x bytes
        //      can be encrypted with this key
        return (modulus.bitLength()/8) - 1 - oaepK0SizeBytes - oaepK1SizeBytes; // IMPLEMENT THIS
    }
       
    // The next four methods are public to help us grade the assignment. In real life, these would
    // be private methods as there's no need to expose these methods as part of the public API
    
    public byte[] encodeOaep(byte[] input, PRGen prgen) {
        // Following algorithm explained in class and Wikipedia page on OAEP
        int Xlen = maxPlaintextLength() + oaepK1SizeBytes;
        byte[] paddedinput = addPadding(input);
        byte[] r = new byte[oaepK0SizeBytes];
        // generate random r, use it to seed a PRGen
        prgen.nextBytes(r);
        PRGen G = new PRGen(r);
        byte[] Gr = new byte[Xlen];
        G.nextBytes(Gr);
        byte[] X = new byte[Xlen];
        // XOR the two arrays / can't find array mapping function on java API
        for(int i=0; i<Xlen; i++){
            X[i] = (byte) (paddedinput[i] ^ Gr[i]);
        }
        // feed the X into another PRGen to get Y -> by doing this,
        // effectively hashing and 'reducing' size of X, as explained by wikipedia
        PRGen H = new PRGen(X);
        byte[] Hx = new byte[oaepK0SizeBytes];
        H.nextBytes(Hx);
        // Get Y by XORing r and H(x)
        byte[] Y = new byte[oaepK0SizeBytes];
        for(int i=0; i<oaepK0SizeBytes; i++){
            Y[i] = (byte) (r[i] ^ Hx[i]);
        }
        // Get X || Y
        byte[] ret = new byte[Xlen + oaepK0SizeBytes];
        System.arraycopy(X, 0, ret, 0, Xlen);
        System.arraycopy(Y, 0, ret, Xlen, oaepK0SizeBytes);
        return ret; // IMPLEMENT THIS
    }
    
    public byte[] decodeOaep(byte[] input) {
        int Xlen = maxPlaintextLength() + oaepK1SizeBytes;
        byte[] X = new byte[Xlen];
        byte[] Y = new byte[oaepK0SizeBytes];
        System.arraycopy(input, 0, X, 0, Xlen);
        System.arraycopy(input, Xlen, Y, 0, oaepK1SizeBytes);
        // Got X and Y, decode. Basically encode backwards
        // Find r
        PRGen H = new PRGen(X);
        byte[] Hx = new byte[oaepK0SizeBytes];
        byte[] r = new byte[oaepK0SizeBytes];
        H.nextBytes(Hx);
        for(int i=0; i<oaepK0SizeBytes; i++){
            r[i] = (byte) (Y[i] ^ Hx[i]);
        }
        // Got r, find plaintext
        PRGen G = new PRGen(r);
        byte[] Gr = new byte[Xlen];
        byte[] ret = new byte[Xlen];
        G.nextBytes(Gr);
        for(int i=0; i<Xlen; i++){
            ret[i] = (byte) (X[i] ^ Gr[i]);
        }
        return ret; // IMPLEMENT THIS
    }
    
    public byte[] addPadding(byte[] input) {
        // fill up message to prevent msg being too short
        int inputlen = input.length;
        int maxlen = maxPlaintextLength();
        int lentopad = maxlen - inputlen;

        if (lentopad == 0){
            return input;
        } else {
            byte[] padding = new byte[lentopad];
            Arrays.fill(padding, (byte) 0);
            padding[0] = (byte) 1; // marker for start of pad
            byte[] ret = new byte[maxlen];
            System.arraycopy(input, 0, ret, 0, inputlen);
            System.arraycopy(padding, 0, ret, inputlen, lentopad);
            return ret;
        }
    }
    
    public byte[] removePadding(byte[] input) {
        int inputlen = input.length;
        int padpos = 0;
        for(int i=inputlen-1; i>=0; i--){
            if(input[i] == 1){
                padpos = i;
                break;
            }
        }
        byte[] ret = new byte[padpos - 1];
        System.arraycopy(input, 0, ret, 0, padpos-1);
        return ret; // IMPLEMENT THIS
    }

}
