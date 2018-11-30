import java.lang.System;
import java.util.Arrays;

public class AuthDecryptor implements Proj1Constants {
	// This class is used to decrypt and authenticate a sequence of values that were encrypted 
	//     by an AuthEncryptor.

	StreamCipher streamCipher;
	private static int macLen = PRFOutputSizeBytes;
	private byte[] macKey;

	public AuthDecryptor(byte[] key) {
		assert key.length == KeySizeBytes;

		// IMPLEMENT THIS
		streamCipher = new StreamCipher(key);

		PRF prf = new PRF(key);
		macKey = prf.eval(key);
	}

	public byte[] decrypt(byte[] in, byte[] nonce, boolean nonceIncluded) {
		// Decrypt and authenticate the contents of <in>.  The value passed in will normally
		//    have been created by calling encrypt() with the same nonce in an AuthEncryptor 
		//    that was initialized with the same key as this AuthDecryptor.
		// If <nonceIncluded> is true, then the nonce has been included in <in>, and
		//    the value passed in as <nonce> will be disregarded.
		// If <nonceIncluded> is false, then the value of <nonce> will be used.
		// If the integrity of <in> cannot be verified, then this method returns null.   Otherwise it returns 
		//    a newly allocated byte-array containing the plaintext value that was originally 
		//    passed to encrypt().

		int inputlength = in.length - macLen;
		if (nonceIncluded){
			inputlength -= nonce.length;
		}
		byte[] ciphertext = new byte[inputlength];
		byte[] inputmac = new byte[macLen];
		byte[] inputnonce = new byte[NonceSizeBytes];
		System.arraycopy(in, 0, ciphertext, 0, inputlength);
		System.arraycopy(in, inputlength, inputmac, 0, macLen);
		if (nonceIncluded){
			System.arraycopy(in, inputlength + macLen, inputnonce, 0, NonceSizeBytes);
		} else {
			System.arraycopy(nonce, 0, inputnonce, 0, NonceSizeBytes);
		}
		// Check for MAC consistency
		PRF prf = new PRF(macKey);
		byte[] macText = prf.eval(ciphertext);
		if (Arrays.equals(macText, inputmac)){
			streamCipher.setNonce(inputnonce);
			byte[] output = new byte[ciphertext.length];
			streamCipher.cryptBytes(ciphertext, 0, output, 0, ciphertext.length);
			return output;
		} else {
			return null;
		}
	}

	// Testing for encryptor / decryptor
	public static void main(String[] args) {          
		byte[] key = new byte[KeySizeBytes];
		for(int i=0; i<KeySizeBytes; ++i){    
			key[i] = (byte)(i+1);
		}
		byte[] nonce = new byte[NonceSizeBytes];
		for (int i=0;i<NonceSizeBytes;i++){ 
			nonce[i]=(byte)(i+5); 
		}
		byte[] testbytes = {(byte) 0x3F, (byte) 0xCB, (byte) 0x94};
		for (int i=0;i<testbytes.length;i++){ 
			System.out.print(testbytes[i] + " ");
		}
		System.out.println("");
		// Test encryption
		AuthEncryptor encryptor = new AuthEncryptor(key);
		byte[] testcipher = encryptor.encrypt(testbytes, nonce, true);
		for (int i=0;i<testbytes.length;i++) {
			System.out.print(testcipher[i] + " ");
		}
		System.out.println("");
		AuthDecryptor decryptor = new AuthDecryptor(key);
		byte[] testdecipher = decryptor.decrypt(testcipher, nonce, true);
		for (int i=0;i<testbytes.length;i++) {
			System.out.print(testdecipher[i] + " ");
		}
		System.out.println("");
	} //  Encrypts and decrypts correctly, also tested for null cases
}