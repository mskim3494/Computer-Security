import java.lang.System;
import java.util.Arrays;

public class AuthEncryptor implements Proj1Constants {
	// This class is used to compute the authenticated encryption of values.  
	//     Authenticated encryption protects the confidentiality of a value, so that the only 
	//     way to recover the initial value is to do authenticated decryption of the value using the 
	//     same key and nonce that were used to encrypt it.   At the same time, authenticated encryption
	//     protects the integrity of a value, so that a party decrypting the value using
	//     the same key and nonce (that were used to decrypt it) can verify that nobody has tampered with the
	//     value since it was encrypted.

	private static int macLen = PRFOutputSizeBytes;
	StreamCipher streamCipher;
	private byte[] macText;
	private byte[] macKey;
	
	public AuthEncryptor(byte[] key) {
		assert key.length == KeySizeBytes;

		// IMPLEMENT THIS
		streamCipher = new StreamCipher(key);

		PRF prf = new PRF(key);
		macKey = prf.eval(key);
	}

	public byte[] encrypt(byte[] in, byte[] nonce, boolean includeNonce) {
		// Encrypts the contents of <in> so that its confidentiality and 
		//    integrity are protected against would-be attackers who do 
		//    not know the key that was used to initialize this AuthEncryptor.
		// Callers are forbidden to pass in the same nonce more than once;
		//    but this code will not check for violations of this rule.
		// The nonce will be included as part of the output iff <includeNonce>
		//    is true.  The nonce should be in plaintext if it is included.
		//
		// This returns a newly allocated byte[] containing the authenticated
		//    encryption of the input.

		// Setting up the output
		int outputlen = in.length + macLen;
		if(includeNonce) {
			outputlen += nonce.length;
		}
		byte[] output = new byte[outputlen];
	
		// Encrypt the message
		byte[] ciphertext = new byte[in.length];
		streamCipher.setNonce(nonce);
		streamCipher.cryptBytes(in, 0, ciphertext, 0, in.length);

		// Encrypt the mackey and add it onto the output
		PRF prf = new PRF(macKey);
		macText = prf.eval(ciphertext);

		System.arraycopy(ciphertext, 0, output, 0, ciphertext.length);
		System.arraycopy(macText, 0, output, ciphertext.length, macText.length);
		if(includeNonce){
			System.arraycopy(nonce, 0, output, ciphertext.length + macText.length, nonce.length);
		}
		return output;  
	}
}