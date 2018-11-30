
public class StreamCipher implements Proj1Constants {
	// This class encrypts or decrypts a stream of bytes, using a stream cipher.

	private byte[] key;
	private boolean setFlag;
	private PRGen prgen;

	public StreamCipher(byte[] key) {
		// <key> is the key, which must be KeySizeBytes bytes in length.

		assert key.length == KeySizeBytes;
		this.key = key.clone();
		setFlag = false;
		// IMPLEMENT THIS
	}

	public void setNonce(byte[] arr, int offset){
		// Reset to initial state, and set a new nonce.
		// The nonce is in arr[offset] thru arr[offset+NonceSizeBytes-1].
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		// IMPLEMENT THIS
		PRF prf = new PRF(key);
		byte[] newseed = prf.eval(arr, offset, NonceSizeBytes);
		prgen = new PRGen(newseed);
		setFlag = true;
	}

	public void setNonce(byte[] nonce) {
		// Reset to initial state, and set a new nonce
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		assert nonce.length == NonceSizeBytes;
		setNonce(nonce, 0);
	}

	public byte cryptByte(byte in) {
		// Encrypt/decrypt the next byte in the stream
		assert setFlag;
		return (byte)(in ^ (prgen.next(8)));   // IMPLEMENT THIS
	}

	public void cryptBytes(byte[] inBuf, int inOffset, 
			byte[] outBuf, int outOffset, 
			int numBytes) {
		// Encrypt/decrypt the next <numBytes> bytes in the stream
		// Take input bytes from inBuf[inOffset] thru inBuf[inOffset+numBytes-1]
		// Put output bytes at outBuf[outOffset] thru outBuf[outOffset+numBytes-1];

		// IMPLEMENT THIS
		for(int i=0; i<numBytes; i++){
			outBuf[i+outOffset] = cryptByte(inBuf[i+inOffset]);
		}
	}
	public static void main(String[] argv) {
 		byte[] testkey = new byte[KeySizeBytes];
		for(int i=0; i<KeySizeBytes; ++i){    
			testkey[i] = (byte)(i+2);
		}
		byte[] nonce = new byte[StreamCipher.NonceSizeBytes];
		for (int i=0;i<StreamCipher.NonceSizeBytes;i++){ 
			nonce[i]=(byte)(i+3);
		}
		StreamCipher sc1 = new StreamCipher(testkey);
		StreamCipher sc2 = new StreamCipher(testkey);
		sc1.setNonce(nonce);
		sc2.setNonce(nonce);
		// Check for both encryption and decryption
		byte testbyte = (byte) 0xAB;
		System.out.println(testbyte);
		byte cryptbyte = sc1.cryptByte(testbyte);
		System.out.println(cryptbyte);
		System.out.println(sc2.cryptByte(cryptbyte));
        }
}
