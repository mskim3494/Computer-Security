
import java.security.SecureRandom;


public class TrueRandomness {
	// This class can stand in as a source of "true randomness." It allows a single
	// call to get() that returns NumBytes of random bytes.
	//
	// *** NOTES TO STUDENTS: ***
	// - YOU MAY NOT MODIFY THIS CLASS
	// - You may use this class to test your PRGen, StreamCipher, and AuthEncryptor/AuthDecryptor,
	// but YOU SHOULD NOT NEED IT TO IMPLEMENT THEM.

	public static final int NumBytes = 16;

	private static boolean alreadyUsed = false;

	public static byte[] get() {
		// Provides <NumBytes> bytes of (assumed to be) random data
		// This can only be called once; assertion will fail if called again

		assert !alreadyUsed;

		byte[] ret = new byte[NumBytes];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(ret);
		alreadyUsed = true;
		return ret;
	}
}