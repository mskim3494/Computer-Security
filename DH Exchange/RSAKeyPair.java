import java.math.BigInteger;

public class RSAKeyPair {
	private RSAKey publicKey;
	private RSAKey privateKey;

	private BigInteger p;
	private BigInteger q;

	public RSAKeyPair(PRGen rand, int numBits) {
		// Create an RSA key pair.  rand is a PRGen that this code can use to get pseudorandom
		//     bits.  numBits is the size in bits of each of the primes that will be used.

		// IMPLEMENT THIS
		p = Proj2Util.generatePrime(rand, numBits);
		q = Proj2Util.generatePrime(rand, numBits);
		BigInteger n = p.multiply(q);

		BigInteger one = BigInteger.ONE;
		BigInteger phi = (p.subtract(one)).multiply(q.subtract(one));
		BigInteger e = BigInteger.valueOf(65537); // from lecture slides
		BigInteger d = e.modInverse(phi);

		publicKey = new RSAKey(e, n);
		privateKey = new RSAKey(d, n);
	}

	public RSAKey getPublicKey() {
		return publicKey;
	}

	public RSAKey getPrivateKey() {
		return privateKey;
	}

	public BigInteger[] getPrimes() {
		// Returns an array containing the two primes that were used in key generation.
		//   In real life we don't always keep the primes around.
		//   But including this helps us grade the assignment.
		BigInteger[] ret = new BigInteger[2];
		ret[0] = p; // IMPLEMENT THIS
		ret[1] = q;
		return ret;
	}
}
