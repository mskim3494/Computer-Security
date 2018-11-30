
import java.util.Random;


public class PRGen extends Random implements Proj1Constants {
	// This implements a pseudorandom generator.  It extends java.util.Random, which provides
	//     a useful set of utility methods that all build on next(.).  See the documentation for
	//     java.util.Random for an explanation of what next(.) is supposed to do.
	// If you're calling a PRGen, you probably want to call methods of the Random superclass.
	//
	// There are two requirements on a pseudorandom generator.  First, it must be pseudorandom,
	//     meaning that there is no (known) way to distinguish its output from that of a
	//     truly random generator, unless you know the key.  Second, it must be deterministic, 
	//     which means that if two programs create generators with the same seed, and then
	//     the two programs make the same sequence of calls to their generators, they should
	//     receive the same return values from all of those calls.
	// Your generator must have an additional property: backtracking resistance.  This means that if an
	//     adversary is able to observe the full state of the generator at some point in time, that
	//     adversary cannot reconstruct any of the output that was produced by previous calls to the
	//     generator.
	
	private byte[] state = new byte[KeySizeBytes];

	public PRGen(byte[] seed) {
		super();
		assert seed.length == KeySizeBytes;

		// IMPLEMENT THIS
		PRF prf = new PRF(seed);
		state = prf.eval(seed);
	}

	protected int next(int bits) {
		// For description of what this is supposed to do, see the documentation for 
		//      java.util.Random, which we are subclassing.
		
		int mask = 0;
		for (int i=0; i<bits; i++){
			mask += Math.pow(2, i);
		}
		byte[] output = state.clone();
		// Advance state
		PRF prf = new PRF(state);
		state = prf.eval(state);
	
		// Turn the byte[] into a returnable int
		int ret = 0;
		int iterations = PRFOutputSizeBytes/8;
		for(int i=0; i < iterations; i++){
			ret = (ret << 8) + (output[i] & 0xFF);
		}
		return (ret & mask);   // IMPLEMENT THIS
	}
	// Testing PRGen for number of bits and implementation
	public static void main(String[] argv) {
		byte[] test = new byte[KeySizeBytes];
		// from PRF main
		for(int i=0; i<KeySizeBytes; i++){
				test[i] = (byte)(i+73); 
		}               
		PRGen prgen = new PRGen(test);
		for (int i=0; i<=KeySizeBytes; i++){
				System.out.println(prgen.next(i));   
		}
	}
}