
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;


public class SecureChannel extends InsecureChannel {
	// This is just like an InsecureChannel, except that it provides 
	//    authenticated encryption for the messages that pass
	//    over the channel.   It also guarantees that messages are delivered 
	//    on the receiving end in the same order they were sent (returning
	//    null otherwise).  Also, when the channel is first set up,
	//    the client authenticates the server's identity, and the necessary
	//    steps are taken to detect any man-in-the-middle (and to close the
	//    connection if a MITM is detected).
	//
	// The code provided here is not secure --- all it does is pass through
	//    calls to the underlying InsecureChannel.

	private PRGen prgen;
	private AuthEncryptor encryptor; // these are saved to prevent multiple object initialization
	private AuthDecryptor decryptor;
	private int receivedMsgCount = 0;
	private int sentMsgCount = 0;

	public SecureChannel(InputStream inStr, OutputStream outStr, 
			PRGen rand, boolean iAmServer,
			RSAKey serverKey) throws IOException {
		// if iAmServer==false, then serverKey is the server's *public* key
		// if iAmServer==true, then serverKey is the server's *private* key

		super(inStr, outStr);

		KeyExchange DHK = new KeyExchange(rand);
		prgen = rand;
		if(iAmServer){
			// Make a nonce exchange to ensure randomness
			byte[] serverNonce = new byte[AuthEncryptor.NonceSizeBytes];
			byte[] clientNonce = super.receiveMessage();
			prgen.nextBytes(serverNonce);
			super.sendMessage(serverNonce);
			// DH exchange
			byte[] outMsg = DHK.prepareOutMessage();
			byte[] sign = serverKey.sign(outMsg, prgen);
			super.sendMessage(outMsg);
			super.sendMessage(sign);
			// Get the response, and authenticate
			byte[] inMsg = super.receiveMessage();
			// https://stackoverflow.com/questions/5513152/easy-way-to-concatenate-two-byte-arrays
			// ^ source for easy byte array concatenation
			// outputStream contains client nonce, inputStream has servernonce used to authenticate
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(outMsg);
			outputStream.write(sign);
			outputStream.write(inMsg);
			outputStream.write(clientNonce);
			ByteArrayOutputStream inputStream = new ByteArrayOutputStream();
			inputStream.write(outMsg);
			inputStream.write(sign);
			inputStream.write(inMsg);
			inputStream.write(serverNonce);
			
			byte[] toVerify = Proj2Util.hash(inputStream.toByteArray());
			byte[] verificationOutput = Proj2Util.hash(outputStream.toByteArray());
			byte[] verificationInput = super.receiveMessage();
			// Authentication
			if(!(Arrays.equals(toVerify, verificationInput))){
				super.close();
			} 
			
			super.sendMessage(verificationOutput);
			encryptor = new AuthEncryptor(DHK.processInMessage(inMsg));
			decryptor = new AuthDecryptor(DHK.processInMessage(inMsg));
		} else {
			// Similar to server-side authentication, first exchange nonces
			byte[] clientNonce = new byte[AuthEncryptor.NonceSizeBytes];
			prgen.nextBytes(clientNonce);
			super.sendMessage(clientNonce);
			byte[] serverNonce = super.receiveMessage();
			// DH exchange
			byte[] inMsg = super.receiveMessage();
			byte[] sign = super.receiveMessage();
			if(!serverKey.verifySignature(inMsg, sign)){
				super.close();
			}
			byte[] outMsg = DHK.prepareOutMessage();
			super.sendMessage(outMsg);
			// Authenticate
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(inMsg);
			outputStream.write(sign);
			outputStream.write(outMsg);
			outputStream.write(serverNonce);
			ByteArrayOutputStream inputStream = new ByteArrayOutputStream();
			inputStream.write(inMsg);
			inputStream.write(sign);
			inputStream.write(outMsg);
			inputStream.write(clientNonce);
			//SecureChannelUtils.printByteArray(outMsg);
			//System.out.println("what am i doing");
			byte[] toVerify = Proj2Util.hash(inputStream.toByteArray());
			byte[] verificationOutput = Proj2Util.hash(outputStream.toByteArray());
			super.sendMessage(verificationOutput);
			byte[] verificationInput = super.receiveMessage();
			// Authentication
			if(!(Arrays.equals(toVerify, verificationInput))){
				super.close();
			} 
			
			encryptor = new AuthEncryptor(DHK.processInMessage(inMsg));
			decryptor = new AuthDecryptor(DHK.processInMessage(inMsg));
		}
	}

	public void sendMessage(byte[] message) throws IOException {
		// Message counter is included to prevent replay attacks
		// and to ensure the order of the messages received match
		this.sentMsgCount++;
		byte[] arrCount = new byte[4];
		for(int i=0; i<4; i++){
			arrCount[i] = (byte) (this.sentMsgCount >> (8*(4 - (i + 1))));
		} 
		// encrypt the message with the counter and random nonce
		byte[] nonce = new byte[AuthEncryptor.NonceSizeBytes];
		prgen.nextBytes(nonce);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(message);
		outputStream.write(arrCount);
		byte[] output = encryptor.encrypt(outputStream.toByteArray(), nonce, true);
		super.sendMessage(output);   
		return; // IMPLEMENT THIS
	}

	public byte[] receiveMessage() throws IOException {
		// reverse engineer sendMessage()
		// with the additional need to check message counter
		byte[] in = super.receiveMessage();
		this.receivedMsgCount++;
		byte[] inMsg = decryptor.decrypt(in, null, true);
		//SecureChannelUtils.printByteArray(inMsg);
		byte[] arrCount = new byte[4];
		int iCount = 0;
		System.arraycopy(inMsg, inMsg.length - 4, arrCount, 0, 4);
		// https://stackoverflow.com/questions/5399798/byte-array-and-int-conversion-in-java
		// ^ source for byte[] to int conversion
		for(int i=0; i<4; i++){
			iCount |= (arrCount[i] & 0xFF) << (4 - (i + 1));
		}
		if(this.receivedMsgCount != iCount){
			return null;
		} 
		int retlen = inMsg.length - 4;
		byte[] ret = new byte[retlen];
		System.arraycopy(inMsg, 0, ret, 0, retlen);
		return ret;   // IMPLEMENT THIS
	}
}
