INTRO TO SECURITY PROJECT 3
mskim3494

This program implements the code designed to implement and study the workings of a secure channel abstraction that can be used by two programs, a client and a server, to communicate across the network by ensuring confidentiality and integrity of the messages. It uses as basis project1 and project2, which implement the PRF, PRGen, RSA key, and DH keys necessary for the implementation of a secure channel. 

The class InsecureChannel is the basic implementation of communication over a network, and SecureChannel extends such class to make any sort of communication secure. In this particular class, the constructor will take care of the initial handshake by exchanging nonces, starting with the client. The server then sends a message and a sign which use the random generator and RSA key that have been supplied. The client responds by sending a DH message which will then seed the encryption and decryption mechanisms. Authentication occurs by sending each other the HMAC(outMsg||signature||inMsg||nonce) and being able to verify it. Once verified, the two have now established a secure channel. 

In order to send or receive a message, a built-in message counter will ensure the integrity and order of the message, making sure that it has not been tampered with. Then, the total message to be encrypted is (msg||msgCount), encrypted using a nonce. 

Prerequisites

This program is compiled using Java 8.


Getting Started

In order to compile and run the program, all files in the project3 repository are needed. For Linux/Unix machines, the line

	javac -cp project1.jar:project2.jar:. [.java files] 

will compile the program. Then, to run a specific class,

	java -ea -cp project1.jar:project2.jar:. [main class]

For Windows machines, the same lines are used with the addition of quotation marks around the appropriate JAR files.


Running Tests

The ChannelTest class provides a demonstration that InsecureChannel works.
Similarly, SecureChannelTest provides a demonstration for SecureChannel.
