/*********************************************************************************************************************************************************
	Goldsmiths, University of London
	IS53012B/S: Computer Security (2019-20) Coursework Part 2
	Part of BSc Computer Science module Computer Security taught by Dr Ida Pu

	GROUP MEMBERS:
	Mohammed Tahmid - Student ID: 33595286, mtahm001@gold.ac.uk
	Dardan Quqalla - Student ID: 33498388, dquqa001@gold.ac.uk
	Butrint Termkolli - Student ID: 33551538, bterm001@gold.ac.uk

	NOTES & ASSUMPTIONS:
	- N/A 
*********************************************************************************************************************************************************/

import java.util.*; 
import java.math.*;

public class NSPK {
    public static void main(String[] args) {

    	//Create Alice and Bob persons and a Server
        Person alice = new Person("Alice");
        Person bob = new Person("Bob");
        Server server;
        
        /*
            This is a solution for a problem we ran into. In RSA the message should not be larger than the public key of the entity that’s encrypting the message. 
            In our case, the Server was encrypting the public key of Bob and sending it to Alice and vice-versa. 
            In some instances, the keys of Alice and Bob were larger than the Servers Public Key and therefore the cipher would not work properly. 
            We invented a quick work around to this, a simple if statement to check if Alices and Bobs keys are larger than the servers...
            ...if they are then keep on generating new keys until the keys of both parties are smaller than the server.
        */
        while (true) {
            server = new Server("Trusted Server", alice, bob); //Create new server with 2 new people
            
            if (server.getPublicKey(bob).get(0) > server.serverGetPublicKey().get(0) || 
                server.getPublicKey(bob).get(1) > server.serverGetPublicKey().get(1) || 
                server.getPublicKey(bob).get(1) > server.serverGetPublicKey().get(0) || 
                server.getPublicKey(bob).get(0) > server.serverGetPublicKey().get(1) ||
                server.getPublicKey(alice).get(0) > server.serverGetPublicKey().get(0) || 
                server.getPublicKey(alice).get(1) > server.serverGetPublicKey().get(1) || 
                server.getPublicKey(alice).get(1) > server.serverGetPublicKey().get(0) || 
                server.getPublicKey(alice).get(0) > server.serverGetPublicKey().get(1)) {

                bob.generateNewKeys();
                alice.generateNewKeys();
            } else {
                break;
            }
        }

        /*
        	Begin NSPK demo.
			These print statements are pretty self explanatory.
        */
        System.out.println("-----------------------------------------------------------------------");
        System.out.println("| FOR DEMO PURPOSES WE PRINT OUT EVERYONES PUBLIC KEYS AND NONCES |");
        System.out.println("-----------------------------------------------------------------------");

        System.out.println("Alices Public Key: " + server.getPublicKey(alice)); //Get Alice public key from server
        System.out.println("Bobs Public Key: " + server.getPublicKey(bob)); //Get Bob public key from server
        System.out.println("Servers Public Key: " + server.serverGetPublicKey()); //Get Server public key from server
        System.out.println("Alices Public Nonce: " + alice.getNonce()); //Get Alices unencrypted nonce from demonstration purposes
        System.out.println("Bobs Nonce: " + bob.getNonce()); //Get Bobs unencrypted nonce from demonstration purposes
        System.out.println("-----------------------------------------------------------------------");


        System.out.println("| PROTOCOL RUN |");
        System.out.println("-----------------------------------------------------------------------");

        ArrayList<BigInteger> bobKeyFromServerToAlice = server.requestKey(bob); //Server sends back Bobs public key encrypted with its private key to Alice
        ArrayList<BigInteger> aliceDecryptsBobsPublicKey = alice.decryptKeyFromServer(bobKeyFromServerToAlice, server); //Alice decrypts the servers message by using its public key to get Bobs key
        BigInteger alicesEncryptedNonce = alice.sendEncryptedNonce(bob, aliceDecryptsBobsPublicKey, alice.getNonce()); //Alice prepares to send her nonce to Bob encrypted with his public key

        System.out.println("1) Alices requests Bob public key from the server");
        System.out.println("2) Server sends back Bobs public key encrypted with the Servers private key " + bobKeyFromServerToAlice);
        System.out.println("---> Alice knows the servers public key so can decrypt the message to get Bobs public key " + aliceDecryptsBobsPublicKey + "\n");

        System.out.println("3) Alice sends her nonce encrypted with Bobs public key to Bob: " + alicesEncryptedNonce);

        BigInteger alicesNonceDecryptedByBob = bob.decryptNonce(alicesEncryptedNonce); //Bob decrypts Alices nonce using his private key
        System.out.println("---> On receipt, Bob decrypts Alices nonce with his private key: " + alicesNonceDecryptedByBob + "\n");
        System.out.println("4) Bob requests Alices public key from the server");
        ArrayList<BigInteger> alicesKeyFromServerToBob = server.requestKey(alice); //Server sends back Alices public key encrypted with its private key to Bob

        System.out.println("5) Server sends back Alices public key encrypted with the Servers private key " + alicesKeyFromServerToBob);
        ArrayList<BigInteger> bobDecryptsAlicesPublicKey = bob.decryptKeyFromServer(alicesKeyFromServerToBob, server); //Bob decrypts the servers message by using its public key to get Alices key
        System.out.println("---> Bob knows the servers public key so can decrypt the message to get Alices public key " + bobDecryptsAlicesPublicKey + "\n");
        BigInteger bobsEncryptedNonce = bob.sendEncryptedNonce(alice, bobDecryptsAlicesPublicKey, bob.getNonce()); //Bob prepares to send his nonce to Alice encrypted with her public key
        System.out.println("---> Bobs encrypts his nonce with Alices public key, so only she can decrypt it " + bobsEncryptedNonce);

        System.out.println("6) Bob sends one final message to Alice with her nonce and his encrypted nonce");
        ArrayList<BigInteger> bobSendsBothNoncesToAlice = bob.finalSend(alice, bobsEncryptedNonce, alicesNonceDecryptedByBob);
        System.out.println("---> Alices opens the message and finds her orignal nonce (which was decrypted by Bob) and she decrypts Bobs nonce using her private key " + bobSendsBothNoncesToAlice + "\n");

        System.out.println("7) Alice sends one final message to Bob containing his decrypted nonce encrypted with his public key, proving that she decrypted it");
        BigInteger aliceSendsBobHisNonce = alice.sendEncryptedNonce(bob, aliceDecryptsBobsPublicKey, bobSendsBothNoncesToAlice.get(0).longValue());
        System.out.println("---> The encrypted nonce Alice sends to Bob is " + aliceSendsBobHisNonce);
        System.out.println("---> Bob decrypts it with his private key to find " + bob.decryptNonce(aliceSendsBobHisNonce) + " his orignal nonce.");
    }

}