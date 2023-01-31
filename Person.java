/*********************************************************************************************************************************************************
    Goldsmiths, University of London
    IS53012B/S: Computer Security (2019-20) Coursework Part 2
    Part of BSc Computer Science module Computer Security taught by Dr Ida Pu

    GROUP MEMBERS:
    Mohammed Tahmid - Student ID: 33595286, mtahm001@gold.ac.uk
    Dardan Quqalla - Student ID: 33498388, dquqa001@gold.ac.uk
    Butrint Termkolli - Student ID: 33551538, bterm001@gold.ac.uk
*********************************************************************************************************************************************************/

import java.util.*;
import java.math.*;

public class Person {
	private String name; //Variable to store person name
	long nonce; //Variable to store person nonce
	RSA_Helper rsa; //Each person will need RSA public private keys

	/*
		Constructor to instantiate a person 
		It takes 1 parameter - name of the person
	*/
	public Person(String name) {
		this.name = name; //Assigns person name to variable
		this.rsa = new RSA_Helper(); //Creates new RSA instance for person, this gives us a public and private key for the person

		/*
			Generates a random nonce for the person between 1 and 50
		*/
		Random rand = new Random(); //New random object
		nonce = rand.nextInt((50 - 1) + 1) + 1; //Pick random number from 1 to 50 and let it be there nonce
	}

	/*
		This function generates new keys for a person.
        This is a solution for a problem we ran into. In RSA the message should not be larger than the public key of the entity that’s encrypting the message. 
        In our case, the Server was encrypting the public key of Bob and sending it to Alice and vice-versa. 
        In some instances, the keys of Alice and Bob were larger than the Servers Public Key and therefore the cipher would not work properly. 
        We invented a quick work around to this, a simple if statement to check if Alices and Bobs keys are larger than the servers...
        ...if they are then keep on generating new keys until the keys of both parties are smaller than the server.
    
	*/
	public void generateNewKeys() {
		this.rsa = new RSA_Helper();
	}

	/*
		Getters
	*/
	public long getNonce() {
		return nonce; //Returns the persons nonce
	}

	public String getName() {
		return name; //Returns the persons name
	}

    public long getE(){
        return rsa.getE(); //Returns the persons public key (e)
    }

    public long getN(){
        return rsa.getN(); //Returns the persons public key (n)
    }

    private long getD() {
    	return rsa.getD(); //Returns the persons private key (d) - note method is private
    }

    /*
		This function is used after a person has reqested another persons public key and the
		server has responded back with a encrypted version of the persons public key.
		The recipient will need to decrypt the key using the servers public key to retrive the
		other persons actual public key.
		Function takes 2 arguments - the encrypted key and the server it was send from
		It returns the decrypted public key
    */
    public ArrayList<BigInteger> decryptKeyFromServer(ArrayList<BigInteger> encryptedKey, Server s) {
    	ArrayList<BigInteger> decryptedKey = new ArrayList<BigInteger>(); //Arraylist to store the decrypted key

    	//Get the public key of the server
		BigInteger serverEValue = BigInteger.valueOf(s.serverGetPublicKey().get(0));
    	BigInteger serverNValue = BigInteger.valueOf(s.serverGetPublicKey().get(1));

    	//This is essentially the RSA decryption algorithm happening (c^d mod n)
    	//Decrypt key using the servers public key
    	BigInteger result = (encryptedKey.get(0).pow(serverEValue.intValue()).mod(serverNValue));
    	BigInteger result2 = (encryptedKey.get(1).pow(serverEValue.intValue()).mod(serverNValue));

    	//Add decrypted key to arraylist
    	decryptedKey.add(result);
    	decryptedKey.add(result2);

    	return decryptedKey; //Return the decrypted public key
    }

    /*
		This function simulates sending an encrypted nonce.
		It takes 3 arguments, the receiver (person), the key for the nonce to be encrypted with (this is
		going to be the recivers public key) and the nonce
		It returns the encrypted nonce
	*/
    public BigInteger sendEncryptedNonce(Person receiver, ArrayList<BigInteger> key, long nonce) {
    	//This is essentially the RSA encryption algorithm happening (m^e mod n)
    	BigInteger result = ((BigInteger.valueOf(nonce)).pow(key.get(0).intValue()).mod(key.get(1))); //Take the nonce and encrypt it with the public key
    	return result; //Return the encrypted nonce
    }

    /*
		This function decrypts the nonce using the persons private key
		It takes 1 argument - the nonce to decrypt
		It returns the decrypted nonce
	*/
    public BigInteger decryptNonce(BigInteger nonce) {
    	//This is essentially the RSA decryption algorithm happening (c^d mod n)
    	BigInteger result = (nonce.pow((int)this.getD()).mod(BigInteger.valueOf(this.getN()))); //Take the nonce and decrypt it with your own private key
    	return result; //Return the decrypted nonce
    }

	/*
		This function simulates step 6 of the protocol where person a sends back the decrypted nonce of the other party alongside
		their encrypted nonce using person b's public key.
		It takes 3 arguements, the reciver of the message, their own nonce encrypted with the other party's public key and the
		nonce of the other party that was decrypted by them.
		It returns 
	*/
    public ArrayList<BigInteger> finalSend(Person receiver, BigInteger encryptedNonce, BigInteger nonceOfOtherParty) {
    	ArrayList<BigInteger> results = new ArrayList<BigInteger>();

    	results.add(receiver.decryptNonce(encryptedNonce));
    	results.add(nonceOfOtherParty);

    	return results;
    }

}