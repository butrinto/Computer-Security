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

public class Server {
	private String serverName; //Variable stores server name
	ArrayList<Long> publicKeyArr; // Create an ArrayList object
	private Person a, b; //Create 2 person objects
    RSA_Helper rsa; //Create RSA instance

    /*
		Constructor to instantiate a server object 
		It takes 3 parameters, serverName, and the 2 persons that want to communiate with each other, person a, person b
	*/
    public Server(String serverName, Person a, Person b) {
    	this.serverName = serverName; //Assigns server name to variable
        this.rsa = new RSA_Helper(); //Creates new RSA instance for server, this gives us the servers public and private key
    	this.a = a; //Assigns person a to variable
    	this.b = b; //Assigns person b to variable
    }

    /*
		This function returns the public key of a person- only for servers use so can be declared as private
		It takes 1 parameters - a person object that you want the public key of
		It returns the public key in the form of an ArrayList object
	*/
    public ArrayList<Long> getPublicKey(Person p) {
        publicKeyArr = new ArrayList<Long>(); //Creates new arraylist
        publicKeyArr.add(p.getE()); //Adds e value of person to arraylist
        publicKeyArr.add(p.getN()); //Adds n value of person to arraylist

        return publicKeyArr; //Returns the public key
    }

    /*
		This function returns the public key of the server
		It returns the public key in the form of an ArrayList object
	*/
    public ArrayList<Long> serverGetPublicKey() {
        publicKeyArr = new ArrayList<Long>(); //Creates new arraylist
        publicKeyArr.add(this.getE()); //Adds e value of server to arraylist
        publicKeyArr.add(this.getN()); //Adds n value of server to arraylist

        return publicKeyArr; //Returns the public key
    }

    /*
		This function is used when a person requests the public key of another person from the server,
		the server encrypts the key with its private key and returns they key
		It takes 1 parameters - a person object that you want the public key of
	*/
    public ArrayList<BigInteger> requestKey(Person p){
        ArrayList<BigInteger> encryptedKey = new ArrayList<BigInteger>(); //Create new arraylist to store the encrypted key

        long personPKE = getPublicKey(p).get(0); //Get the public key pair of the person requested
        long personPKN = getPublicKey(p).get(1); //Get the public key pair of the person requested

        long serverPrivateKey1 = rsa.getD(); //Get the servers private key
        long serverPrivateKey2 = this.getN(); //Get the servers private key

        //This is essentially the RSA encryption algorithm happening (m^e mod n)
        BigInteger encryptedEVal = ((BigInteger.valueOf(personPKE)).pow((int)serverPrivateKey1).mod(BigInteger.valueOf(serverPrivateKey2))); //RSA encryption m^e mod n
        BigInteger encryptedNVal = ((BigInteger.valueOf(personPKN)).pow((int)serverPrivateKey1).mod(BigInteger.valueOf(serverPrivateKey2))); //RSA encryption m^e mod n
        
        encryptedKey.add(encryptedEVal); //Add the encrypted key pair to the arraylist
        encryptedKey.add(encryptedNVal); //Add the encrypted key pair to the arraylist

        return encryptedKey; //Return the arraylist
    }

    /*
    	This is a getter that returns the RSA e value
    */
    public long getE(){
        return rsa.getE();
    }

    /*
    	This is a getter that returns the RSA n value
    */
    public long getN(){
        return rsa.getN();
    }
}