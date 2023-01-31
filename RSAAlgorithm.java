/*********************************************************************************************************************************************************
	Goldsmiths, University of London
	IS53012B/S: Computer Security (2019-20) Coursework Part 1
	Part of BSc Computer Science module Computer Security taught by Dr Ida Pu

	GROUP MEMBERS:
	Mohammed Tahmid - Student ID: 33595286, mtahm001@gold.ac.uk
	Dardan Quqalla - Student ID: 33498388, dquqa001@gold.ac.uk
	Butrint Termkolli - Student ID: 33551538, bterm001@gold.ac.uk

	CREDITS:
	- The modular exponentiation algorithm - modularExponentiation(), and the findPrime() function (which takes care of generating a random prime number)
	were taken and modified from the following URL: http://homepages.gold.ac.uk/rachel/CryptoTools.java
	- The gcd() function was taken and adapted from the following url: https://stackoverflow.com/a/4009247/2632390
	- getInverse() function was adapted from the algorithm Dr Ida Pu provided on learn.gold under week 5 of the course page.

	NOTES & ASSUMPTIONS:
	1) Our RSA implementation uses long values for simplicity. In real life, because numbers would be so large, you would use BigInteger.
	2) If the message value is above 2000 there is a chance it could cause a silent long overflow error. Again, using BigInteger would solve this.
	2) Both prime numbers p and q would be chosen privately and discarded after e and d are calculated.
	3) d value is private so only the sender has it/has access to it. n and e are public. 
	4) We are aware that our function getRandomE() is very inefficient as it stores all e values in an ArrayList - this is only for demo purposes.
	5) In the real world, for any random number generation, e.g generating a random prime number, there are specific cryptographically secure ways
	   of generating truly random numbers. Random functions built into java are not cryptographically secure. 
*********************************************************************************************************************************************************/

import java.io.*;
import java.math.*;
import java.util.*;

public class RSAAlgorithm {
	static long eCounter = 0; //A counter for the number of possible e values we can choose from. Used just for demonstration purposes.
	//Declare variables for p, q, n, phin and e
	long p;
	long q;
	long n;
	long phin; 
	long e;
	long d;

	public static void main(String[] args) {
		int num; //Declare variable for user input

		//Print statements for instuctions and scenario
		System.out.println("-------------------------------------------------------------------------------------------------");
		System.out.println("Hi and welcome to the RSA Algorithm.");
		System.out.println("To begin simulation, please enter the message you wish to encrypt.");
		System.out.println("NOTE: It must be a number below 1000");
		System.out.println("-------------------------------------------------------------------------------------------------\n");
		
		//While loop to make sure number is below 1000 to prevent message being larger than key because we're using long values
		do {
			Scanner scanner = new Scanner(System.in); //New scanner object
			num = scanner.nextInt(); //Save user input
			if(num > 1000) //Only display message if number above 1000
				System.out.println("\nYou did not enter number below 1000. Try again."); //Print error message if number above 1000
		} while (num > 1000); //Get user to try again if number above 1000

		RSAAlgorithm myRSA = new RSAAlgorithm(num); //Run new instance of the RSA Algorithm
	}

	public RSAAlgorithm(int userInput) {
		 p = findPrime(800); //Generate a random prime number within 1000
		 q = findPrime(800); //Generate a second random prime number within 1000
		 n = calculateN(p, q); //Calculate n and store it in a variable
		 phin = calculatePhi(p, q); //Calculate phin and store it in a variable
		 e = getRandomE(phin); //Get an number that is relatively prime to n

		//Printing out both prime numbers chosen for demonstation purposes
		System.out.println("-------------------------------------------------------------------------------------------------\n");
		System.out.println("The first prime number is: " + p);
		System.out.println("The second prime number is: " + q);

		//Printing out n and phin for demonstation purposes
		System.out.println("N is: " + n + " (because " + p + " * " + q + ")");
		System.out.println("Phi N is: " + phin + " (because Euler's Totient, " + p + "-1 * " + q + "-1)");		

		//Printing out E value chosen for demonstation purposes
		System.out.println("There are " + eCounter + " possible e values that are below " + phin +  " and coprime to " + phin);
		System.out.println("The E chosen at random is: " + e);

		d = getInverse(phin, e); //Calculate the d value which is the modular inverse of (e,φ(n)) and save it in variable
		System.out.println("The inverse (D) is calculated: " + d + "\n"); //Print out D value

		//MEESAGE TRANSMISION BEGINS HERE
		String message = Integer.toString(userInput); //This is the secret message to be sent. 
		//This just prints out the scenario
		System.out.println("-------------------------------------------------------------------------------------------------\n");
		System.out.println("Alice wants to send a message to Bob. The secret message is: " + message + "\n");
		System.out.println("1) Bob generates his public/private key pair. He shares his public key with the world and keeps his private key safe.");
		System.out.println("2) Alice uses Bobs public key to encrypt the message");
		System.out.println("3) Bob decrypts the message using his private key (" + d + ", " + n + ")"); 
		System.out.println("\n-------------------------------------------------------------------------------------------------\n");

		System.out.println("Original Message = " + message + "\n"); //Print out message
		BigInteger cipherText = encryption(e, n, message); //This runs the encrption function and turns the PLAIN TEXT into CIPHER TEXT
		
		decryption(d, n, cipherText); //This runs the decryption function and turns the CIPHER TEXT into PLAIN TEXT

		//CHARLIE BRUTE-FORCE EXAMPLE
		System.out.println("Charlie brute forces and finds the decryption key: " + charlieBruteForce(n, e) + " (d)\n");
	}

	/*
		This function calculates N
		It takes 2 parameters which are 2 prime numbers (p, q) and returns the product
	*/
	static long calculateN(long p, long q) {
		return p * q;
	}

	/*
		This function calculates φ(n)
		It takes 2 parameters which are 2 prime numbers (p, q) and returns φ(n)
	*/
	static long calculatePhi(long p, long q) {
		return (p-1) * (q-1);
	}

	/*
		This function encrypts the message, in other words, it turns plain text into cipher text
		Input: It takes 3 parameters, e and n values (which make up the public key of said person) and m, the message to be encrypted
		Output: It returns the cipher text
	*/
	static BigInteger encryption(long e, long n, String m) {
		BigInteger message = new BigInteger(m); //Convert the message to BigInteger so we can use it later

		BigInteger result = (message.pow((int)e).mod(BigInteger.valueOf(n))); //Run the actual encryption function which is ciphertext = m^e mod n

		// Prints out the encryption key for demo purposes
		System.out.println("Encryption (public) key is: " + e + " (e), " + n + " (n)");
		// Prints out the cipher text
		System.out.println("--> Cipher text generated with encryption key: " + result + "\n");

		return result; //Returns the result - the cipher text
	}

	/*
		This function decrypts the message, in other words, it turns cipher text back into plain text
		It takes 3 parameters, d and n values (which make up the private key of said person) and c, the cipher text to be decrypted
		Output: It returns the plain text message
	*/
	static String decryption(long d, long n, BigInteger cipherText) {
		BigInteger oriMessage = (cipherText.pow((int)d).mod(BigInteger.valueOf(n))); //Run the actual decryption function which is message = c^d mod n
		
		// Prints out the decryption key for demo purposes
		System.out.println("Decryption (private) key is: " + d + " (d), " + n + " (n)");
		// Prints out the message decrypted
		System.out.println("--> Result generated from using decryption key on cipher text: " + oriMessage + "\n");
		System.out.println("Bob now knows the secret message");
		System.out.println("\n-------------------------------------------------------------------------------------------------\n");
		
		return oriMessage.toString(); //Returns the result - the decrypted message
	}

	/*
		This is a helper function calcuates and returns the greatest common divisor of 2 numbers
		It takes 2 parameters (2 numbers) and it is used to help generate a suitable e value
		This one line gcd function was adapted from the following url: https://stackoverflow.com/a/4009247/2632390
	*/
	static long gcd(long a, long b) { 
		return (b != 0) ? gcd(b, a % b) : a; 
	} 

	/*
		This function calcuates a suitable e value
		It takes φ(n) as input and returns e value
		It checks if the greatest common divisor of phi and number i is equal to 1
	*/
	static long getRandomE(long phin) {
		ArrayList<Integer> eValueList = new ArrayList<Integer>(); //Creates a new arraylist
		for(int i = 2; i < phin; i++) { //Loops from 2 to the value of phi(n)
			if(gcd(phin, i) == 1) { //Checks if the greatest common dividor is 1
				eValueList.add(i); //If it is, adds it to the arraylist
				eCounter++; //Increments counter by 1, again, only for demo purposes
			}
		}
		Random rand = new Random(); //Creates new random object
		Integer randomEValue = eValueList.get(rand.nextInt(eValueList.size())); //Goes through the arraylist of possible e's and randomly picks an e
		return randomEValue; //Returns the random e value
	}

	/*
		This is the Extended Euclidean Algorithm
		This function calcuates the d value for RSA which forms the private key
		It takes 2 numbers (in the case of RSA, e and phi(n)) as parameters and returns the inverse
		The algorithm was provided by Dr Ida Pu under week 5 on learn.gold
	*/
   	static long getInverse(long a, long b) {
		long store = a, temp, q, r = 1, s = 0;
		int sign = 1;

		while(b != 0) {
			q = a/b;
			temp = r;
			r = temp*q+s;
			s = temp;
			temp = b;
			b = a-q*temp;
			a = temp;
			sign = -sign;
		}
		if(sign == -1) {
			s = b-s;
		}

		return (r-s) % store;
	}

	/*
		This function simply returns a prime number between 0 and the maximum number provided in the parameter
		It uses the modular eexponentiation algorithm Dr Ida Pu provided under week 5 on learn.gold
		This function was adapted from: http://homepages.gold.ac.uk/rachel/CryptoTools.java
	*/
	static long findPrime(long maximum) { 
		long primeFound = 0; //Initialise and set primeFound variable to 0
		boolean found = false; //Set found variable to false

		while (found == false) { //Run loop until prime is found

			long trialNumber = (long)(Math.random()*maximum); //Generate random number to test for primality
			found = true; //Assume the number we've generated is prime

			if (trialNumber % 2 == 0 || trialNumber == 1) { //Since prime numbers are odd except 2, check if the number is even
				found = false; //If it is, we have't found our prime
			} 

			if (modularExponentiation(2, trialNumber-1, trialNumber)!=1 || 
					(modularExponentiation(3, trialNumber-1, trialNumber)!=1 || 
						(modularExponentiation(5, trialNumber-1, trialNumber)!=1))) {
				found = false; //If not, then prime not found and we start again.
			}

			if (found == true) { //If the number passes the above checks, then the number is a prime
				primeFound = trialNumber; //Set the primeFound variable to that number
			}
		}
					
		return primeFound; //Return the prime number
	}

	/*
		This function is used to help find a suitable prime in the findPrime() function
		This is the modular eexponentiation algorithm Dr Ida Pu provided under week 5 on learn.gold
		This function was taken and adapted from: http://homepages.gold.ac.uk/rachel/CryptoTools.java
	*/
	public static long modularExponentiation(long x, long n, long m) {
		long y = 1, u = x % m;

		do {								
			if(n % 2 == 1) { //Check if n mod 2 is 1
				y = (y * u) % m; //if it is, set y to (y * (x%m)) % m
			}      
			n = (int)Math.floor(n/2); //divide n by 2
			u = (u * u) % m; //Set u to u*u mod m					   
		} while(n != 0); //loop as long as n not equal to 0

		return y; //return y
	}

	/*
		This function simulates Charlie The Hacker brute forcing the RSA algorithm when numbers are small
		Function takes n and e as arguments because we must assume Charlie knows n and e as they are public
		It returns the brute forced decryption key d
	*/
	public static long charlieBruteForce(long n, long e) {
		long originalN = n; //Creates a copy of n for demo purposes 
		ArrayList<Long> isPrime = new ArrayList<Long>(); //Store the factors in an arraylist

		//This for loop checks which numbers are prime factors of n
		for (long i = 2; i <= n; i++) { //Goes through all numbers from 2 till n
			if (n % i == 0) { //Checks if modulous equals to 0
				isPrime.add(i); //If it is a prime factor of n, then it adds it to the arraylist
				n = n/i; 
				i--;
			} 
		} 

		long charlieGetsPhiN = calculatePhi(isPrime.get(0), isPrime.get(1)); //Charlie now calcuates phiN because he know which 2 numbers are multiplied to get n
		long charlieHasE = e; //Charlie already knows e because e is public
		long charlieGetsD = getInverse(charlieGetsPhiN, e); //Charlie breaks RSA and gets the decryption key!

		//Print statements to simulate scenario
		System.out.println("Charlie the hacker can brute force RSA when prime numbers and keys are small.");
		System.out.println("--> Charlie finds the prime factors of n by using factorisation algorithm.\n");
		System.out.println("He finds that " + isPrime.get(0) + "*" + isPrime.get(1) + " is " + originalN + " (n)");
		System.out.println("He can now find phi(n): " + (isPrime.get(0)-1) + "*" + (isPrime.get(1)-1) + " = " + charlieGetsPhiN);
		System.out.println("Charlie now has p, q, n, phi(n), and e so get can get d.");

		return charlieGetsD; //Return the decryption key
	}

}