/*********************************************************************************************************************************************************
	Goldsmiths, University of London
	IS53012B/S: Computer Security (2019-20)
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
	2) Both prime numbers p and q would be chosen privately and discarded after e and d are calculated.
	3) d value is private so only the sender has it/has access to it. n and e are public. 
	4) We are aware that our function getRandomE() is very inefficient as it stores all e values in an ArrayList - this is only for demo purposes.
	5) In the real world, for any random number generation, e.g generating a random prime number, there are specific cryptographically secure ways
	   of generating truly random numbers. Random functions built into java are not cryptographically secure. 
*********************************************************************************************************************************************************/




/********************************************************************************************************************************************************
*************************THIS IS A HELPER CLASS FOR OUR NSPK PROTOCOL. IT IS A STRIPPED DOWN VERSION OF OUR RSA ALGORITHM!*****************************
*********************************************************************************************************************************************************/
import java.io.*;
import java.math.*;
import java.util.*;

public class RSA_Helper {
	//Declare variables for p, q, n, phin and e
	long p;
	long q;
	long n;
	long phin; 
	long e;
	long d;

	public RSA_Helper() {
		p = findPrime(250); //Generate a random prime number within 1000
		q = findPrime(250); //Generate a second random prime number within 1000
		n = calculateN(p, q); //Calculate n and store it in a variable
		phin = calculatePhi(p, q); //Calculate phin and store it in a variable
		e = getRandomE(phin); //Get an number that is relatively prime to n
		d = getInverse(phin, e); //Calculate the d value which is the modular inverse of (e,φ(n)) and save it in variable
	}

	/*
		This function is a getter
		It simply returns d
	*/
	public long getD() {
		return d;
	}

	/*
		This function is a getter
		It simply returns n
	*/
	public long getN() {
		return n;
	}

	/*
		This function is a getter
		It simply returns e
	*/
	public long getE() {
		return e;
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
		while(b != 0)
		{
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
}