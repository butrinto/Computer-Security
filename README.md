# Data and Machine Learning

This document outlines the RSA algorithm and the Needham-Schroeder Protocol. 

In the first part we go through the RSA algorithm and how it works and then provide an example using Alice and Bob notation. We then discuss how Charlie (the hacker) can brute force RSA if they keys aren’t large enough. We then go onto explain our own basic Java implementation of the RSA protocol and finally we discuss trusted servers and our implementation of the NSPK protocol.

[Installation](#Installation) | [What does it do?](#Java1) | [How does it work?](#Java2) |

Technologies: Java, Needham-Schroeder Protocol, RSA Alogrithm

## <a name="Installation">Installation</a>

### To run PART 1 (RSA):
`java RSAAlgorithm` in terminal from the /code directory

### To run PART 2 (NSPK):
`java NSPK` in terminal from the /code directory

## <a name="Java1">Computer Security — How does it work?</a>

Scenario: Alice wants to send a message to Bob. The message contains the date of a secret
coursework deadline: 1303

### 1. Encryption

<i>Note: For the example we will be using small prime numbers so it is easy to compute but RSA in
real life uses huge prime numbers</i>

Bob generates his public/private key pair
First he generates 2 random prime numbers <i>(p, q)</i> and calculates <i>n</i>
<p align="center"><i>
p = 71, q = 41
</p></i>
<p align="center"><i>
n = 2911 (because 71 ∗ 41)
</p></i>

Next he calculates <i>φ(n)</i>
<p align="center"><i>
φ(n) = 2800 (because (71 − 1) ∗ (41 − 1))
</p></i>

He then selects a random e between 1 and φ(n) that’s relatively prime to φ(n)
The e we have chosen at random is:
<p align="center"><i>
e = 2473
</p></i>

Bob now has his public key that he can share to the world:
<p align="center"><i>
publickey = (2473, 2911)
</p></i>

Alice now uses Bob’s public key to encrypt the date of the secret deadline: 1303
<p align="center"><i>
1303<sup>2473</sup> mod 2911 = 360
</p></i>
<p align="center"> <b>
THE CIPHER TEXT IS 360
</p></b>

### 2. Decryption

Bob receives the cipher text 360 and wants to decrypt it to get the original message Alice
sent him.

Bob calculates <i>d</i> which is the inverse of <i>e</i>
<p align="center"><i>
d = 137
</p></i>

Bob now has his private key which only he knows:
<p align="center"><i>
privatekey = (137, 2911)
</p></i>

To decrypt the message he uses his private key:
<p align="center"><i>
(360<sub>137</sub>) mod 2911 = 1303
</p></i>

<p align="center"> <b>
THE ORIGINAL MESSAGE IS 1303
</p></b>

<b>Bob now knows the date of the secret coursework deadline</b>

### 3. Special Case - Charlie The Hacker

If the values for p and q are too small, Charlie can use brute force techniques and find d and ultimately decipher the message. Below outlines some steps Charlie can take:

1) We must assume that Charlie knows e and n as they are public.
2) Charlie intercepts the cipher text
3) Charlie needs p and q to get the decryption key d
4) Charlie uses prime factorisation to find p and q from n
5) Charlie can now easily calculate φ(n) because he knows p and q
6) Charlie now has all the ingredients to find d, he has p, q, phi(n), n and e so he can calculate the inverse
7) Charlie decrypts the message

## <a name="Java2">Computer Security — What does it do?</a>


Below is the output of our program when you run it (RSAAlogrithm.java)

<p align="center">
  <img width="600" height="400" src=./images/RSA1.png>
</p>

The below snippet shows our implementation of the RSA encryption algorithm. The function takes a message m and encrypts itwith the RSA encryption algorithm - m<sub>e</sub>mod n. It returns the cipher text generated from the encryption.

```
/* This function encrypts the message, in other words, it turns plain text into cipher text
Input: It takes 3 parameters, e and n values and m
Output: It returns the cypher text
*/

static BigInteger encryption{long e, long n, String m)
{
  BigInteger message = new BigInteger(m);

  BigInteger result = (message.pow((int)e).mod(BigInteger.valueOf(n))); //Runs the actual encryption

  //Prints out the encryption key for demo purposes
  System.out.println("Encryption (public) key is: " + e + " (e), " + n + " (n)");
  //Prints out the cupher text
  System.out.println("--> Cipher text generated with encryption key: " + result + "\n!);

  return result; //Resturns the result - the cipher text
}
```


The below screenshot shows our implementation of the RSA decryption algorithm. The function takes a cipher text c and decrypts it with the RSA decryption algorithm - c<sub>d</sub>modn.
It returns the message/result generated from the decryption.

```
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
  ```
  

The below code shows our function to generate an e value. It takes φ(n) as input and checks if the greatest common divisor of each number from 2 to φ(n) and φ(n) is equal to 1. If it is, then it is a suitable candidate for e value. For demo purposes we keep a counter of all suitable e values and store all suitable candidates in an arraylist and randomly pick out a suitable value from that list.

```
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
```

For full code breakdown and review, please refer to our Report - detailed below:

[Computer_Security_Report.pdf](https://github.com/butrinto/Computer-Security/files/10547792/Computer_Security_Report.pdf)


