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
