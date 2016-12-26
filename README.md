This is RSA-OAEP program   "Use Eclipse, Pleaseh, "read the last part of this file..."

Java specifications:
	Java data types are little bit different than other languages such as C, where Character is 16 bits, integer 32 bits

RSA-OAEP Specification:
	1- this program takes a message from user (14-character maximum) as input and does the following:
		a. Padding the message 
		b. Encrypt the padded message with 1024 bits primes and fixed value of e: 65537
		c. Decrypt the Encrypted message
		d. Depending the message
	2- the program will save everything except the output of the XOR results in text files, it is possible to access them outside the "src" folder
	3- the program is using outside files from other sources! the Credits of these supporting files will be at the end of this textfile
	4- wiener Attack is implemented to test if we can generate the secret key d, also indicates how well the primes are.

How to run:
	1- either import the jar file or import the RSA-OAEP folder as existing projects into workspace.
	2- Main class is MainRSA.java, run it as java application.
	3- no need external libraries
	4- console will show the output, and output folders will be saved outside src folder. 
		a. the files that being generated will replace each other every time you run the code!

Credits:
	used some methods from outside sources belongs to:
	1-  * First_1000_Primes.java: author Kim Dinh Son Email:sonkdbk@gmail.com 
	2- * GenPrime.java author Kim Dinh Son Email:sonkdbk@gmail.com

complementary materials:
	there will be two pictures of how the system flows, feel free to look at them. 


--------Issues:

	1- the exponent E is hardcoded, it is possible to be any prime,  2^k +1
	2- wiener attack will always fail since D > N^1/4 all the time due to the size of the exponent E is small

Thank you! =)

if needed more information feel free to contact me: amh-ahmad@hotmail.com 

