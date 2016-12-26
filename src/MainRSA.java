/**
 * This is RSA-OAEP crypto system. For Comp4109 Project Demo
 * this system using RSA-2048 key with sha256
 * some files were used to support the functionality of this program
 *  
 * @author Ahmad Moneer Holpa , 100877933
 * 
 * design issues:
 * 1- The variables must be declared as private and passed between the function properly  ("getter/setters").
 * 2- modInverse,modPow and finding primes , was possible to be done without depending on external liberaries or files. However, due-
 * 		to the problems I was having in the previous team project and the time frame given , I needed to use external liberaries to do the three mentioned functions
 * 3- Java bit-size representations are different than other languages , Character are 16 bits and integers are 32 bits , hence the message will be encrypted will be smaller than other languages
 * 
 * 
 */

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


public class MainRSA {
	/**
	 * get the string 
	 * padding ! 
	 * encrypt
	 * 
	 * get the cipher 
	 * depadd
	 * string
	 */

	private List<BigInteger> a;
	private List<Fraction> b;
	private List<BigInteger> c;
	private List<BigInteger> dd;
	private String m="";
	private String r="";
	private String G="";
	private StringBuilder sb;
	private String X="" ;
	private String H="";
	private String Y="";
	private BigInteger n, d, e, p, q ,enc,dec;
	private int size;
	private int pass;// flag for passing weiner attack !

	/**
	 * 
	 * Constructor passing in message String
	 * @param m
	 */
	public MainRSA(String m)
	{
		a = new ArrayList<BigInteger>();
		b = new ArrayList<Fraction>();
		c = new ArrayList<BigInteger>();
		dd = new ArrayList<BigInteger>();
		this.m= m;
		pass=0;
	}

	/**
	 * this method is OAEP padding
	 * takes in message m and padd it depends on how long is that message
	 * then it follows OAEP scheme to get the padded(M) and Y
	 */
	public void padding()
	{
		System.out.println("the message is: "+m);
		size=this.m.length();
		while(m.length()<14)
		{
			m=m+"0";
		}
		if(m.length()>14)
		{
			System.out.println("you have passed the reccomended size  which is 16 character 16 * 16 = 256 bits I am using sha 256 bits !\n yes it might work but that will defeat the point of padding");

		}else
		{
			System.out.println("Padding starts");
			System.out.println(m);
			System.out.println("XOR the string with  Sha256(k0) where k0 = 0000000000000000 will get m which is the message will be encrypted by RSA");
			r= "0000000000000000";
			G=sha256(r);

			System.out.println("the value from Sha(r) is G = "+G);
			sb = new StringBuilder();
			for(int i = 0; i < m.length(); i++)
			{
				sb.append((char)(m.charAt(i) ^ G.charAt(i % G.length())));
			}
			X= sb.toString();
			System.out.println(X);
			H= sha256(X);
			System.out.println("getting the Y value by XOR k0 pre hash with sha256(m)");
			sb = new StringBuilder();
			for(int i = 0; i < r.length(); i++)
			{
				sb.append((char)(r.charAt(i) ^ H.charAt(i % H.length())));
			}
			Y = sb.toString();
			System.out.println(Y);
			System.out.println("\n-------padding is over ! time to RSA-------\n");
		}
	}
	/**
	 * this is RSA 2048 bit private key,  Primes are 1024 each
	 * it follows the TextBook RSA scheme in encrypt and decrypt
	 * and it generates text files outside the Src folder.
	 * @throws FileNotFoundException
	 * @throws UnsupportedEncodingException
	 */
	public void rsa() throws FileNotFoundException, UnsupportedEncodingException
	{
		//RSA TIME
		// make keys !
		do{
			p = new GenPrime().genPrime(1024);
			q = new GenPrime().genPrime(1024);

			System.out.println("bit length for P :"+p.bitLength()+"\n bit length for Q is: "+q.bitLength());
			e = new BigInteger("65537");		
			//System.out.println("primes are P: "+p+"\n"+"and Q:"+q);
			n=p.multiply(q);

			Wiener();
			if(pass==0)
			{
				System.out.println("failed to generate good primes, making new primes");
			}
		}while(p.compareTo(q)==-1 && pass==0);


		BigInteger pi = (p.subtract(BigInteger.ONE)).multiply(q
				.subtract(BigInteger.ONE));
		d=e.modInverse(pi);
		System.out.println("Public keys are : \n n:"+n+"\n e:"+e);
		System.out.println("Private keys are : \n p:"+p+"\n q:"+q+"\n d:"+d+"\n pi:"+pi);
		System.out.println("\nEncryption starting");
		m = new BigInteger(m.getBytes()).modPow(e, n).toString();
		System.out.println("encrypted message:"+m);
		PrintWriter writer = new PrintWriter("EnchM.txt", "UTF-8");
		writer.println("encrypted message: "+m);
		writer.close();
		System.out.println("encryption done ! Dec starting");

		m= new String((new BigInteger(m)).modPow(d, n).toByteArray());
		System.out.println("Decrypted message"+m);
		writer = new PrintWriter("DecM.txt", "UTF-8");
		writer.println("Decrypted message: "+m);
		writer.close();

		System.out.println("-------Writing into text files every run these files will be over written!--------");
		writer = new PrintWriter("publicKeys.txt", "UTF-8");
		writer.println("N= "+n);
		writer.println("\nE= "+e);
		writer.close();

		writer = new PrintWriter("privateKeys.txt", "UTF-8");
		writer.println("D= "+d);
		writer.println("\nP= "+p);
		writer.println("\nQ= "+q);
		writer.println("\nPI= "+pi);
		writer.close();
		System.out.println("------Done generating the public / private keys----");
		System.out.println("\n--------RSA DECRYPT IS OVER DEPADDING TIME-----------\n");
	}

	/**
	 * this method is the reverse of padding method
	 * @throws UnsupportedEncodingException 
	 * @throws FileNotFoundException 
	 */
	public void depadding() throws FileNotFoundException, UnsupportedEncodingException
	{
		// Depdadding
		System.out.println(" XOR  Y with sha256(hh) we will get k0");
		sb = new StringBuilder();
		for(int i = 0; i < Y.length(); i++)
		{
			sb.append((char)(Y.charAt(i) ^ H.charAt(i % H.length())));
		}
		r = sb.toString();
		System.out.println("value of r ="+r);

		System.out.println(" XOR  X with G we will get m padded");
		sb = new StringBuilder();
		for(int i = 0; i < X.length(); i++)
		{
			sb.append((char)(X.charAt(i) ^ G.charAt(i % G.length())));
		}
		m = sb.toString();
		System.out.println("value of m padded ="+m);
		m=m.substring(0, size);
		System.out.println("value of original message = "+m);
		PrintWriter writer = new PrintWriter("Final Message.txt", "UTF-8");
		writer.println("Final Message: "+m);
		writer.close();

	}

/*
 *    ---------MAIN------
 *    program starts here
 */
	public static void main(String[] args) throws Exception {

		String input;
		Scanner sc = new Scanner(System.in);
		boolean run=true;
		do{
			System.out.println("please input the String and must not pass 14 characters");
			input= sc.nextLine();
			if(input.length()<14)
			{
				System.out.println("the length of the input"+input.length());
				MainRSA test = new MainRSA(input);
				test.padding();
				test.rsa();
				test.depadding();
				input="";
				System.out.println("------------Done---------");
			}else
			{
				System.out.println("the input is bigger then 224 java-char bits try again please");
				//sc.close();
				input="";
			}
		}while(run);
		sc.close();
	}

	/**
	 * Sha256 function
	 * @param base - String
	 * @return String
	 */
	public String sha256(String base) {
		try{
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(base.getBytes("UTF-8"));
			StringBuffer hexString = new StringBuffer();

			for (int i = 0; i < hash.length; i++) {
				String hex = Integer.toHexString(0xff & hash[i]);
				if(hex.length() == 1) hexString.append('0');
				hexString.append(hex);
			}

			return hexString.toString();
		} catch(Exception ex){
			throw new RuntimeException(ex);
		}
	}

	/** 
	 * from this method downwards all methods are used to check how good the primes are.
	 * these methods are imported and modified to follow my conventions 
	 * the source of this method is https://github.com/wihoho/Wiener-s-Attack
	 * given time-frame for my case I was not able to impelement full wiener attack , hence needed external support.
	 */
	//WienerAttack
	public void Wiener(){

		BigInteger privateKey = this.attack(); //Start to attack

		if(privateKey.equals(BigInteger.ONE.negate())){
			//System.out.print("Case "+caseNum+": ");
			System.out.println("This attack is unsuccessful because there are no continuted fractions fulfilling the requirements of private key. YES!!");
			pass=1;
		}
		else{
			//Files.writeKeyToFile(privateKey, "P1_PrivateKey"+caseNum+".bin"); //Write the private key into a proper file
			//System.out.println("Case "+caseNum+": "+privateKey.toString());
			System.out.println("The above private key has been successfully found");
			System.out.println();
		}

	}

	public BigInteger attack(){
		int i= 0;
		BigInteger temp1;

		//This loop keeps going unless the privateKey is calculated or no privateKey is generated
		//When no privateKey is generated, temp1 == -1
		while((temp1 = step(i)) == null){
			i++;
		}

		return temp1;
	}

	//Steps follow the paper called "Cryptanalysis of Short RSA Secret Exponents by Michael J. Wiener"
	public  BigInteger step(int iteration){

		Fraction kDdg = new Fraction(BigInteger.ZERO, BigInteger.ONE); // k/dg, D means "divide"

		if(iteration == 0){
			//initialization for iteration 0

			Fraction ini = new Fraction(e,n);
			a.add(ini.floor());
			b.add(ini.remainder());
			c.add(a.get(0));
			dd.add(BigInteger.ONE);		
		}
		else if (iteration == 1){
			//iteration 1
			Fraction temp2 = new Fraction(b.get(0).denominator, b.get(0).numerator);
			a.add(temp2.floor());
			b.add(temp2.remainder());
			c.add((a.get(0).multiply(a.get(1))).add(BigInteger.ONE));
			dd.add(a.get(1));
		}
		else{
			if(b.get(iteration-1).numerator.equals(BigInteger.ZERO)){
				return BigInteger.ONE.negate(); //Finite continued fraction. and no proper privateKey could be generated. Return -1
			}

			//go on calculating n and d for iteration i by using formulas stating on the paper
			Fraction temp3 = new Fraction(b.get(iteration-1).denominator, b.get(iteration-1).numerator);
			a.add(temp3.floor());
			b.add(temp3.remainder());
			c.add((a.get(iteration).multiply(c.get(iteration-1)).add(c.get(iteration-2))));
			dd.add((a.get(iteration).multiply(dd.get(iteration-1)).add(dd.get(iteration-2))));
		}

		//if iteration is even, assign <q0, q1, q2,...,qi+1> to kDdg
		if(iteration % 2 == 0){
			if(iteration == 0){
				kDdg = new Fraction(a.get(0).add(BigInteger.ONE), BigInteger.ONE);
			}
			else{
				kDdg = new Fraction((a.get(iteration).add(BigInteger.ONE)).multiply(c.get(iteration-1)).add(c.get(iteration-2)), (a.get(iteration).add(BigInteger.ONE)).multiply(dd.get(iteration-1)).add(dd.get(iteration-2)));
			}
		}

		//if iteration is odd, assign <q0, q1, q2,...,qi> to kDdg
		else{
			kDdg = new Fraction(c.get(iteration), dd.get(iteration));
		}

		//System.out.println("k: "+kDdg.numerator+" dg:"+kDdg.denominator);

		BigInteger edg = e.multiply(kDdg.denominator); //get edg from e * dg

		//dividing edg by k yields a quotient of (p-1)(q-1) and a remainder of g 
		BigInteger fy = (new Fraction(e, kDdg)).floor(); 
		BigInteger g = edg.mod(kDdg.numerator);

		//get (p+q)/2 and check whether (p+q)/2 is integer or not
		BigDecimal pAqD2 = (new BigDecimal(n.subtract(fy))).add(BigDecimal.ONE).divide(new BigDecimal("2"));
		if(!pAqD2.remainder(BigDecimal.ONE).equals(BigDecimal.ZERO))
			return null;

		//get [(p-q)/2]^2 and check [(p-q)/2]^2 is a perfect square or not
		BigInteger pMqD2s = pAqD2.toBigInteger().pow(2).subtract(n);
		BigInteger pMqD2 = sqrt(pMqD2s);
		if(!pMqD2.pow(2).equals(pMqD2s))
			return null;

		//get private key d from edg/eg
		BigInteger privateKey = edg.divide(e.multiply(g));
		return privateKey;

	}

	//get the root of BigInteger paramBigInteger
	public  BigInteger sqrt(BigInteger paramBigInteger){
		BigInteger localBigInteger1 = BigInteger.valueOf(0L);
		BigInteger localBigInteger2 = localBigInteger1.setBit(2 * paramBigInteger.bitLength());
		do
		{
			BigInteger localBigInteger3 = localBigInteger1.add(localBigInteger2);
			if (localBigInteger3.compareTo(paramBigInteger) != 1) {
				paramBigInteger = paramBigInteger.subtract(localBigInteger3);
				localBigInteger1 = localBigInteger3.add(localBigInteger2);
			}
			localBigInteger1 = localBigInteger1.shiftRight(1);
			localBigInteger2 = localBigInteger2.shiftRight(2);
		}while (localBigInteger2.bitCount() != 0);
		return localBigInteger1;
	}
/**
 * getters and setters
 */

	/**
	 * @return the a
	 */
	public List<BigInteger> getA() {
		return a;
	}

	/**
	 * @param a the a to set
	 */
	public void setA(List<BigInteger> a) {
		this.a = a;
	}

	/**
	 * @return the b
	 */
	public List<Fraction> getB() {
		return b;
	}

	/**
	 * @param b the b to set
	 */
	public void setB(List<Fraction> b) {
		this.b = b;
	}

	/**
	 * @return the c
	 */
	public List<BigInteger> getC() {
		return c;
	}

	/**
	 * @param c the c to set
	 */
	public void setC(List<BigInteger> c) {
		this.c = c;
	}

	/**
	 * @return the dd
	 */
	public List<BigInteger> getDd() {
		return dd;
	}

	/**
	 * @param dd the dd to set
	 */
	public void setDd(List<BigInteger> dd) {
		this.dd = dd;
	}

	/**
	 * @return the m
	 */
	public String getM() {
		return m;
	}

	/**
	 * @param m the m to set
	 */
	public void setM(String m) {
		this.m = m;
	}

	/**
	 * @return the r
	 */
	public String getR() {
		return r;
	}

	/**
	 * @param r the r to set
	 */
	public void setR(String r) {
		this.r = r;
	}

	/**
	 * @return the g
	 */
	public String getG() {
		return G;
	}

	/**
	 * @param g the g to set
	 */
	public void setG(String g) {
		G = g;
	}

	/**
	 * @return the sb
	 */
	public StringBuilder getSb() {
		return sb;
	}

	/**
	 * @param sb the sb to set
	 */
	public void setSb(StringBuilder sb) {
		this.sb = sb;
	}

	/**
	 * @return the x
	 */
	public String getX() {
		return X;
	}

	/**
	 * @param x the x to set
	 */
	public void setX(String x) {
		X = x;
	}

	/**
	 * @return the h
	 */
	public String getH() {
		return H;
	}

	/**
	 * @param h the h to set
	 */
	public void setH(String h) {
		H = h;
	}

	/**
	 * @return the y
	 */
	public String getY() {
		return Y;
	}

	/**
	 * @param y the y to set
	 */
	public void setY(String y) {
		Y = y;
	}

	/**
	 * @return the n
	 */
	public BigInteger getN() {
		return n;
	}

	/**
	 * @param n the n to set
	 */
	public void setN(BigInteger n) {
		this.n = n;
	}

	/**
	 * @return the d
	 */
	public BigInteger getD() {
		return d;
	}

	/**
	 * @param d the d to set
	 */
	public void setD(BigInteger d) {
		this.d = d;
	}

	/**
	 * @return the e
	 */
	public BigInteger getE() {
		return e;
	}

	/**
	 * @param e the e to set
	 */
	public void setE(BigInteger e) {
		this.e = e;
	}

	/**
	 * @return the p
	 */
	public BigInteger getP() {
		return p;
	}

	/**
	 * @param p the p to set
	 */
	public void setP(BigInteger p) {
		this.p = p;
	}

	/**
	 * @return the q
	 */
	public BigInteger getQ() {
		return q;
	}

	/**
	 * @param q the q to set
	 */
	public void setQ(BigInteger q) {
		this.q = q;
	}

	/**
	 * @return the enc
	 */
	public BigInteger getEnc() {
		return enc;
	}

	/**
	 * @param enc the enc to set
	 */
	public void setEnc(BigInteger enc) {
		this.enc = enc;
	}

	/**
	 * @return the dec
	 */
	public BigInteger getDec() {
		return dec;
	}

	/**
	 * @param dec the dec to set
	 */
	public void setDec(BigInteger dec) {
		this.dec = dec;
	}

	/**
	 * @return the size
	 */
	public int getSize() {
		return size;
	}

	/**
	 * @param size the size to set
	 */
	public void setSize(int size) {
		this.size = size;
	}

	/**
	 * @return the pass
	 */
	public int getPass() {
		return pass;
	}

	/**
	 * @param pass the pass to set
	 */
	public void setPass(int pass) {
		this.pass = pass;
	}
	
	
	/*
	public String readFirstChars(File f, int number) throws IOException {
		Reader r = new BufferedReader(new InputStreamReader(
				new FileInputStream(f), "US-ASCII"));
		try {
			StringBuilder resultBuilder = new StringBuilder();
			int count = 0;
			int intch;
			while (((intch = r.read()) != -1) && count < number) {
				resultBuilder.append((char) intch);
				count++;
			}
			return resultBuilder.toString();
		} finally {
			r.close();
		}
	}*/
}

