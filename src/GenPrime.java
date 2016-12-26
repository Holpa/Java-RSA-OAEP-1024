

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * GenPrime.java
 * TODO: 
 *
 * @author Kim Dinh Son
 * Email:sonkdbk@gmail.com
 */

public class GenPrime {
	static BigInteger TWO = new BigInteger("2");
	
	public BigInteger genBigPrime() {
		return BigInteger.probablePrime(3072, new SecureRandom());
	}
	
	public BigInteger genBigPrime(int numBits) {
		return BigInteger.probablePrime(numBits, new SecureRandom());
	}
	
	/*
	 * numBits = 3072 bits
	 * */
	public BigInteger genPrime(int numBits) {
		BigInteger proPrime = new BigInteger(numBits,128,new SecureRandom());
		if(proPrime.mod(TWO).equals(0)){
			proPrime = proPrime.add(BigInteger.ONE);
		}
		
		while (proPrime.bitLength() > numBits) {
			// step 1
			if (checkSmallPrime(proPrime)) {
				// step 2
				if (checkFermatBase2(proPrime)) {
					//step 3
					if (checkBasePrime(proPrime)){
						break;
					} else
						proPrime = proPrime.add(new BigInteger(numBits, new SecureRandom())); // or add 2
				} else
					proPrime = proPrime.add(new BigInteger(numBits, new SecureRandom())); // or add 2
			} else
				proPrime = proPrime.add(new BigInteger(numBits, new SecureRandom())); // or add 2			
		}		
		return proPrime;
	}
	
	public boolean checkSmallPrime(BigInteger n){
		int[] aValues = First_1000_Primes.getPrimes();
		
		for (int i = 0; i < aValues.length; i++) {
			if (n.mod(BigInteger.valueOf(aValues[i]))
					.compareTo(BigInteger.ZERO) == 0)
				return false;
		}	
		return true;
	}
	
	public boolean checkFermatBase2(BigInteger n){
		if (TWO.modPow(n, n).compareTo(TWO) == 0)
			return true;
		return false;
	}
	
	public boolean checkBasePrime(BigInteger n){
		int[] aValues = Arrays.copyOfRange(First_1000_Primes.getPrimes(), 1, 20);
		for(int i = 0; i<aValues.length; i++){
			if (BigInteger.valueOf(aValues[i]).modPow(n, n).compareTo(TWO) == 0)
				return true;
		}
		return false;
	}
	
}
