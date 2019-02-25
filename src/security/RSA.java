package security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Random;

public class RSA {

	public RSA() {}

	/**
	 * given two primes, generate an RSA key pair
	 * @param p prime
	 * @param q prime
	 * @return RSA public and private key pair
	 */
	public static RSA.KeyPair generateKeys(BigInteger p, BigInteger q) {
		// calculate n
		BigInteger n = p.multiply(q);

		// (p - 1), (q - 1)
		BigInteger pMinus1 = p.subtract(BigInteger.ONE);
		BigInteger qMinus1 = q.subtract(BigInteger.ONE);

		// (p - 1) X (q - 1)
		BigInteger phiN = pMinus1.multiply(qMinus1);

		// possible e such that 1 < e < phiN
		BigInteger e = BigInteger.probablePrime(phiN.bitLength(), new Random());

		// calculate d
		BigInteger d = e.modInverse(phiN);

		// save key pair
		RSA.KeyPair keyPair = new RSA.KeyPair(new RSA.PublicKey(e, n), new RSA.PrivateKey(d, n));

		return keyPair;
	}

	/**
	 * cipher bytes with key
	 * Using the RSA algorithm
	 * C = Me  mod n
	 * @param M message
	 * @param K private or public key
	 * @return ciphered message
	 * @throws Exception if operation does not succeed
	 */
	public static byte[] cipher(byte M[], RSA.Key K) throws Exception {
		return new BigInteger(M).modPow(K.getKey(), K.getN()).toByteArray();
	}

	/**
	 * cipher a string with key
	 * @param s message
	 * @param K private or public key
	 * @return ciphered message
	 * @throws Exception if operation does not succeed
	 */
	public static byte[] cipher(String s, RSA.Key K) throws Exception {
		return cipher(s.getBytes(), K);
	}

	/**
	 * a tool to generate and ciper with RSA keys
	 * @param args command line arguments
	 * @throws Exception any error occurring
	 */
	public static void main(String[] args) throws Exception {
		if (args.length < 1) {
			System.out.println("Must have 1 or more arguments. Follow the command guideline below for assistance.");
			System.out.println("java security.RSA -help");
			return;
		} else if (args[0].equals("-help")) {
			System.out.println("java security.RSA -help");
			System.out.println("\t- this message\n");
			System.out.println("java security.RSA -gen <text>");
			System.out.println("\t- generate private (KR) and public (KU) keys");
			System.out.println("\t  and test them on <text> (optional)");
		} else if (args[0].equals("-gen") && args.length <= 2) {
			String p1 = System.getProperty("prime_size");
			String p2 = System.getProperty("prime_certainty");
			int primeSize = 256;
			int primeCertainty = 5;
			
			if (p1 != null) {
				int temp = Integer.parseInt(p1);
				
				if (temp > 127 && temp < 1024)
					primeSize = temp;
			}
			
			if (p2 != null)
				primeCertainty = Integer.parseInt(p2);
			
			BigInteger p = new BigInteger(primeSize, primeCertainty, new Random());
			BigInteger q = new BigInteger(primeSize, primeCertainty, new Random());
			
			RSA.KeyPair keys = generateKeys(p, q);
			
			System.out.println(keys);
			
			if (args.length == 2) {
				byte[] cipher = cipher(args[1], keys.getPubKey());
				
				System.out.println("\ncipher: " + new String(cipher));
				System.out.println("\noriginal: " + new String(cipher(cipher, keys.getPriKey())));
			}
		}
	}

	public static class KeyPair {

		private PublicKey pubKey;
		private PrivateKey priKey;

		public KeyPair(PublicKey pubKey, PrivateKey priKey) {
			this.pubKey = pubKey;
			this.priKey = priKey;
		}

		public PublicKey getPubKey() {
			return pubKey;
		}

		public PrivateKey getPriKey() {
			return priKey;
		}
		
		// Convert the key pair to a string and return the string
		public String toString() {
			return "KR={" + priKey.getKey() + ", " + priKey.getN() + "}\n\n"
					+ "KU={" + pubKey.getKey() + ", " + pubKey.getN() + "}";			
		}

	}

	public static class Key {
		// a Key is represented by two large Integers.
		protected BigInteger key;
		protected BigInteger n;
		private static final BigInteger zero = BigInteger.ZERO;
		
		public Key() {
			this(zero, zero);
		}
		
		public Key(BigInteger key, BigInteger n) {
			this.key = key;
			this.n = n;
		}

		protected BigInteger getKey() {
			return key;
		}

		protected BigInteger getN() {
			return n;
		}
		
		// convert byte input to inputstream
		public void read(byte m[]) throws IOException {
			read(new ByteArrayInputStream(m));
		}
		
		public void read(InputStream input) throws IOException {
			// the first character of the file must be '{'
			if (input.read() != 123)
				throw new IOException("Must follow format: {key,n}");
			
			StringBuffer sb = new StringBuffer();
			int inputInt = input.read();
			
			// every number is part of the key until a ',' is reached
			while (inputInt != 44) {
				sb.append((char) inputInt);
				inputInt = input.read();
			}
			
			// if the string is not a number, throw an exception
			try {
				key = new BigInteger(sb.toString());
			} catch (NumberFormatException nfe) {
				throw new IOException(nfe.toString());
			}
			
			sb = new StringBuffer();
			inputInt = input.read();
			
			// every number is part of the n until a '}' is reached
			while (inputInt != 125) {
				sb.append((char) inputInt);
				inputInt = input.read();
			}
			
			// if the string is not a number, throw an exception
			try {
				n = new BigInteger(sb.toString());
			} catch (NumberFormatException nfe) {
				throw new IOException(nfe.toString());
			}
		}
		
		// Convert key and n to a string
		public String toString() {
			return "key={" + key + ", " + n + "}";
		}
		
	}

	public static class PublicKey extends Key {
		
		public PublicKey(byte aByte[]) throws IOException {
			read(aByte);
		}

		public PublicKey(InputStream input) throws IOException {
			read(input);
		}

		public PublicKey(BigInteger key, BigInteger n) {
			super(key, n);
		}

	}

	public static class PrivateKey extends Key {
		
		public PrivateKey(byte aByte[]) throws IOException {
			read(aByte);
		}

		public PrivateKey(InputStream input) throws IOException {
			read(input);
		}

		public PrivateKey(BigInteger key, BigInteger n) {
			super(key, n);
		}

	}

}
