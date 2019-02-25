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
		//	if (args.length < 1) {
		//		System.out.println("Error. Must have 1 or more arguments");
		//		return;
		//	}
		RSA.KeyPair keys = generateKeys(BigInteger.probablePrime(64, new Random()), BigInteger.probablePrime(64, new Random()));
		System.out.println(keys);
		String msg = "testing";
		
		byte[] cipher = cipher(msg, keys.getPubKey());
		
		System.out.println("cipher: " + new String(cipher));
		System.out.println("original: " + new String(cipher(cipher, keys.getPriKey())));
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
			return "KR={" + priKey.getKey() + "," + priKey.getN() + "}\n"
					+ "KU={" + pubKey.getKey() + "," + pubKey.getN() + "}";			
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
			// TODO
		}
		
		// Convert key and n to a string
		public String toString() {
			return "key={" + key + "," + n + "}";
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
