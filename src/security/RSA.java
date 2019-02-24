package security;

import java.math.BigInteger;
import java.util.Random;

public class RSA {

	public RSA() {
	}

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
		RSA.KeyPair keyPair = new RSA.KeyPair(e, d, n);

		return keyPair;
	}

	public static byte[] cipher(byte M[], byte[] K) throws Exception {
		// TODO
		return null;
	}

	public static byte[] cipher(String s, byte[] K) throws Exception {
		// TODO
		return null;
	}

	public static void main(String[] args) {
		// TODO
	}

	private static class KeyPair {

		private BigInteger pubKey;
		private BigInteger priKey;
		private BigInteger n;

		public KeyPair(BigInteger pubKey, BigInteger priKey, BigInteger n) {
			this.setPubKey(pubKey);
			this.setPriKey(priKey);
			this.setN(n);
		}

		public BigInteger getPubKey() {
			return pubKey;
		}

		public void setPubKey(BigInteger pubKey) {
			this.pubKey = pubKey;
		}

		public BigInteger getPriKey() {
			return priKey;
		}

		public void setPriKey(BigInteger priKey) {
			this.priKey = priKey;
		}

		public BigInteger getN() {
			return n;
		}

		public void setN(BigInteger n) {
			this.n = n;
		}

	}

}
