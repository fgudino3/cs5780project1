package security;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class RSA {

	public static void main(String[] args) {		
		if (args.length == 1)
			generate(Integer.parseInt(args[0]));
		else if (args.length == 3)
			generate(new BigInteger(args[0]), new BigInteger(args[1]), new BigInteger(args[2]));
		else
			System.out.println("Error. Must have 1 or 3 arguments");
	}

	private static void generate(int k) {
		Random r = new Random();

		// pick 2 large prime numbers
		BigInteger p = BigInteger.probablePrime(k, r);
		BigInteger q = BigInteger.probablePrime(k, r);

		// calculate n
		BigInteger n = p.multiply(q);

		// (p - 1), (q - 1)
		BigInteger pMinus1 = p.subtract(BigInteger.ONE);
		BigInteger qMinus1 = q.subtract(BigInteger.ONE);

		// (p - 1) X (q - 1)
		BigInteger phiN = pMinus1.multiply(qMinus1);

		// possible e such that 1 < e < phiN
		BigInteger e = BigInteger.probablePrime(k / 2, r);
		
		// gcd(phiN, possible e's) = 1 and 1 < e < phiN
		while (phiN.gcd(e).compareTo(BigInteger.ONE) != 0 && e.compareTo(phiN) < 0)
			e.add(BigInteger.ONE);
		
		// calculate d
		BigInteger d = e.modInverse(phiN);

		createKeys(e, d, n);
	}

	private static void generate(BigInteger p, BigInteger q, BigInteger e) {
		// calculate n
		BigInteger n = p.multiply(q);

		// (p - 1), (q - 1)
		BigInteger pMinus1 = p.subtract(BigInteger.ONE);
		BigInteger qMinus1 = q.subtract(BigInteger.ONE);

		// (p - 1) X (q - 1)
		BigInteger phiN = pMinus1.multiply(qMinus1);
		
		// calculate d
		BigInteger d = e.modInverse(phiN);

		createKeys(e, d, n);
	}

	private static void createKeys(BigInteger e, BigInteger d, BigInteger n) {
		List<String> pubKey = Arrays.asList("e = " + e, "n = " + n);
		List<String> priKey = Arrays.asList("d = " + d, "n = " + n);
		Path pub = Paths.get("pub_key.txt");
		Path pri = Paths.get("pri_key.txt");

		try {
			Files.write(pub, pubKey, Charset.forName("UTF-8"));
			Files.write(pri, priKey, Charset.forName("UTF-8"));
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		System.out.println("public key  = " + e);
		System.out.println("private key = " + d);
		System.out.println("n = " + n);
	}

}
