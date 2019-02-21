package security;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class RSADecrypt {

	public static void main(String[] args) {
		if (args.length == 2)
			encrypt(args[0], args[1]);
		else
			System.out.println("Error. There must be 2 arguments");
	}

	private static void encrypt(String textFile, String pubKeyFile) {
		StringBuilder blocks = new StringBuilder();
		String[] cipher = input(textFile).get(0).split(" ");
		List<String> priKey = input(pubKeyFile);
		List<String> plains = new ArrayList<String>();

		BigInteger d = new BigInteger(priKey.get(0).substring(4));
		BigInteger n = new BigInteger(priKey.get(1).substring(4));

		for (int i = 0; i < cipher.length; i++) {
			BigInteger plain = new BigInteger(cipher[i]);
			String p = "" + plain.modPow(d, n);
			String encoded = p.length() == 6 ? p : "0" + p;
			
			if (encoded.length() == 5)
				encoded = "0" + encoded;
			
			System.out.println(encoded);

			String block = decode(encoded.substring(0, 2)) + decode(encoded.substring(2, 4))
					+ decode(encoded.substring(4, 6));

			blocks.append(block);
		}

		plains.add(blocks.toString());

		output(plains);
	}

	private static List<String> input(String f) {
		Path file = Paths.get(f);

		try {
			return Files.readAllLines(file);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	private static void output(List<String> cipher) {
		Path testEnc = Paths.get("test.dec");

		try {
			Files.write(testEnc, cipher, Charset.forName("UTF-8"));
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	private static String decode(String num) {
		switch (num) {
		case "00":
			return "a";
		case "01":
			return "b";
		case "02":
			return "c";
		case "03":
			return "d";
		case "04":
			return "e";
		case "05":
			return "f";
		case "06":
			return "g";
		case "07":
			return "h";
		case "08":
			return "i";
		case "09":
			return "j";
		case "10":
			return "k";
		case "11":
			return "l";
		case "12":
			return "m";
		case "13":
			return "n";
		case "14":
			return "o";
		case "15":
			return "p";
		case "16":
			return "q";
		case "17":
			return "r";
		case "18":
			return "s";
		case "19":
			return "t";
		case "20":
			return "u";
		case "21":
			return "v";
		case "22":
			return "w";
		case "23":
			return "x";
		case "24":
			return "y";
		case "25":
			return "z";
		case "26":
			return " ";
		case "27":
			return ",";
		case "28":
			return "?";
		case "29":
			return ":";
		case "30":
			return ".";
		case "31":
			return "'";		
		default:
			return "";
		}
	}
}
