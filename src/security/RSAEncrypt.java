package security;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class RSAEncrypt {

	public static void main(String[] args) {
		if (args.length == 2)
			encrypt(args[0], args[1]);
		else
			System.out.println("Error. There must be 2 arguments");
	}
	
	private static void encrypt(String textFile, String pubKeyFile) {
		List<String> text = input(textFile);
		List<String> pubKey = input(pubKeyFile);
		List<String> ciphers = new ArrayList<String>();
		StringBuilder blocks = new StringBuilder();
		
		BigInteger e = new BigInteger(pubKey.get(0).substring(4));
		BigInteger n = new BigInteger(pubKey.get(1).substring(4));
		
		for (int i = 0; i < text.size(); i++) {
			List<Character> line = new ArrayList<Character>();
			
			for (char c: text.get(i).toCharArray())
				line.add(c);
			
			while (line.size() % 3 != 0)
				line.add('*');
			
			for (int j = 0; j <= line.size() - 3; j += 3) {
				String sub = encode(line.get(j)) + encode(line.get(j + 1)) + encode(line.get(j + 2));
				
				BigInteger block = new BigInteger(sub);
				
				blocks.append(block.modPow(e, n) + " ");
				System.out.println("sub: " + sub + " int: " + block);
			}
		}
		
		ciphers.add(blocks.toString());
		
		output(ciphers);		
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
		Path testEnc = Paths.get("test.enc");

		try {
			Files.write(testEnc, cipher, Charset.forName("UTF-8"));
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	private static String encode(char letter) {
		switch (Character.toLowerCase(letter)) {
		case 'a':
			return "00";
		case 'b':
			return "01";
		case 'c':
			return "02";
		case 'd':
			return "03";
		case 'e':
			return "04";
		case 'f':
			return "05";
		case 'g':
			return "06";
		case 'h':
			return "07";
		case 'i':
			return "08";
		case 'j':
			return "09";
		case 'k':
			return "10";
		case 'l':
			return "11";
		case 'm':
			return "12";
		case 'n':
			return "13";
		case 'o':
			return "14";
		case 'p':
			return "15";
		case 'q':
			return "16";
		case 'r':
			return "17";
		case 's':
			return "18";
		case 't':
			return "19";
		case 'u':
			return "20";
		case 'v':
			return "21";
		case 'w':
			return "22";
		case 'x':
			return "23";
		case 'y':
			return "24";
		case 'z':
			return "25";
		case ' ':
			return "26";
		case ',':
			return "27";
		case '?':
			return "28";
		case ':':
			return "29";
		case '.':
			return "30";
		case '\'':
			return "31";
		default:
			return "32";
		}
	}
}
