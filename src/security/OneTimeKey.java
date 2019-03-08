package security;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

public class OneTimeKey {
	
	public OneTimeKey() {}
	
	/**
	 * generate a new one-time key
	 * @param R use this random stream
	 * @param n this many bytes
	 * @return a new on-time key of n bytes
	 */
	 public static byte[] newKey(Random R, int n) {
		 byte[] key = new byte[n];
		 
		 R.nextBytes(key);
		 
		 return key;
	 }
	 
	 /**
	  * generate a new one-time key
	  * use the system clock as a random seed
	  * @param n this many bytes
	  * @return a new on-time key of n bytes
	  */
	 public static byte[] newKey(int n) {
		 return newKey(new Random(System.currentTimeMillis()), n);
	 }
	 
	 /**
	  * encrypt M using bitwise exclusive or
	  * @param M message
	  * @param K one-time key
	  * @return K(M)
	  * @throws Exception for corrupt messages
	  */
	 public static byte[] xor(byte M[], byte K[]) throws Exception {
		 if (M.length % K.length != 0)
			 throw new Exception("Incorrect key length. K.length " + K.length + ", M.length " + M.length);
		 
		 byte[] encoded = new byte[M.length];
		 
		 for (int i = 0; i < encoded.length; i++)
			 encoded[i] = (byte) (M[i] ^ K[i % K.length]);
		 
		 return encoded;
	 }
	 
	 /**
	  * 
	  * @param b key
	  * @param os output stream
	  * @throws IOException if os is corrupt
	  */
	 public static void printKey(byte b[], OutputStream os) throws IOException {
		 os.write(b);
	 }
	 
	/**
	 * test program
	 * encrypts and then decrypts messages to check that the method works
	 * @param args command line arguments
	 * @throws Exception if an error occurs
	 */
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			System.out.println("Error. Must have 2 or more arguments. Follow the command guideline below\n");
			System.out.println("java security.OneTimeKey <key>  <text1> ... <textn>");
			return;
		}
		
		byte[] key = args[0].getBytes();
		
		for (int i = 1; i < args.length; i++) {
			byte[] encoded = xor(args[i].getBytes(), key);
			
			System.out.println("original text is " + args[i]);
			System.out.println("encoded to " + new String(encoded));
			System.out.println("decoded to " + new String(xor(encoded, key)));
		}

	}

}
