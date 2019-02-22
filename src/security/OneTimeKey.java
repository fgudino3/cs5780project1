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
		 // TODO
		 return null;
	 }
	 
	 /**
	  * generate a new one-time key
	  * use the system clock as a random seed
	  * @param n this many bytes
	  * @return a new on-time key of n bytes
	  */
	 public static byte[] newKey(int n) {
		 // TODO
		 return null;
	 }
	 
	 /**
	  * encrypt M using bitwise exclusive or
	  * @param M message
	  * @param K one-time key
	  * @return K(M)
	  * @throws Exception for corrupt messages
	  */
	 public static byte[] xor(byte M[], byte K[]) throws Exception {
		 // TODO
		 return K;
	 }
	 
	 /**
	  * 
	  * @param b key
	  * @param os output stream
	  * @throws IOException if os is corrupt
	  */
	 public static void printKey(byte b[], OutputStream os) throws IOException {
		 // TODO
	 }
	 
	/**
	 * test program
	 * encrypts and then decrypts messages to check that the method works
	 * @param args command line arguments
	 * @throws Exception if an error occurs
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

	}

}
