package security;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class CryptoOutputStream extends FilterOutputStream{

	protected Hash H;
	protected byte[] K;
	private byte[] buffer;
	private int pointer;
	
	public CryptoOutputStream(OutputStream stream, byte[] K, Hash H) {
		super(stream);
		this.H = H;
		this.K = K;
		int i = H.getNumberOfDataBytes();
		buffer = new byte[i];
		pointer = 0;
	}
	
	public void write(int b) throws IOException{
		buffer[pointer++] = (byte)b;
		if(pointer == buffer.length) {
			pointer = 0;
			write(buffer, 0, buffer.length);
		}
	}
	
	public void write(byte[] b, int off, int len) throws IOException{
		byte[] RSAByte1 = new byte[len];
		System.arraycopy(b,  off,  RSAByte1,  0,  len);
		try {
			byte[] RSAByte2 = H.pack(RSAByte1);
			RSAByte2 = OneTimeKey.xor(RSAByte2, K);
			out.write(RSAByte2);
		}
		catch(Exception e) {
			System.out.println(e);
		}
	}
	
	protected void shallowFlush() throws IOException{
		if(pointer != 0) {
			write(buffer, 0, pointer);
			pointer = 0;
		}
	}
	
	public void flush() throws IOException{
		if(pointer != 0)
			shallowFlush();
		
		super.flush();
	}
}
