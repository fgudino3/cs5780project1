package security;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CryptoInputStream extends FilterInputStream{
	
	protected Hash H;
	protected byte[] K;
	protected byte[] buffer;
	protected int pointer;
	
	public CryptoInputStream(InputStream stream, byte[] K, Hash H) {
		super(stream);
		this.H = H;
		this.K = K;
		pointer = 0;
	}

	public int read() throws IOException{
		if(pointer == 0) {
			int i = 0;
			byte[] RSAByte = new byte[H.getPacketSize()];
			
			for(int j = 0; j < H.getPacketSize(); j++) {
				int m = in.read();
				if(m == -1) {
					if(j == 0)
						return -1;
					throw new IOException("Read Data Error");
				}
				
				RSAByte[i++] = (byte)m;
			}
			try {
				RSAByte = OneTimeKey.xor(RSAByte,  K);
				buffer = H.unpack(RSAByte);
			}
			catch(RuntimeException re) {
				System.out.println(re);
			}
			catch(Exception e) {
				throw new IOException("Read Error");
			}
		}
		
		int i = buffer[pointer];
		int j = buffer.length;
		pointer = (pointer + 1) % j;
		return i;
	}
	
	public int read(byte[] b, int off, int len) throws IOException{
		if(b == null)
			throw new NullPointerException("Empty Buffer");
		
		int k = H.getPacketSize();
		int m = H.getNumberOfDataBytes();
		
		int i = off/m;
		int j = off % m;
		
		int n = (len + j)/k;
		int p = (len + j) % k;
		
		if(p != 0)
			n++;
		
		byte[] RSAByte2 = new byte[n*k];
		int q = i * k;
		int r = n * k;
		
		try {
			if(super.available() >= r) {
				int o = in.read(RSAByte2,  q,  r);
				
				if(o == -1)
					return o;
				
				byte[] RSAByte1 = OneTimeKey.xor(RSAByte2,  K);
				RSAByte1 = H.unpack(RSAByte1);
				System.arraycopy(RSAByte1,  0,  b,  0,  RSAByte1.length);
				
				return o/k * m;
			}
			
			return 0;
		}
		catch(Exception e) {
			System.out.println("Decryption Error");
		}
		
		return 0;
	}
	
	public long skip(long n) throws IOException{
		for( long i = 0L; i < n; i += 1L)
			if(read() == -1)
				return i;
		return n;
	}
	
	public int available() throws IOException{
		int i = super.available();
		
		return i / H.getPacketSize() * H.getNumberOfDataBytes();
	}
}
