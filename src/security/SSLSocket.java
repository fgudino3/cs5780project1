package security;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public class SSLSocket extends Socket{
	
	protected InputStream cryptoIn;
	protected OutputStream cryptoOut;
	protected Hash H;
	protected byte[] K;
	protected Socket s;
	
	public SSLSocket(InetAddress addr, int port, byte[] id, byte[] MC, byte[] KC, byte[] K, Hash H) throws IOException{
		super(addr, port);
		handshake(id, MC, KC);
		this.K = K;
		this.H = H;
	}
	
	public SSLSocket(InetAddress raddr, int rport, InetAddress laddr, int lport, byte[] id, byte[] MC, byte[] KC, byte[] K, Hash H) throws IOException{
		super(raddr, rport, laddr, lport);
		handshake(id, MC, KC);
		this.K = K;
		this.H = H;
	}
	
	public SSLSocket(String host, int port, byte[] id, byte[] MC, byte[] KC, byte[] K, Hash H) throws IOException{
		super(host, port);
		handshake(id, MC, KC);
		this.K = K;
		this.H = H;
	}
	
	public SSLSocket(String rhost, int rport, InetAddress laddr, int lport, byte[] id, byte[] MC, byte[] KC, byte[] K, Hash H) throws IOException{
		super(rhost, rport, laddr, lport);
		handshake(id, MC, KC);
		this.K = K;
		this.H = H;
	}
	
	public SSLSocket(Socket s, byte[] K, Hash H) throws IOException{
		//super(s.getInetAddress(), s.getPort());
		  
		this.s = s;
		this.K = K;
		this.H = H;
		
//		byte[] cipherUserName;
//		byte[] cipherCompanyName;
//		byte[] cipherK;
//		try {
//			cipherUserName = RSA.cipher(user.getUserName(), user.getPubKey());
//			cipherCompanyName = RSA.cipher(user.getCompanyName(), user.getPriKey());
//			cipherK = RSA.cipher(K, user.getPubKey());
//			handshake(cipherUserName, cipherCompanyName, cipherK);
//			
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		 
	}
	
	protected void handshake(byte[] KID, byte[] MC, byte[] KC) throws IOException{
		int i = 0;
		for(int j = 0; j < KID.length; j++)
			if(KID[j] == 33 || KID[j] == 92)
				i++;
		
		for(int k = 0; k < MC.length; k++)
			if(MC[k] == 33 || MC[k] == 92)
				i++;
		
		for(int m = 0; m < KC.length; m++)
			if(KC[m] == 33 || KC[m] == 92)
				i++;
		
		byte[] RSAByte = new byte[KID.length + MC.length + KC.length + i + 4];
		int n = 1;
		
		RSAByte[0] = 33;
		
		for(int o = 0; o < KID.length; o++) {
			if(KID[o] == 33 || KID[o] == 92)
				RSAByte[n++] = 92;
			RSAByte[n++] = KID[o];
		}
		
		RSAByte[n++] = 33;
		
		for(int p = 0; p < MC.length; p++) {
			if(MC[p] == 33 || MC[p] == 92)
				RSAByte[n++] = 92;
			RSAByte[n++] = MC[p];
		}
		
		RSAByte[n++] = 33;
		
		for(int q = 0; q < KC.length; q++) {
			if(KC[q] == 33 || KC[q] == 92)
				RSAByte[n++] = 92;
			RSAByte[n++] = KC[q];
		}
		
		RSAByte[n] = 33;
		s.getOutputStream().write(RSAByte);
		s.getOutputStream().flush();
	}
	
	@Override
	public InputStream getInputStream() throws IOException{
		if(cryptoIn == null) {
			InputStream input = s != null ? s.getInputStream() : super.getInputStream();
			cryptoIn = new CryptoInputStream(input, K, H);
		}
		
		return cryptoIn;
	}
	
	@Override
	public OutputStream getOutputStream() throws IOException{
		if(cryptoOut == null) {
			OutputStream output = s != null ? s.getOutputStream() : super.getOutputStream();
			cryptoOut = new CryptoOutputStream(output, K, H);
		}
		
		return cryptoOut;
	}
	
	public InputStream getCryptedInputStream() throws IOException{
	
		if(s == null)
			return super.getInputStream();
		
		return s.getInputStream();
		
		}
	
	public String toString() {
		return "Crypto(" + s + ")";
	}
	
	public void close() throws IOException{
		if(s == null) {
			super.close();
			return;
		}
		
		s.close();
	}
}
