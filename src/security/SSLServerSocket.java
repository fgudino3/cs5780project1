package security;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Properties;
import java.net.ServerSocket;

class SSLServerSocket extends ServerSocket{
	protected RSA.PrivateKey sKR;
	protected Properties users;
	
	public SSLServerSocket(int port, RSA.PrivateKey sKR, Properties users) throws IOException{
		super(port);
		this.sKR = sKR;
		this.users = users;
		
	}
	
	public SSLServerSocket(int port, int backlog, RSA.PrivateKey sKR, Properties users) throws IOException{
		super(port, backlog);
		this.sKR = sKR;
		this.users = users;
	}
	
	public SSLServerSocket(int port, int backlog, InetAddress bindAddr, RSA.PrivateKey sKR, Properties users) throws IOException{
		super(port, backlog, bindAddr);
		this.sKR = sKR;
		this.users = users;
	}
	
	protected byte[] getGreetingToken(Socket s) throws IOException{
		int  i = 128;
		byte[] tempByte = new byte[i];
		int j = 0;
		int k;
		while((k = s.getInputStream().read()) != 33) {
			if(k == -1)
				throw new EOFException("Greeting ended unexpectedly");
			if(k == 92 && (k = s.getInputStream().read()) == -1)
				throw new EOFException("Greeting ended unexpectedly");
			if(j == i) {
				i += i/2 + 1;
				byte[] RSAByteArray = new byte[i];
				System.arraycopy(tempByte, 0, RSAByteArray, 0, j);
				tempByte = RSAByteArray;
			}
			tempByte[j++] = ((byte) k);
		}
		byte[] RSAByteArray = new byte[j];
		System.arraycopy(tempByte,  0,  RSAByteArray,  0,  j);
		return RSAByteArray;
	}
	
	protected Object[] handshake(Socket s) throws Exception{
		int i;
		while((i = s.getInputStream().read()) != 33) {
			if(i == -1)
				throw new EOFException("Greeting not finished");
		}
		byte[] RSAByte1 = getGreetingToken(s);
		byte[] RSAByte2 = getGreetingToken(s);
		byte[] RSAByte3 = getGreetingToken(s);
		
		String str1 = new String(RSA.cipher(RSAByte1, sKR));
		String str2 = users.getProperty(str1 + ".public_key");
		
		if(str2 == null) 
			throw new Exception(str1 + " isn't a known user.");
		
		RSA.PublicKey userPublicKey = new RSA.PublicKey(str2.getBytes());
		
		String str3 = new String(RSA.cipher(RSAByte2,  userPublicKey));
		
		if( !str3.equals(users.getProperty(str1 + ".company")))
			throw new Exception("Wrong company (" + str1 + ":" + str3 + ")");
		
		int j = Integer.parseInt(users.getProperty(str1 + ".ndabytes"));
		int k = Integer.parseInt(users.getProperty(str1 + ".ncheckbytes"));
		byte b = (byte) Integer.parseInt(users.getProperty(str1 + ".pattern"));
		int m = Integer.parseInt(users.getProperty(str1 + ".k"));
		Object[] objectArray = new Object[2];
		
		objectArray[0] = RSA.cipher(RSAByte3, sKR);
		objectArray[1] = new Hash(j, k, b, m);
		
		return objectArray;
	}
	
	@Override
	public Socket accept() throws IOException{
		Socket s = super.accept();
		byte[] RSAByte = null;
		Hash h = null;
		try {
			Object[] objectArray = handshake(s);
			RSAByte = (byte[]) objectArray[0];
			h = (Hash) objectArray[1];
		}
		catch(Exception e) {
			throw new IOException(e.toString());
		}
		
		return new SSLSocket(s, RSAByte, h);
	}
}
