package security;

import java.net.Socket;

public class SimpleClient { 

	   // network socket
	   private Socket s;
	   private SSLSocket socket;
	   private byte[] K;
	   private Hash H;
	   private User user;

	   public SimpleClient(String host, int port) throws Exception {
		   user = new User("mickey");
		   user.load();
		   
		   int databytes = user.getNdatabytes();
		   int checkbytes = user.getNcheckbytes();
		   byte pattern = (byte) user.getPattern();
		   int k = user.getK();
		   
		   this.H = new Hash(databytes, checkbytes, pattern, k);
		   this.K = OneTimeKey.newKey(1 + databytes + checkbytes);
		   
	       // open a connection to the server
	       s = new Socket(host,port);
	       socket = new SSLSocket(s, this.K, this.H);
	       
	       byte[] cipherUserName = RSA.cipher(user.getUserName(), user.getPubKey());
	       byte[] cipherCompanyName = RSA.cipher(user.getCompanyName(), user.getPriKey());
	       byte[] cipherK = RSA.cipher(K, user.getPubKey());
			 
	       socket.handshake(cipherUserName, cipherCompanyName, cipherK);
	   }

	   // data transfer
	   public void execute() throws Exception {		      
	      int c, k=0,i=0;

	      // read data from keyboard until end of file
	      while((c = System.in.read()) != -1) {

	         // send it to server
	    	  socket.getOutputStream().write(c);
	         // if carriage return, flush stream
	         if ((char)c == '\n' || (char)c == '\r') 
	        	 socket.getOutputStream().flush();
	         ++k;
	         
	         System.out.println(c);
	      }
	      socket.getOutputStream().flush();
	      
	      System.out.println("Exit read data from keyboard.");
	      // read until end of file or same number of characters
	      // read from server 
	      while((c = socket.getInputStream().read()) != -1) {
	         System.out.write(c);
	         System.out.println(c);
	         if(++i == k) break;
	      }
	      System.out.println();
	      System.out.println("wrote " +i + " bytes");
	      socket.close();
	   }

	   
	   public static void main(String[] argv) throws Exception {
		   
		  if (argv.length == 0) {
			  String host = "127.0.0.1"; int port = 12345;
			  
			  new SimpleClient(host,port).execute();
		  }else if (argv.length == 2) {
			  String host = argv[0]; 
			  int port = Integer.parseInt(argv[1]);
			  
			  new SimpleClient(host,port).execute();
		  }else {
			  System.out.println("java SimpleClient <host> <port>"); 
			  System.exit(1); 
		  }
		  
	   } 
	}
