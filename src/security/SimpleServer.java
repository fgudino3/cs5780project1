package security;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;

import security.RSA.Key;
import security.RSA.PrivateKey;
import security.RSA.PublicKey;

public class SimpleServer implements Runnable {

   // server's socket
   //private ServerSocket s;
   private SSLServerSocket socket;
   private RSA.PrivateKey sKR;
   private Properties users;

   // server's port
   @SuppressWarnings("unused")
   private int port;

   public SimpleServer(int p) throws Exception {

	   loadUsers();
	   loadPrivateKey();
	   
      // open server socket and start listening
      socket = new SSLServerSocket(p, this.sKR, this.users);
   }
   
   public void loadPrivateKey() {
	   String fileName = "private_key.txt";
		try {
			BufferedReader br = new BufferedReader(new FileReader(fileName));

			String line = br.readLine();
			Key key = getKey(line);
			sKR = new PrivateKey(key.getKey(), key.getN());

			br.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
   }
   
   public void loadUsers() {
	   String fileName = "users.txt";
	   Properties usersProps = null;
	   try {
		   usersProps = new Properties();
		   usersProps.load(new FileInputStream(fileName));
		   this.users = usersProps;
		   
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
   }
   
   public Key getKey(String keyFormat) {
		keyFormat = keyFormat.replace("{", "").replace("}", "");
		String keyArr[] = keyFormat.split(",");
		String keyStr = keyArr[0];
		String nStr = keyArr[1];
		Key key = new Key(new BigInteger(keyStr), new BigInteger(nStr));
		
		return key;
	}

   public class RequestHandler implements Runnable {
      private Socket sock;

      private RequestHandler(java.net.Socket x) {
         sock = x;
      }

      public void run() {
         try {
        	 System.out.println(users.toString());
        	 System.out.println("handshake complete");
             System.out.println("connect...");
            
            int c;
            
            // read the bytes from the socket
            // and convert the case
            while((c = sock.getInputStream().read()) != -1) {
                if(c >= 97 && c <= 122) {
                  c -= 32;
                } else if (c >= 65 && c <=90) {
                  c += 32;
                }
                // write it back
                sock.getOutputStream().write(c);
                System.out.println((char)c);
                sock.getOutputStream().flush();
                // flush output if no more data on input
                if (sock.getInputStream().available() == 0) {
                   sock.getOutputStream().flush();
                }
            }

            sock.getOutputStream().flush();
            sock.close();
            System.out.println("disconnect...");
         } catch (Exception e) {
            System.out.println("HANDLER: " + e.getMessage() + e.getStackTrace());
         }
      } 
   }

   public void run() {
      while(true) {
         try {
            // accept a connection and run handler in a new thread
            new Thread(new RequestHandler(socket.accept())).run();
         } catch(Exception e) {
            System.out.println("SERVER: " + e.getMessage() + e.getStackTrace());
         }
      }
   } 


  public static void main(String[] argv) throws Exception {
	  
	  if (argv.length == 0) {
		    new SimpleServer(12345).run();
	     }
	  else if(argv.length == 1) {
		  new SimpleServer(Integer.parseInt(argv[0])).run();
	  }
	  else {
        System.out.println("java SimpleServer <port>");
        System.exit(1);
     }
  }
   

}
