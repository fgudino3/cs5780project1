package security;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;

import security.RSA.Key;
import security.RSA.PrivateKey;
import security.RSA.PublicKey;

public class User {
	
	private String userName;
	private String CompanyName;
	private int ndatabytes;
	private int ncheckbytes;
	private int pattern;
	private int k;
	private PublicKey pubKey;
	private PrivateKey priKey;
	
	public void load() {
		
		String fileName = this.getUserName() + ".txt";
		try {
			BufferedReader br = new BufferedReader(new FileReader(fileName));

			String line = null;
			while ((line = br.readLine()) != null) {
				line = line.trim();
				
				String temp[] = line.split("=");

				if (temp[0].equals("private_key")) {
					Key key = getKey(temp[1]);
					this.setPriKey(new PrivateKey(key.getKey(), key.getN()));
				}else if (temp[0].equals("company")) {
					this.setCompanyName(temp[1]);
				}else if (temp[0].equals("ndatabytes")) {
					this.setNdatabytes(Integer.parseInt(temp[1]));
				}else if (temp[0].equals("ncheckbytes")) {
					this.setNcheckbytes(Integer.parseInt(temp[1]));
				}else if (temp[0].equals("k")) {
					this.setK(Integer.parseInt(temp[1]));
				}else if (temp[0].equals("pattern")) {
					this.setPattern(Integer.parseInt(temp[1]));
				}else if (temp[0].equals("server.public_key")) {
					Key key = getKey(temp[1]);
					this.setPubKey(new PublicKey(key.getKey(), key.getN()));
				}

			}

			br.close();

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
	
	public User() {
		
	}
	
	public User(String userName) {
		this.userName = userName;
	}
	
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getCompanyName() {
		return CompanyName;
	}
	public void setCompanyName(String companyName) {
		CompanyName = companyName;
	}
	public int getNdatabytes() {
		return ndatabytes;
	}
	public void setNdatabytes(int ndatabytes) {
		this.ndatabytes = ndatabytes;
	}
	public int getNcheckbytes() {
		return ncheckbytes;
	}
	public void setNcheckbytes(int ncheckbytes) {
		this.ncheckbytes = ncheckbytes;
	}
	public int getPattern() {
		return pattern;
	}
	public void setPattern(int pattern) {
		this.pattern = pattern;
	}
	public int getK() {
		return k;
	}
	public void setK(int k) {
		this.k = k;
	}
	public PublicKey getPubKey() {
		return pubKey;
	}
	public void setPubKey(PublicKey pubKey) {
		this.pubKey = pubKey;
	}
	public PrivateKey getPriKey() {
		return priKey;
	}
	public void setPriKey(PrivateKey priKey) {
		this.priKey = priKey;
	}

}
