package security;

public class Hash {

	private int ndb;
	private int ncb;
	private byte p;
	private int k;

	/*
	 * Hash object constructor
	 * 
	 * @param ndb - number of data bytes
	 * 
	 * @param ncb - number of checksum bytes
	 * 
	 * @param p - hash function byte pattern
	 * 
	 * @param k - hash function k
	 */
	public Hash(int ndb, int ncb, byte p, int k) {
		this.ndb = ndb;
		this.ncb = ncb;
		this.p = p;
		this.k = k;
	}

	/*
	 * @return the number of bytes a packet occupies
	 */
	public int getPacketSize() {
		return 1 + ndb + ncb;
	}

	/*
	 * @return the number of data bytes in a packet
	 */
	public int getNumberOfDataBytes() {
		return ndb;
	}

	/*
	 * Assemble a burst of packets from the data passed If the number of bytes is
	 * not a multiple of the packet size, the last packet will have less data bytes.
	 * 
	 * @param data - data bytes
	 * 
	 * @return assembled packets
	 */
	public byte[] pack(byte data[]) {
		return pack(data, ndb, ncb, p, k);
	}

	/*
	 * Assemble a burst of packets from the data passed
	 * 
	 * @param data - data bytes
	 * 
	 * @param nused - package only the first these many bytes
	 */
	public byte[] pack(byte data[], int nused) {
		byte[] dataSubset = new byte[nused];
		
		System.arraycopy(data, 0, dataSubset, 0, nused);
		
		return pack(dataSubset, ndb, ncb, p, k);
	}

	/*
	 * Assemble a burst of packets from the data passed This function allows to pack
	 * a burst of data without using an actual Hash instance.
	 * 
	 * @param data - data bytes
	 * 
	 * @param ndatabytes - number of data bytes
	 * 
	 * @param ncheckbytes - number of checksum bytes
	 * 
	 * @param pattern - hash function pattern
	 * 
	 * @param k - hash function k
	 * 
	 * @return assembled packets
	 */
	public static byte[] pack(byte data[], int ndatabytes, int ncheckbytes, byte pattern, int k) {
		// TODO
		return data;
	}

	/*
	 * Disassemble a burst of packets
	 * 
	 * @param packets - packet bytes
	 * 
	 * @return data bytes
	 * 
	 * @throws Exception if the checksums are incorrect
	 */
	public byte[] unpack(byte packets[]) throws Exception {
		return unpack(packets, ndb, ncb, p, k);
	}

	/*
	 * Disassemble a burst of packets
	 * This function allows to disassemble a burst of packets without actually using a Hash instance.
	 * 
	 * @param packets - packet bytes
	 * 
	 * @param ndatabytes - number of data bytes
	 * 
	 * @param ncheckbytes - number of checksum bytes
	 * 
	 * @param pattern - hash function pattern
	 * 
	 * @param k - hash function k
	 * 
	 * @return data stored in the packets
	 * 
	 * @throws Exception if the checksum bytes are incorrect
	 * */
	public static byte[] unpack(byte packets[], int ndatabytes, int ncheckbytes, byte pattern, int k) throws Exception {
		// TODO
		return packets;
	}

	/*
	 * Assemble and then disassemble some data. Only provided as a test method.
	 * 
	 * @param args - explained when run
	 * 
	 * @throws Exception gathered while running the program
	 * */
	public static void main(String[] args) throws Exception {
		if (args.length < 5) {
			System.out.println("Error. Must have 5 or more arguments. Follow the command guideline below\n");
			System.out.println("java security.Hash <databytes> <checkbytes> <pattern> <k> <text1> ... <textn>");
			return;
		}
		
		int databytes = Integer.parseInt(args[0]);
		int checkbytes = Integer.parseInt(args[1]);
		byte pattern = (byte) Integer.parseInt(args[2]);
		int k = Integer.parseInt(args[3]);
		
		for (int i = 4; i < args.length; i++) {
			byte[] packet = pack(args[i].getBytes(), databytes, checkbytes, pattern, k);
			System.out.println("Packed Bytes: " + new String(packet));
			System.out.println("Unpacked Bytes: " + new String(unpack(packet, databytes, checkbytes, pattern, k)));
		}
	}

}
