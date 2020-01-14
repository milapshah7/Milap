public class EncryptionTest {

	public static byte[] xor_func(byte[] a, byte[] b) {
		byte[] out = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			out[i] = (byte) (a[i] ^ b[i]);
		}
		return out;

	}

	public static int binary(int number, int count) {
		if (number == 0) 
		{
			return count;
		} 
		else 
		{
			if (number % 2 != 0) 
				count++;

			return (binary(number / 2, count));
		}
	}

	public static void main(String[] args) {

		try {

			String text = "We are Discovered hide your self at end of the path";
			System.out.println("Input Length: " + text.length());
			// AES
			long start, end;
			String j = "abcde12345fghij7";

			
			 byte[] input = text.getBytes();
			 /* for (int i = 0; i < input.length;
			 i++) { System.out.println("Plain Text : " + input[i]); String t=
			 * Integer.toHexString(input[i]);
			 * 
			 * //input[i] =(byte)Integer.parseInt(t);
			 * System.out.println(Integer.toBinaryString(input[i])); }
			 */
			start = System.nanoTime();
			byte[] encr = AES.encrypt(text.getBytes(), j.getBytes());
			end = System.nanoTime();
			byte[] diff = xor_func(text.getBytes(), encr);
			
			int cnt=0;
			for (int i = 0; i < diff.length; i++) {

				cnt += binary(diff[i], 0);

			}

			System.out.println("Total Input Bits: "+ text.length()*8);
			
			System.out.println("OutDiff Count : " + cnt);
			
			System.out.println("Bit Ration: " + ((double)cnt/(double)(text.length()*8))*100.0);
			
			/*
			 * System.out.println("Encrypted Ascii"); for(int
			 * i=0;i<encr.length;i++){
			 * 
			 * System.out.println("Ascii"+encr[i]);
			 * 
			 * 
			 * }
			 */
			System.out.println("");
			System.out.println("Encryption Time Taken: " + (end - start)
					+ " ns\n");
			System.out.println("Text encrypted with AES: " + new String(encr));

			start = System.nanoTime();
			byte[] decr = AES.decrypt(encr, j.getBytes());
			end = System.nanoTime();

			System.out.println("Decryption Time Taken: " + (end - start)
					+ " ns\n");
			System.out.println("Text decrypted with AES: " + new String(decr));
			/*
			 * for (int k = 0; k < decr.length; k++)
			 * System.out.println("Text decrypted with AES: " + decr[k]);
			 */

			System.out.println("------------------");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
