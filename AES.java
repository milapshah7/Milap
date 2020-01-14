public class AES {

	private static int Nb, Nk, Nr;
	private static byte[][] w; // stores subkeys

	private static int[] sbox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
			0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
			0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
			0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
			0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23,
			0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
			0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52,
			0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
			0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
			0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9,
			0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
			0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
			0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
			0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
			0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0,
			0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62,
			0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
			0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
			0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
			0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
			0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
			0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
			0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41,
			0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

	private static int[] inv_sbox = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
			0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
			0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
			0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
			0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1,
			0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B,
			0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4,
			0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
			0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
			0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4,
			0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
			0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
			0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
			0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
			0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47,
			0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E,
			0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79,
			0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
			0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27,
			0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
			0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
			0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53,
			0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1,
			0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

	private static int Rcon[] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
			0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
			0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
			0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
			0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
			0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
			0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
			0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
			0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
			0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
			0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
			0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
			0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
			0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
			0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
			0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
			0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
			0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
			0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
			0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
			0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
			0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
			0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

	private static byte[] xor_func(byte[] a, byte[] b) {
		byte[] out = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			out[i] = (byte) (a[i] ^ b[i]);
		}
		return out;

	}

	

	private static byte[][] generateSubkeys(byte[] key) {
		byte[][] tmp = new byte[Nb * (Nr + 1)][4];

		int i = 0;
		while (i < Nk) {

			tmp[i][0] = key[i * 4];
			tmp[i][1] = key[i * 4 + 1];
			tmp[i][2] = key[i * 4 + 2];
			tmp[i][3] = key[i * 4 + 3];
			i++;
		}
		i = Nk;
		while (i < Nb * (Nr + 1)) {
			byte[] temp = new byte[4];
			for (int k = 0; k < 4; k++)
				temp[k] = tmp[i - 1][k];
			if (i % Nk == 0) {
				temp = SubWord(rotateWord(temp)); // performs the xor with Rcon
				temp[0] = (byte) (temp[0] ^ (Rcon[i / Nk] & 0xff));
			} else if (Nk > 6 && i % Nk == 4) {
				temp = SubWord(temp);
			}
			tmp[i] = xor_func(tmp[i - Nk], temp);
			i++;
		}

		return tmp;
	}

	private static byte[] SubWord(byte[] in) {
		byte[] tmp = new byte[in.length];

		for (int i = 0; i < tmp.length; i++)
			tmp[i] = (byte) (sbox[in[i] & 0x000000ff] & 0xff);

		return tmp;
	}

	private static byte[] rotateWord(byte[] input) {
		byte[] tmp = new byte[input.length];
		tmp[0] = input[1];
		tmp[1] = input[2];
		tmp[2] = input[3];
		tmp[3] = input[0];

		return tmp;
	}

	/*
	 * private static byte[][] ibdAddRoundKey(byte[][] state, byte[][] w, int
	 * blk) {
	 * 
	 * byte[][] tmp = new byte[state.length][state[0].length]; byte temp[] = new
	 * byte[16]; int b = -1; int q=0; int j=0; for(int i=0;i<16;i++){
	 * 
	 * q= i/4; if((q+5*(i%4))%4==0) { j=q+ 5*((i-1)%4)+1; } else { j=q+5* (i%4);
	 * } //temp [i] = state[]//xor_func(state[j], w[i%state.length]);
	 * tmp[i%state.length] = xor_func(state[j], w[i%state.length]); if(i>0 &&
	 * i%4==0) b++; state[b]=tmp[i%state.length]; }
	 * 
	 * return tmp; }
	 */

	/*
	 * private static byte[][] AddRoundKey(byte[][] state, byte[][] w, int
	 * round) {
	 * 
	 * byte[][] tmp = new byte[state.length][state[0].length];
	 * 
	 * for (int c = 0; c < Nb; c++) { for (int l = 0; l < 4; l++) tmp[l][1] =
	 * (byte) (state[l][1] ^ w[round * Nb + c][l]); }
	 * 
	 * return tmp; }
	 */

	private static byte[][] AddRoundKey(byte[][] state, byte[][] w, int round) {

		byte[][] tmp = new byte[state.length][state[0].length];

		for (int c = 0; c < Nb; c++) {
			for (int l = 0; l < 4; l++) {
				tmp[l][c] = (byte) (state[l][c] ^ w[round * Nb + c][l]);
			}
		}

		return tmp;
	}

	private static byte[][] InvIBitDAddRoundKey(byte[][] s1, byte[][] s2,byte[][] s3, byte[][] s4, byte[][] w, int round)
	{

		int i = 0;
		int q, j;
		byte[][] temp = new byte[16][4];
		byte[][] t1 = new byte[16][4];
		byte []s_bits = new byte[512];
		byte []k_bits = new byte[128];
		byte []temp_bits = new byte[512];
		
		byte[][] s11 = new byte[4][4];
		byte[][] s12=new byte[4][4];
		byte[][] s13=new byte[4][4];
		byte[][] s14=new byte[4][4];
		
		int cnt=0;
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s1[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s2[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s3[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s4[k][l] & 0xFF) + 0x100).substring(1);
				//Integer.toBinaryString((s4[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		cnt=0;
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						k_bits[cnt++] = 1;
					else
						k_bits[cnt++] = 0;
				}
			}
		}
		
		for(int l=0;l<512;l++)
		{
			temp_bits [(l * 4) % 512 + l / 128] = (byte)(s_bits[l] ^ k_bits[l % 128]);
			//temp_bits [l] =(byte) ((byte)s_bits[l % 4 * 4 + l / 4] ^ (byte)k_bits[l % 128]);  
		}
		
		cnt=0;
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				s11[k][l] = (byte)(Integer.parseInt(s, 2) & 0xff);//Byte.parseByte(s,2);
			}
		}
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				s12[k][l] = (byte)(Integer.parseInt(s, 2) & 0xff);//Byte.parseByte(s,2);
			}
		}
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				s13[k][l] = (byte)(Integer.parseInt(s, 2)& 0xff);//Byte.parseByte(s,2);
			}
		}
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				//System.out.println("String is: "+ s);
				
				s14[k][l] = (byte)(Integer.parseInt(s, 2)& 0xff);//Byte.parseByte(s,2);
			}
		}
		
		for (i = 0; i < 4; i++) {

			temp[i] = s11[i];
			temp[i + 4] = s12[i];
			temp[i + 4 * 2] = s13[i];
			temp[i + 4 * 3] = s14[i];
			
		}
		
		return temp;
	}
	
	private static byte[][] IBitDAddRoundKey(byte[][] s1, byte[][] s2,byte[][] s3, byte[][] s4, byte[][] w, int round)
	{

		int i = 0;
		int q, j;
		byte[][] temp = new byte[16][4];
		byte[][] t1 = new byte[16][4];
		byte []s_bits = new byte[512];
		byte []k_bits = new byte[128];
		byte []temp_bits = new byte[512];
		
		byte[][] s11 = new byte[4][4];
		byte[][] s12=new byte[4][4];
		byte[][] s13=new byte[4][4];
		byte[][] s14=new byte[4][4];
		
		int cnt=0;
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s1[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s2[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s3[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				s = Integer.toBinaryString((s4[k][l] & 0xFF) + 0x100).substring(1);
				//Integer.toBinaryString((s4[k][l] & 0xFF) + 0x100).substring(1);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						s_bits[cnt++] = 1;
					else
						s_bits[cnt++] = 0;
				}
			}
		}
		cnt=0;
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					if(s.charAt(m)=='1')
						k_bits[cnt++] = 1;
					else
						k_bits[cnt++] = 0;
				}
			}
		}
		
		for(int l=0;l<512;l++)
		{
			System.out.println("Testing : "+((l*4) % 512 + l / 128) +"\n");
			temp_bits [l] = (byte)(s_bits[(l * 4) % 512 + l / 128] ^ k_bits[l % 128]);
			/*if(l<128)
			temp_bits [l] = (byte)(s_bits[l % 4 * 4 + l / 4] ^ k_bits[l % 128]);
			else if(l<256)
				temp_bits [l] = (byte)(s_bits[l % 4 * 4 + l / 4] ^ k_bits[l % 128]);
			else if(l<384)
				temp_bits [l] = (byte)(s_bits[l % 4 * 4 + l / 4] ^ k_bits[l % 128]);
			else
				temp_bits [l] = (byte)(s_bits[l % 4 * 4 + l / 4] ^ k_bits[l % 128]);*/
		}
		
		cnt=0;
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				s11[k][l] = (byte)(Integer.parseInt(s, 2)& 0xff);// Byte.parseByte(s,2);
			}
		}
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				s12[k][l] = (byte)(Integer.parseInt(s, 2)& 0xff);// Byte.parseByte(s,2);
			}
		}
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				s13[k][l] = (byte)(Integer.parseInt(s, 2)& 0xff);//Byte.parseByte(s,2);
			}
		}
		
		for(int k=0;k<4;k++)
		{
			for(int l=0;l<4;l++)
			{
				String s = "";
				
				//s = Integer.toBinaryString((w[round * Nb + k][l] & 0xFF) + 0x100).substring(1); 
						//Integer.toBinaryString(w[round * Nb + k][l]);
				for(int m=0;m<8;m++)
				{
					s += temp_bits[cnt++];
				}
				
				s14[k][l] = (byte)(Integer.parseInt(s, 2)& 0xff);//Byte.parseByte(s,2);
			}
		}
		
		for (i = 0; i < 4; i++) {

			temp[i] = s11[i];
			temp[i + 4] = s12[i];
			temp[i + 4 * 2] = s13[i];
			temp[i + 4 * 3] = s14[i];
			
		}
		
		return temp;
	}
	
	private static byte[][] IBDAddRoundKey(byte[][] s1, byte[][] s2,
			byte[][] s3, byte[][] s4, byte[][] w, int round) {

		int i = 0;
		int q, j;
		byte[][] temp = new byte[16][4];
		byte[][] t1 = new byte[16][4];
		for (i = 0; i < 4; i++) {

			temp[i] = s1[i];
			temp[i + 4] = s2[i];
			temp[i + 4 * 2] = s3[i];
			temp[i + 4 * 3] = s4[i];
			
			t1[i] = s1[i];
			t1[i + 4] = s2[i];
			t1[i + 4 * 2] = s3[i];
			t1[i + 4 * 3] = s4[i];
		}

		/*for(i=0;i<4;i++) {
			
			System.out.println("temp0: "+new String(temp[i]));
			System.out.println("S1: "+new String(s1[i]));
			System.out.println("temp1: "+new String(temp[i+4]));
			System.out.println("S2: "+new String(s2[i]));
			System.out.println("temp2: "+new String(temp[i+8]));
			System.out.println("S3: "+new String(s3[i]));
			System.out.println("temp3: "+new String(temp[i+12]));
			System.out.println("S4: "+new String(s4[i]));
			
		}*/
		
		for (i = 0; i < 16; i++) {

			System.out.println("I: " + i);
			q = i / 4;
			if (q > 0 && (q + 5 * (i % 4)) % 4 == 0) {
				System.out.println("q: " + q);
				j = q + 5 * ((i - 1) % 4) + 1;
			} else {
				System.out.println("q:in " + q);
				j = q + 5 * (i % 4);
				if (j > 15)
					j -= 4;
			}
			if (i == 14)
				j = 9;
			System.out.println("J: " + " : " + (j));
			temp[i] = xor_func(t1[j], w[(i % 4) + (round * Nb)]);

		}
		
		/*for(i=0;i<16;i++) {
			
			temp[i] = xor_func(temp[i % 4 * 4 + i / 4],w[(i % 4) + (round * Nb)] );
			
		}*/
		
		return temp;

	}

	private static byte[][] invIBDAddRoundKey(byte[][] s1, byte[][] s2,
			byte[][] s3, byte[][] s4, byte[][] w, int round) {

		int c = -1;
		int i = 0;
		int k, j;
		byte[][] temp = new byte[16][4];
		byte[][] t1 = new byte[16][4];
		for (i = 0; i < 4; i++) {

			temp[i] = s1[i];
			temp[i + 4] = s2[i];
			temp[i + 4 * 2] = s3[i];
			temp[i + 4 * 3] = s4[i];
			
			t1[i] = s1[i];
			t1[i + 4] = s2[i];
			t1[i + 4 * 2] = s3[i];
			t1[i + 4 * 3] = s4[i];
		}

		for (i = 0; i < 16; i++) {

			k = i;
			if (i % 4 == 0) {
				c++;
			}
			if (c != 0) {
				k = i - c;
			}
			//System.out.println("Decryption:");
			j = (k * 4) % 16 + c;
			//System.out.println("j: "+j);
			temp[i] = xor_func(t1[j], w[(c) + (round * Nb)]);

		}

		return temp;

	}

	private static byte[][] SubBytes(byte[][] state) {

		byte[][] tmp = new byte[state.length][state[0].length];
		for (int row = 0; row < 4; row++) {
			for (int col = 0; col < Nb; col++) {
				tmp[row][col] = (byte) (sbox[(state[row][col] & 0x000000ff)] & 0xff);
			}
		}

		return tmp;
	}

	private static byte[][] InvSubBytes(byte[][] state) {
		for (int row = 0; row < 4; row++)
			for (int col = 0; col < Nb; col++)
				state[row][col] = (byte) (inv_sbox[(state[row][col] & 0x000000ff)] & 0xff);

		return state;
	}

	private static byte[][] ShiftRows(byte[][] state) {

		byte[] t = new byte[4];
		for (int r = 1; r < 4; r++) {
			for (int c = 0; c < Nb; c++)
				t[c] = state[r][(c + r) % Nb];
			for (int c = 0; c < Nb; c++)
				state[r][c] = t[c];
		}

		return state;
	}

	private static byte[][] InvShiftRows(byte[][] state) {
		byte[] t = new byte[4];
		for (int r = 1; r < 4; r++) {
			for (int c = 0; c < Nb; c++)
				t[(c + r) % Nb] = state[r][c];
			for (int c = 0; c < Nb; c++)
				state[r][c] = t[c];
		}
		return state;
	}

	private static byte[][] InvMixColumns(byte[][] s) {
		int[] sp = new int[4];
		byte b02 = (byte) 0x0e, b03 = (byte) 0x0b, b04 = (byte) 0x0d, b05 = (byte) 0x09;
		for (int c = 0; c < 4; c++) {
			sp[0] = FFMul(b02, s[0][c]) ^ FFMul(b03, s[1][c])
					^ FFMul(b04, s[2][c]) ^ FFMul(b05, s[3][c]);
			sp[1] = FFMul(b05, s[0][c]) ^ FFMul(b02, s[1][c])
					^ FFMul(b03, s[2][c]) ^ FFMul(b04, s[3][c]);
			sp[2] = FFMul(b04, s[0][c]) ^ FFMul(b05, s[1][c])
					^ FFMul(b02, s[2][c]) ^ FFMul(b03, s[3][c]);
			sp[3] = FFMul(b03, s[0][c]) ^ FFMul(b04, s[1][c])
					^ FFMul(b05, s[2][c]) ^ FFMul(b02, s[3][c]);
			for (int i = 0; i < 4; i++)
				s[i][c] = (byte) (sp[i]);
		}

		return s;
	}

	private static byte[][] MixColumns(byte[][] s) {
		int[] sp = new int[4];
		byte b02 = (byte) 0x02, b03 = (byte) 0x03;
		for (int c = 0; c < 4; c++) {
			sp[0] = FFMul(b02, s[0][c]) ^ FFMul(b03, s[1][c]) ^ s[2][c]
					^ s[3][c];
			sp[1] = s[0][c] ^ FFMul(b02, s[1][c]) ^ FFMul(b03, s[2][c])
					^ s[3][c];
			sp[2] = s[0][c] ^ s[1][c] ^ FFMul(b02, s[2][c])
					^ FFMul(b03, s[3][c]);
			sp[3] = FFMul(b03, s[0][c]) ^ s[1][c] ^ s[2][c]
					^ FFMul(b02, s[3][c]);
			for (int i = 0; i < 4; i++) {
				s[i][c] = (byte) (sp[i]);
			}
		}

		return s;
	}

	public static byte FFMul(byte a, byte b) {
		byte aa = a, bb = b, r = 0, t;
		while (aa != 0) {
			if ((aa & 1) != 0) {
				r = (byte) (r ^ bb);
			}
			t = (byte) (bb & 0x80);
			bb = (byte) (bb << 1);
			if (t != 0) {
				bb = (byte) (bb ^ 0x1b);
			}
			aa = (byte) ((aa & 0xff) >> 1);
		}
		return r;
	}

	public static byte[] parEncryptBitD(byte[] in) {

		byte[] tmp = new byte[in.length];
		byte[][] state1 = new byte[4][Nb];
		byte[][] state2 = new byte[4][Nb];
		byte[][] state3 = new byte[4][Nb];
		byte[][] state4 = new byte[4][Nb];

		int i;
		// System.out.println("Length in: "+ in.length);
		for (i = 0; i < 16; i++) {

			state1[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
		    //System.out.println("s1 i: "+(i % 4 * 4 + i / 4));
		}
		for (i = 0; i < 16; i++) {

			state2[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 16];
			//System.out.println("s2 i: "+((i % 4 * 4 + i / 4)+16));
		}
		for (i = 0; i < 16; i++) {
			state3[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 32];
			//System.out.println("s3 i: "+((i % 4 * 4 + i / 4)+32));
		}
		for (i = 0; i < 16; i++) {
			state4[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 48];
			//System.out.println("s4 i: "+((i % 4 * 4 + i / 4)+48));
		}

		state1 = AddRoundKey(state1, w, 0);
		state2 = AddRoundKey(state2, w, 0);
		state3 = AddRoundKey(state3, w, 0);
		state4 = AddRoundKey(state4, w, 0);

		for (int round = 1; round < Nr; round++) {
			state1 = SubBytes(state1);
			state2 = SubBytes(state2);
			state3 = SubBytes(state3);
			state4 = SubBytes(state4);

			state1 = ShiftRows(state1);
			state2 = ShiftRows(state2);
			state3 = ShiftRows(state3);
			state4 = ShiftRows(state4);

			state1 = MixColumns(state1);
			state2 = MixColumns(state2);
			state3 = MixColumns(state3);
			state4 = MixColumns(state4);

			byte[][] tState = IBitDAddRoundKey(state1, state2, state3, state4, w,
					round);

			for (int j = 0; j < 4; j++) {

				state1[j] = tState[j];

			}
			for (int j = 0; j < 4; j++) {

				state2[j] = tState[j + 4];

			}
			for (int j = 0; j < 4; j++) {

				state3[j] = tState[j + 8];

			}
			for (int j = 0; j < 4; j++) {

				state4[j] = tState[j + 12];

			}
		}

		state1 = SubBytes(state1);
		state2 = SubBytes(state2);
		state3 = SubBytes(state3);
		state4 = SubBytes(state4);

		state1 = ShiftRows(state1);
		state2 = ShiftRows(state2);
		state3 = ShiftRows(state3);
		state4 = ShiftRows(state4);

		state1 = AddRoundKey(state1, w, Nr);
		state2 = AddRoundKey(state2, w, Nr);
		state3 = AddRoundKey(state3, w, Nr);
		state4 = AddRoundKey(state4, w, Nr);

		for (i = 0; i < 16; i++) {
			tmp[i % 4 * 4 + i / 4] = state1[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 16] = state2[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 32] = state3[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 48] = state4[i / 4][i % 4];
		}

		return tmp;

	}
	
	public static byte[] parEncryptByteD(byte[] in) {

		byte[] tmp = new byte[in.length];
		byte[][] state1 = new byte[4][Nb];
		byte[][] state2 = new byte[4][Nb];
		byte[][] state3 = new byte[4][Nb];
		byte[][] state4 = new byte[4][Nb];

		int i;
		// System.out.println("Length in: "+ in.length);
		for (i = 0; i < 16; i++) {

			state1[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
		    //System.out.println("s1 i: "+(i % 4 * 4 + i / 4));
		}
		for (i = 0; i < 16; i++) {

			state2[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 16];
			//System.out.println("s2 i: "+((i % 4 * 4 + i / 4)+16));
		}
		for (i = 0; i < 16; i++) {
			state3[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 32];
			//System.out.println("s3 i: "+((i % 4 * 4 + i / 4)+32));
		}
		for (i = 0; i < 16; i++) {
			state4[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 48];
			//System.out.println("s4 i: "+((i % 4 * 4 + i / 4)+48));
		}

		state1 = AddRoundKey(state1, w, 0);
		state2 = AddRoundKey(state2, w, 0);
		state3 = AddRoundKey(state3, w, 0);
		state4 = AddRoundKey(state4, w, 0);

		for (int round = 1; round < Nr; round++) {
			state1 = SubBytes(state1);
			state2 = SubBytes(state2);
			state3 = SubBytes(state3);
			state4 = SubBytes(state4);

			state1 = ShiftRows(state1);
			state2 = ShiftRows(state2);
			state3 = ShiftRows(state3);
			state4 = ShiftRows(state4);

			state1 = MixColumns(state1);
			state2 = MixColumns(state2);
			state3 = MixColumns(state3);
			state4 = MixColumns(state4);

			byte[][] tState = IBDAddRoundKey(state1, state2, state3, state4, w,
					round);

			for (int j = 0; j < 4; j++) {

				state1[j] = tState[j];

			}
			for (int j = 0; j < 4; j++) {

				state2[j] = tState[j + 4];

			}
			for (int j = 0; j < 4; j++) {

				state3[j] = tState[j + 8];

			}
			for (int j = 0; j < 4; j++) {

				state4[j] = tState[j + 12];

			}
		}

		state1 = SubBytes(state1);
		state2 = SubBytes(state2);
		state3 = SubBytes(state3);
		state4 = SubBytes(state4);

		state1 = ShiftRows(state1);
		state2 = ShiftRows(state2);
		state3 = ShiftRows(state3);
		state4 = ShiftRows(state4);

		state1 = AddRoundKey(state1, w, Nr);
		state2 = AddRoundKey(state2, w, Nr);
		state3 = AddRoundKey(state3, w, Nr);
		state4 = AddRoundKey(state4, w, Nr);

		for (i = 0; i < 16; i++) {
			tmp[i % 4 * 4 + i / 4] = state1[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 16] = state2[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 32] = state3[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 48] = state4[i / 4][i % 4];
		}

		return tmp;

	}

	public static byte[] parEncrypt(byte[] in) {

		byte[] tmp = new byte[in.length];
		byte[][] state1 = new byte[4][Nb];
		byte[][] state2 = new byte[4][Nb];
		byte[][] state3 = new byte[4][Nb];
		byte[][] state4 = new byte[4][Nb];

		int i;
		// System.out.println("Length in: "+ in.length);
		for (i = 0; i < 16; i++) {

			state1[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
			// System.out.println("i: "+(i % 4 * 4 + i / 4));
		}
		for (i = 0; i < 16; i++) {

			state2[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 16];
		}
		for (i = 0; i < 16; i++) {
			state3[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 32];
		}
		for (i = 0; i < 16; i++) {
			state4[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 48];
		}

		state1 = AddRoundKey(state1, w, 0);
		state2 = AddRoundKey(state2, w, 0);
		state3 = AddRoundKey(state3, w, 0);
		state4 = AddRoundKey(state4, w, 0);

		for (int round = 1; round < Nr; round++) {

			state1 = SubBytes(state1);
			state2 = SubBytes(state2);
			state3 = SubBytes(state3);
			state4 = SubBytes(state4);

			state1 = ShiftRows(state1);
			state2 = ShiftRows(state2);
			state3 = ShiftRows(state3);
			state4 = ShiftRows(state4);

			state1 = MixColumns(state1);
			state2 = MixColumns(state2);
			state3 = MixColumns(state3);
			state4 = MixColumns(state4);

			state1 = AddRoundKey(state1, w, round);
			state2 = AddRoundKey(state2, w, round);
			state3 = AddRoundKey(state3, w, round);
			state4 = AddRoundKey(state4, w, round);

		}

		state1 = SubBytes(state1);
		state2 = SubBytes(state2);
		state3 = SubBytes(state3);
		state4 = SubBytes(state4);

		state1 = ShiftRows(state1);
		state2 = ShiftRows(state2);
		state3 = ShiftRows(state3);
		state4 = ShiftRows(state4);

		state1 = AddRoundKey(state1, w, Nr);
		state2 = AddRoundKey(state2, w, Nr);
		state3 = AddRoundKey(state3, w, Nr);
		state4 = AddRoundKey(state4, w, Nr);

		for (i = 0; i < 16; i++) {
			tmp[i % 4 * 4 + i / 4] = state1[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 16] = state2[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 32] = state3[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 48] = state4[i / 4][i % 4];
		}

		return tmp;

	}

	public static byte[] encryptBlock(byte[] in) {
		byte[] tmp = new byte[in.length];
		//System.out.println("Block Length:" + in.length);
		byte[][] state = new byte[4][Nb];

		for (int i = 0; i < in.length; i++) {
			state[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
			// state[i / 4][i % 4] = in[i];
			// int a = i % 4 * 4 + i / 4;
			System.out.println("i%4 :" + (i % 4 * 4 + i / 4));
		}

		state = AddRoundKey(state, w, 0);
		for (int round = 1; round < Nr; round++) {
			state = SubBytes(state);
			state = ShiftRows(state);
			state = MixColumns(state);
			state = AddRoundKey(state, w, round);
		}
		state = SubBytes(state);
		state = ShiftRows(state);
		state = AddRoundKey(state, w, Nr);

		for (int i = 0; i < tmp.length; i++) {
			tmp[i % 4 * 4 + i / 4] = state[i / 4][i % 4];
		}
		System.out.println("Encrypted Length= " + tmp.length);
		return tmp;
	}

	public static byte[] parDecrypt(byte[] in) {

		byte[] tmp = new byte[in.length];
		byte[][] state1 = new byte[4][Nb];
		byte[][] state2 = new byte[4][Nb];
		byte[][] state3 = new byte[4][Nb];
		byte[][] state4 = new byte[4][Nb];

		int i;
		// System.out.println("Length in: "+ in.length);
		for (i = 0; i < 16; i++) {

			state1[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
			// System.out.println("i: "+(i % 4 * 4 + i / 4));
		}
		for (i = 0; i < 16; i++) {

			state2[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 16];
		}
		for (i = 0; i < 16; i++) {
			state3[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 32];
		}
		for (i = 0; i < 16; i++) {
			state4[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 48];
		}

		state1 = AddRoundKey(state1, w, Nr);
		state2 = AddRoundKey(state2, w, Nr);
		state3 = AddRoundKey(state3, w, Nr);
		state4 = AddRoundKey(state4, w, Nr);

		for (int round = Nr - 1; round > 0; round--) {

			state1 = InvShiftRows(state1);
			state2 = InvShiftRows(state2);
			state3 = InvShiftRows(state3);
			state4 = InvShiftRows(state4);

			state1 = InvSubBytes(state1);
			state2 = InvSubBytes(state2);
			state3 = InvSubBytes(state3);
			state4 = InvSubBytes(state4);

			state1 = AddRoundKey(state1, w, round);
			state2 = AddRoundKey(state2, w, round);
			state3 = AddRoundKey(state3, w, round);
			state4 = AddRoundKey(state4, w, round);

			state1 = InvMixColumns(state1);
			state2 = InvMixColumns(state2);
			state3 = InvMixColumns(state3);
			state4 = InvMixColumns(state4);

		}

		state1 = InvShiftRows(state1);
		state2 = InvShiftRows(state2);
		state3 = InvShiftRows(state3);
		state4 = InvShiftRows(state4);

		state1 = InvSubBytes(state1);
		state2 = InvSubBytes(state2);
		state3 = InvSubBytes(state3);
		state4 = InvSubBytes(state4);

		state1 = AddRoundKey(state1, w, 0);
		state2 = AddRoundKey(state2, w, 0);
		state3 = AddRoundKey(state3, w, 0);
		state4 = AddRoundKey(state4, w, 0);

		for (i = 0; i < 16; i++) {
			tmp[i % 4 * 4 + i / 4] = state1[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 16] = state2[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 32] = state3[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 48] = state4[i / 4][i % 4];
		}

		return tmp;

	}

	public static byte[] parDecryptBitD(byte[] in) {

		byte[] tmp = new byte[in.length];
		byte[][] state1 = new byte[4][Nb];
		byte[][] state2 = new byte[4][Nb];
		byte[][] state3 = new byte[4][Nb];
		byte[][] state4 = new byte[4][Nb];

		int i;
		// System.out.println("Length in: "+ in.length);
		for (i = 0; i < 16; i++) {

			state1[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
			System.out.println("i: "+(i % 4 * 4 + i / 4));
		}

		for (i = 0; i < 16; i++) {

			state2[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 16];
		}

		for (i = 0; i < 16; i++) {
			state3[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 32];
		}

		for (i = 0; i < 16; i++) {
			state4[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 48];
		}

		state1 = AddRoundKey(state1, w, Nr);
		state2 = AddRoundKey(state2, w, Nr);
		state3 = AddRoundKey(state3, w, Nr);
		state4 = AddRoundKey(state4, w, Nr);

		for (int round = Nr - 1; round > 0; round--) {

			state1 = InvShiftRows(state1);
			state2 = InvShiftRows(state2);
			state3 = InvShiftRows(state3);
			state4 = InvShiftRows(state4);

			state1 = InvSubBytes(state1);
			state2 = InvSubBytes(state2);
			state3 = InvSubBytes(state3);
			state4 = InvSubBytes(state4);

			byte[][] tState = InvIBitDAddRoundKey(state1, state2, state3, state4,
					w, round);

			for (int j = 0; j < 4; j++) {

				state1[j] = tState[j];

			}
			for (int j = 0; j < 4; j++) {

				state2[j] = tState[j + 4];

			}
			for (int j = 0; j < 4; j++) {

				state3[j] = tState[j + 8];

			}
			for (int j = 0; j < 4; j++) {

				state4[j] = tState[j + 12];

			}

			state1 = InvMixColumns(state1);
			state2 = InvMixColumns(state2);
			state3 = InvMixColumns(state3);
			state4 = InvMixColumns(state4);

		}

		state1 = InvShiftRows(state1);
		state2 = InvShiftRows(state2);
		state3 = InvShiftRows(state3);
		state4 = InvShiftRows(state4);

		state1 = InvSubBytes(state1);
		state2 = InvSubBytes(state2);
		state3 = InvSubBytes(state3);
		state4 = InvSubBytes(state4);

		state1 = AddRoundKey(state1, w, 0);
		state2 = AddRoundKey(state2, w, 0);
		state3 = AddRoundKey(state3, w, 0);
		state4 = AddRoundKey(state4, w, 0);

		for (i = 0; i < 16; i++) {
			tmp[i % 4 * 4 + i / 4] = state1[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 16] = state2[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 32] = state3[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 48] = state4[i / 4][i % 4];
		}

		return tmp;

	}
	
	public static byte[] parDecryptByteD(byte[] in) {

		byte[] tmp = new byte[in.length];
		byte[][] state1 = new byte[4][Nb];
		byte[][] state2 = new byte[4][Nb];
		byte[][] state3 = new byte[4][Nb];
		byte[][] state4 = new byte[4][Nb];

		int i;
		// System.out.println("Length in: "+ in.length);
		for (i = 0; i < 16; i++) {

			state1[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
			System.out.println("i: "+(i % 4 * 4 + i / 4));
		}

		for (i = 0; i < 16; i++) {

			state2[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 16];
		}

		for (i = 0; i < 16; i++) {
			state3[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 32];
		}

		for (i = 0; i < 16; i++) {
			state4[i / 4][i % 4] = in[(i % 4 * 4 + i / 4) + 48];
		}

		state1 = AddRoundKey(state1, w, Nr);
		state2 = AddRoundKey(state2, w, Nr);
		state3 = AddRoundKey(state3, w, Nr);
		state4 = AddRoundKey(state4, w, Nr);

		for (int round = Nr - 1; round > 0; round--) {

			state1 = InvShiftRows(state1);
			state2 = InvShiftRows(state2);
			state3 = InvShiftRows(state3);
			state4 = InvShiftRows(state4);

			state1 = InvSubBytes(state1);
			state2 = InvSubBytes(state2);
			state3 = InvSubBytes(state3);
			state4 = InvSubBytes(state4);

			byte[][] tState = invIBDAddRoundKey(state1, state2, state3, state4,
					w, round);

			for (int j = 0; j < 4; j++) {

				state1[j] = tState[j];

			}
			for (int j = 0; j < 4; j++) {

				state2[j] = tState[j + 4];

			}
			for (int j = 0; j < 4; j++) {

				state3[j] = tState[j + 8];

			}
			for (int j = 0; j < 4; j++) {

				state4[j] = tState[j + 12];

			}

			state1 = InvMixColumns(state1);
			state2 = InvMixColumns(state2);
			state3 = InvMixColumns(state3);
			state4 = InvMixColumns(state4);

		}

		state1 = InvShiftRows(state1);
		state2 = InvShiftRows(state2);
		state3 = InvShiftRows(state3);
		state4 = InvShiftRows(state4);

		state1 = InvSubBytes(state1);
		state2 = InvSubBytes(state2);
		state3 = InvSubBytes(state3);
		state4 = InvSubBytes(state4);

		state1 = AddRoundKey(state1, w, 0);
		state2 = AddRoundKey(state2, w, 0);
		state3 = AddRoundKey(state3, w, 0);
		state4 = AddRoundKey(state4, w, 0);

		for (i = 0; i < 16; i++) {
			tmp[i % 4 * 4 + i / 4] = state1[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 16] = state2[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 32] = state3[i / 4][i % 4];
		}
		for (i = 0; i < 16; i++) {
			tmp[(i % 4 * 4 + i / 4) + 48] = state4[i / 4][i % 4];
		}

		return tmp;

	}

	public static byte[] decryptBloc(byte[] in) {
		byte[] tmp = new byte[in.length];

		byte[][] state = new byte[4][Nb];

		for (int i = 0; i < in.length; i++) {
			state[i / 4][i % 4] = in[i % 4 * 4 + i / 4];
		}

		state = AddRoundKey(state, w, Nr);
		for (int round = Nr - 1; round >= 1; round--) {

			state = InvShiftRows(state);
			state = InvSubBytes(state);
			state = AddRoundKey(state, w, round);
			state = InvMixColumns(state);
		}

		state = InvShiftRows(state);
		state = InvSubBytes(state);
		state = AddRoundKey(state, w, 0);

		for (int i = 0; i < tmp.length; i++) {
			tmp[i % 4 * 4 + i / 4] = state[i / 4][i % 4];
		}

		return tmp;
	}

	public static byte[] encrypt(byte[] in, byte[] key) {

		Nb = 4;// Number ofk column
		Nk = 4;// Number of words of the key
		Nr = 10;// Number of Rounds

		int lenght = 0;
		byte[] padding = new byte[1];
		
		int i;

		lenght = 64 - in.length % 64;
		padding = new byte[lenght];
		padding[0] = (byte) 0x80;

		for (i = 1; i < lenght; i++)
			padding[i] = 0;

		byte[] tmp = new byte[in.length + lenght];
		byte[] block = new byte[64];

		w = generateSubkeys(key);

		int count = 0;

		// System.out.println("In.Length= "+in.length +" Length= "+lenght);

		for (i = 0; i < in.length + lenght; i++) {
			if (i > 0 && i % 64 == 0) {
				System.out.println("Block Length: "+block.length);
				//block = encryptBlock(block);
				// block = parEncrypt(block);
				//block = parEncryptByteD(block);
				block = parEncryptBitD(block);
				System.arraycopy(block, 0, tmp, i - 64, block.length);
				// System.out.println("Encrypted Blcok= "+i%16+": "+new
				// String(tmp));
			}
			if (i < in.length) {
				block[i % 64] = in[i];
				// System.out.println("block["+(i%16)+"]="+in[i]);
			} else {
				block[i % 64] = padding[count % 64];

				// System.out.println("Padding block["+(i%16)+"]="+padding[count%16]);
				count++;
			}
		}
		// System.out.println("i:"+block.length);
		if (block.length == 64) {
			// block = encryptBlock(block);
			// block = parEncrypt(block);
			//block = parEncryptByteD(block);
			block = parEncryptBitD(block);
			System.arraycopy(block, 0, tmp, i - 64, block.length);
		}
		// System.out.println("Lenth Enc: "+tmp.length);
		return tmp;
	}

	public static byte[] decrypt(byte[] in, byte[] key) {
		int i;
		byte[] tmp = new byte[in.length];
		byte[] block = new byte[64];

		Nb = 4;
		Nk = 4;
		Nr = 10;
		w = generateSubkeys(key);
		//System.out.println("Dec InLength: " + in.length);
		for (i = 0; i < in.length; i++) {
			if (i > 0 && i % 64 == 0) {
				// block = decryptBloc(block);
				// block = parDecrypt(block);
				//block = parDecryptByteD(block);
				block = parDecryptBitD(block);
				System.arraycopy(block, 0, tmp, i - 64, block.length);
			}
			if (i < in.length) {
				block[i % 64] = in[i];
			}
		}

		if (block.length == 64) {

			 //block = decryptBloc(block);
			// block = parDecrypt(block);
			//block = parDecryptByteD(block);
			block = parDecryptBitD(block);
			System.arraycopy(block, 0, tmp, i - 64, block.length);

		}

		tmp = deletePadding(tmp);

		return tmp;
	}

	private static byte[] deletePadding(byte[] input) {
		int count = 0;

		int i = input.length - 1;
		while (input[i] == 0) {
			count++;
			i--;
		}

		byte[] tmp = new byte[input.length - count - 1];
		System.arraycopy(input, 0, tmp, 0, tmp.length);
		return tmp;
	}

}