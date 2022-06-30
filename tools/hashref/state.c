/*
     Reference Implementation for 32-bit processor 
     The state consists of four 32-bit registers       
     state[3] || state[2] || state[1] || state[0]

     Implemented by Hongjun Wu
*/   

#define FrameBitsIV  0x10  
#define FrameBitsAD  0x30  
#define FrameBitsPC  0x50  //Framebits for plaintext/ciphertext      
#define FrameBitsFinalization 0x70       

#define NROUND1 128*5 
#define NROUND2 128*10

/*non-optimized state update function*/    
void state_update(unsigned int *state, const unsigned char *key, unsigned int number_of_steps)
{
	unsigned int i; 
	unsigned int t1, t2, t3, t4, feedback;
	//in each iteration, we compute 256 steps of the state update function. 
	for (i = 0; i < (number_of_steps >> 5); i++)
	{
		t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
		t2 = (state[2] >> 6)  | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
		t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
		t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
		feedback = state[0] ^ t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[i & 7];
		// shift 32 bit positions 
		state[0] = state[1]; state[1] = state[2]; state[2] = state[3];
		state[3] = feedback;
	}
}
