#include <stdio.h>
#include <errno.h>
#include <ctype.h>

int fmemdump(FILE *f,void *addr, int len, const char *title) {
int i;
unsigned char *curaddr;
unsigned char *savaddr;

    errno = 0;                          /* clear residual errno value   */

    if (len < 1) {			/* let's be sane, please	*/
        errno = EINVAL;
        return -1;
    }

    if (title)				/* if he gave us a title...	*/
      fprintf(f,"memdump: %s\n\n\r",title);/* ...print it out for him.	*/

    curaddr = (unsigned char *)addr;	/* let's get started...		*/

    do {
        savaddr = curaddr;		/* we'll need this later...	*/
        fprintf(f," %08X   ",(unsigned int)curaddr); /* print current address */
        for (i = 0; i < 16; i++) {	/* print hex digits across	*/
            fprintf(f,"%02X",*curaddr++);/* print the hex digits	*/
            if (i == 3 || i == 7 || i == 11)
                fprintf(f," ");		/* separate on word boundary	*/
            if (curaddr >= ((unsigned char *)addr + len) )
                break;			/* we're done here		*/
        }
        for ( ; ++i < 16; ) {
            fprintf(f,"  ");		/* take up any slack		*/
            if (i == 3 || i == 7 || i == 11)
                fprintf(f," ");		/* separate on word boundary	*/
        }
        fprintf(f,"  *");
        for (i = 0; i < 16; i++) {
            if (!isprint(*savaddr) ||
                 *savaddr == '\t'  ||
                 *savaddr == '\r'  ||
                 *savaddr == '\n')
                fprintf(f,".");		/* non-printable character	*/
            else
                fprintf(f,"%c",*savaddr);  /* print the character	*/
            if (++savaddr >= ((unsigned char *)addr + len) )
                break;			/* we're done here		*/
        }
        for ( ; ++i < 16; ) {
            fprintf(f," ");		/* take up any slack		*/
        }
        fprintf(f,"*\n\r");		/* end of line			*/
    }
    while (curaddr < ((unsigned char *)addr + len) );

    return 0;				/* all done			*/
}

int memdump(void *addr, int len, const char *title) {
    return(fmemdump(stdout,addr,len,title));
}
