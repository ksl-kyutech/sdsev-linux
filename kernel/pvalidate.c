#define PVALIDATE 0x123455

#define TEST_NUM 0


unsigned int sys_pvalidate(unsigned long gpa)
{

	


    asm volatile(
        "li a0, %0;"
        "mv a1, %1;"
        ".word 0x00000000;"
        :: "i"(PVALIDATE), "r"(gpa)
        :"a0", "a1");

    

	

    return 0;
}