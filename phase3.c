#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <libuser.h>
#include <usyscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* -------------------------- Globals ------------------------------------- */ 

int debugflag3 = 1;

//sysvec array
//void (*sys_vec[MAXSYSCALLS])(systemArgs *args);
//void (*systemCallVec[MAXSYSCALLS])(systemArgs *args);
//process table
struct procSlot procTable[MAXPROC];
//process table editing mailbox
int procTable_mutex;
//next function ptr for spawnLaunch to execute
int (*next_func)(char *);
char * next_arg;



int start2(char *arg)
{
    int pid;
    int status;

    if (DEBUG3 && debugflag3)
        USLOSS_Console("start2(): at beginning\n");

    //check kernel mode
    if ( !inKernelMode("start2") ){
        USLOSS_Console("Start 2(): Not in kernel mode! Halting...");
        USLOSS_Halt(1);
    }
    /*
     * Data structure initialization as needed...
     * Need proc table again
     */

    int i;
    //initialize empty syscalls to nullsys3 function
    for(i = 0; i<MAXSYSCALLS; i++)
        systemCallVec[i] = nullsys3;


    //no idea why spawn_num is set to 3, other syscalls being used?
    systemCallVec[3] = spawn;


    /*
    Still need to create these functions

    sys_vec[2] = wait;
    sys_vec[3] = terminate;
    sys_vec[4] = semCreate;
    sys_vec[5] = semP;
    sys_vec[6] = semV;
    sys_vec[7] = semFree;
    sys_vec[8] = getTimeofDay;
    sys_vec[9] = cpuTime;
    sys_vec[10] = getPID;

    */

    

    //inititalize process table
    for(i = 0; i < MAXPROC; i++){
        procTable[i].pid = -1;
        procTable[i].nextProc = NULL;
        procTable[i].priority = -1;
    }
    //set up currently running procs


    //initialize mailboxes
    procTable_mutex = MboxCreate(1, 0);

    if (DEBUG3 && debugflag3)
        USLOSS_Console("start2(): data structures initialized\n");
    /*
     * Create first user-level process and wait for it to finish.
     * These are lower-case because they are not system calls;
     * system calls cannot be invoked from kernel mode.
     * Assumes kernel-mode versions of the system calls
     * with lower-case names.  I.e., Spawn is the user-mode function
     * called by the test cases; spawn is the kernel-mode function that
     * is called by the syscallHandler; spawnReal is the function that
     * contains the implementation and is called by spawn.
     *
     * Spawn() is in libuser.c.  It invokes USLOSS_Syscall()
     * The system call handler calls a function named spawn() -- note lower
     * case -- that extracts the arguments from the sysargs pointer, and
     * checks them for possible errors.  This function then calls spawnReal().
     *
     * Here, we only call spawnReal(), since we are already in kernel mode.
     *
     * spawnReal() will create the process by using a call to fork1 to
     * create a process executing the code in spawnLaunch().  spawnReal()
     * and spawnLaunch() then coordinate the completion of the phase 3
     * process table entries needed for the new process.  spawnReal() will
     * return to the original caller of Spawn, while spawnLaunch() will
     * begin executing the function passed to Spawn. spawnLaunch() will
     * need to switch to user-mode before allowing user code to execute.
     * spawnReal() will return to spawn(), which will put the return
     * values back into the sysargs pointer, switch to user-mode, and 
     * return to the user code that called Spawn.
     */
    pid = spawnReal("start3", start3, NULL, USLOSS_MIN_STACK, 3);

    /* Call the waitReal version of your wait code here.
     * You call waitReal (rather than Wait) because start2 is running
     * in kernel (not user) mode.
     */
     int toBlock = MboxCreate(0,0);
     MboxSend(toBlock, NULL, 0);
    //pid = waitReal(&status);

} /* start2 */

/*
 *checks the PSR for kernel mode
 *returns true in if its in kernel mode, and false if not
*/
int inKernelMode(char *procName)
{
    if( (USLOSS_PSR_CURRENT_MODE & USLOSS_PsrGet()) == 0 ) {
      USLOSS_Console("Kernel Error: Not in kernel mode, may not run %s()\n", procName);
      USLOSS_Halt(1);
      return 0;
    }
    else{
      return 1;
    }
}

void spawn (systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): at beginning\n");
    /* extract args and check for errors */
    //get address of function to spawn
    int (*func)(char *) = args->arg1;
    //get function name
    char* name = args->arg5;
    //get argument passed to spawned function
    char * arg = args->arg2;
    //get stack size
    int stack_size = (int) args->arg3;
    //get priority
    int priority = (int) args->arg4;

    //return if name is an illegal value
    if (name == NULL){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): illegal value for name! Returning\n");
        args->arg1 = (void *) -1;
        args->arg4 = (void *) -1;
        return;
    }
    //return if priority is an illegal value
    if (priority < 3 || priority > 5){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): illegal value for priority! Returning\n");
        args->arg1 = (void *) -1;
        args->arg4 = (void *) -1;
        return;
    }
    //return if stack size is and illegal value
    if (stack_size < USLOSS_MIN_STACK){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): illegal value for stack size! Returning\n");
        args->arg1 = (void *) -1;
        args->arg4 = (void *) -1;
        return;
    }
    //return if name is an illegal value
    if (strlen(name) > MAXNAME){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): illegal value for name! Returning\n");
        args->arg1 = (void *) -1;
        args->arg4 = (void *) -1;
        return;
    }
    //return if arg is an illegal value
    if ( arg != NULL && strlen(arg) > MAXARG){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): illegal value for arg! Returning\n");
        args->arg1 = (void *) -1;
        args->arg4 = (void *) -1;
        return;

    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): At end\n");
    }
    //arguments are legal, give them to spawnReal, pass arg1 for pid
    int kpid = spawnReal(name, func, arg, stack_size, priority);

    //check to make sure spawnReal worked
    if (kpid == -1){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawn(): fork1 failed to create process, returning -1\n");
        args->arg4 = (void *) -1;
    }

    //assign pid to proper spot of arg struct
    args->arg1 = kpid;

}

int spawnReal(char *name, int (*func)(char *), char *arg, 
    int stack_size, int priority)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): at beginning\n");
    int kpid;

    //get values needed by spawn launch to globals so it can launch
    next_func = func;
    if(arg == NULL) next_arg = NULL; else strcpy(next_arg, arg);

    //create new process
    kpid = fork1(name, spawnLaunch, arg, stack_size, priority);

    //send to mutex box to edit proc table
    MboxSend(procTable_mutex, NULL, 0);

    procTable[kpid].pid = kpid;
    procTable[kpid].start_func = func;
    procTable[kpid].name = name;
    if(arg == NULL) procTable[kpid].arg = NULL; else strcpy(procTable[kpid].arg, arg);
    procTable[kpid].stack_size = stack_size;
    procTable[kpid].priority = priority;
    procTable[kpid].nextProc = NULL;
    procTable[kpid].privateMbox = MboxCreate(0, 0);
    //release mutex box for proc table
    MboxReceive(procTable_mutex, NULL, 0);

    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): at end\n");
        
    //return kpid to spawn so it can set the return field
    return kpid;

}

//spawn launch won't actually return, but it fixes a warning if it returns int
int spawnLaunch()
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): at beginning\n");

    //switch to user mode
    //The idea here is to shift off the current mode bit and bring it
    //back in as 0
    unsigned int psr = USLOSS_PsrGet();
    psr = psr >> 1;
    psr = psr << 1;
    USLOSS_PsrSet(psr);

    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): PRS set to user mode\n");

    int result = next_func(next_arg);

    USLOSS_Halt(1);

}




















