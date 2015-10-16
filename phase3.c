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

int debugflag3 = 0;

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

    //initialize mailboxes
    procTable_mutex = MboxCreate(1, 0);

    /*
     * Data structure initialization as needed...
     * Need proc table again
     */

    int i;
    //initialize  syscalls to nullsys3 function
    for(i = 0; i<MAXSYSCALLS; i++)
        systemCallVec[i] = nullsys3;


    //no idea why spawn_num is set to 3, other syscalls being used?
    systemCallVec[3] = spawn;
    systemCallVec[4] = wait1;
    systemCallVec[5] = terminate;

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

    
    MboxSend(procTable_mutex, NULL, 0);

    //inititalize process table
    for(i = 0; i < MAXPROC; i++){
        procTable[i].pid = -1;
        procTable[i].parentPid = -1;
        procTable[i].nextChild = NULL;
        procTable[i].nextSib = NULL;
        procTable[i].parent = NULL;
        procTable[i].priority = -1;
        procTable[i].start_func = NULL;
        procTable[i].name = NULL;
        procTable[i].arg = NULL;
        procTable[i].stack_size = -1;
        procTable[i].privateMbox = -1;
        procTable[i].termCode = -1;
        procTable[i].status = -1;
    }
    //proc table setup, in case we fdo a dump_proc later
    procTable[1].name = "sentinel";
    procTable[1].priority = 6;
    procTable[1].pid = 1;
    procTable[1].status = READY;
    procTable[2].name = "start1";
    procTable[2].priority = 1;
    procTable[2].pid = 2;
    procTable[2].status = JOIN_BLOCKED;



    //get start2 entry completely set up, will be important for spawnReal  
    procTable[getpid()].pid = getpid();
    procTable[getpid()].parentPid = 2;  //start1 PID
    procTable[getpid()].start_func = start2;
    procTable[getpid()].name = "start2";
    procTable[getpid()].status = READY;
    procTable[getpid()].arg = arg;
    procTable[getpid()].stack_size = USLOSS_MIN_STACK;
    procTable[getpid()].priority = 1;
    procTable[getpid()].nextChild = NULL;
    procTable[getpid()].nextSib = NULL;
    procTable[getpid()].parent = NULL;
    procTable[getpid()].privateMbox = MboxCreate(0,sizeof(int[2]));
    procTable[getpid()].termCode = -1;

    MboxReceive(procTable_mutex, NULL, 0);

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
     //MboxSend(toBlock, NULL, 0);
     pid = wait1Real(&status);

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

void setToUserMode()
{
    unsigned int psr = USLOSS_PsrGet();
    psr = psr >> 1;
    psr = psr << 1;
    USLOSS_PsrSet(psr);
}
/*
*   spawn will extract the arguments from the systemArgs stuct given by
*   Spawn(). It will then pass these arguments along to spawnReal()
*
*   After the call to spawnReal(), spawn must check to make sure everything
*   is still okay i.e. not zapped, proper PID returned, etc.
*
*   Side Effects: sets values of arg1 and arg4 of *args stuct
*/
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
    if (priority < 1 || priority > 5){
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
    //no errors at this point, arg4 can be set to 0
    args->arg4 = 0;
    //will return to user level function, set to user mode!
    setToUserMode();
    return;

}

/*
*   spawnReal makes the actuall call to fork1, then updates the process
*   table
*
*   Side Effects: Saves values of func and arg in next_func and next_arg
*   to be used in spawnLaunch. 
*/
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
    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): called fork1() to create new process\n");

    //send to mutex box to edit proc table
    //BEGIN CRITICAL SECTION
    MboxSend(procTable_mutex, NULL, 0);

    procTable[kpid].pid = kpid;
    procTable[kpid].start_func = func;
    procTable[kpid].name = name;
    //prevents seg fault if arg is NULL
    if(arg == NULL) 
        procTable[kpid].arg = NULL; 
    else 
        strcpy(procTable[kpid].arg, arg);
    procTable[kpid].stack_size = stack_size;
    procTable[kpid].priority = priority;
    procTable[kpid].nextChild = NULL;
    procTable[kpid].parent = &procTable[getpid()];
    procTable[kpid].parentPid = getpid();
    //it's possible this was made alredy in spawn launch
    if (procTable[kpid].privateMbox == -1)
        procTable[kpid].privateMbox = MboxCreate(0, sizeof(int[2]));

    //add to parent's child list (via linked list traversal if needed)
    if (procTable[getpid()].nextChild != NULL){
        //there are other children in the list, add to end
        procPtr cur = procTable[getpid()].nextChild;
        while (cur->nextSib != NULL){
            cur = cur->nextSib;
        }
        //cur now points to last sib in the list
        cur->nextSib = &procTable[kpid];

    }else{
        //this is the parents first child
        procTable[getpid()].nextChild = &procTable[kpid];
    }

    //END CRITICAL SECTION
    //release mutex box for proc table
    MboxReceive(procTable_mutex, NULL, 0);

    //just in case the child had higher priority, it's stuck in spawnLaunch
    MboxCondSend(procTable[kpid].privateMbox, NULL, 0);

    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): added new process to the procTable\n");

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

    //create the mailbox and block so that spawnReal can finish making the proc table before moving on!
    if (procTable[getpid()].pid != getpid()){
        procTable[getpid()].privateMbox = MboxCreate(0, sizeof(int[2]));
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): finishing process table creation\n");
        MboxReceive(procTable[getpid()].privateMbox, 0, 0);
    }
    //switch to user mode
    //The idea here is to shift off the current mode bit and bring it
    //back in as 0
    setToUserMode();

    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): PRS set to user mode\n");

    int result = next_func(next_arg);

    //terminate proc when/if it gets here, may term itself before this
    USLOSS_Halt(1);

}

void wait1(systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1(): at beginning\n");
    //Wait has no input, check to make sure it was called legally
    if (procTable[getpid()].nextChild == NULL){
        USLOSS_Console("wait1(): process calling Wait has no children!\n");
        USLOSS_Halt(1);
    }
    int kpid, status;
    kpid = wait1Real(&status);
    //set output in args
    args->arg1 = (void *) kpid;
    args->arg2 = (void *) status;
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1(): a child terminated, returning\n");
    setToUserMode();


}

int wait1Real(int * status)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1Real(): blocking process on mailbox\n");
    //getting here means it just needs to wait to be woken up

    //this array contains [ -1, -1], and will be the result of the recieve
    //                  [kpid to return, status to assign]
    int result [] = {-1, -1};

    //modify status
    MboxSend(procTable_mutex, NULL, 0);
    procTable[getpid()].status = WAIT_BLOCKED;
    MboxReceive(procTable_mutex, NULL, 0);

    //block
    MboxReceive(procTable[getpid()].privateMbox, result, sizeof(int[2]));

    //process has been woken up by send of terminating child
    //get in synch with child and wait until child completely quits
    zap(result[0]);

    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1Real(): process is waking up from wait block\n");

    MboxSend(procTable_mutex, NULL, 0);
    procTable[getpid()].status = READY;
    MboxReceive(procTable_mutex, NULL, 0);

    *status = result[1];
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1Real(): Returning\n");
    return result[0];

}

void terminate (systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): at beginning\n");
    //extract arg1, the termination code
    int termCode = (int) args->arg1;

    //going to be reading proc table, don't want anyone to touch
    if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): sending to procTable_mutex\n");
    //MboxSend(procTable_mutex, NULL, 0);

    //if there isn't any children
    if (procTable[getpid()].nextChild == NULL){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): terminating process has no children\n");
        //if the parent is wait blocked, wake it up
        if (procTable[getpid()].parent->status == WAIT_BLOCKED){
            if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): terminating process's parent is wait blocked!\n");
            int message [] = {getpid(), termCode}; //build message
            MboxSend( procTable[procTable[getpid()].parent->pid].privateMbox, message, sizeof(message));
        }
    }
    //MboxReceive(procTable_mutex, NULL, 0);
    if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): calling quit after cleaning the proc table\n");

    if ( procTable[getpid()].nextSib == NULL )
        procTable[getpid()].parent->nextChild = NULL;
    else
        procTable[getpid()].parent->nextChild = procTable[getpid()].nextSib;
    cleanProcSlot(getpid());
    //dumpProc();
    quit(termCode);
}

//DO NOT CALL WITHOUT MUTEX CHECKED OUT
void cleanProcSlot(int i)
{
    procTable[i].pid = -1;
    procTable[i].parentPid = -1;
    procTable[i].nextChild = NULL;
    procTable[i].nextSib = NULL;
    procTable[i].parent = NULL;
    procTable[i].priority = -1;
    procTable[i].start_func = NULL;
    procTable[i].name = NULL;
    procTable[i].arg = NULL;
    procTable[i].stack_size = -1;
    procTable[i].privateMbox = -1;
    procTable[i].termCode = -1;
    procTable[i].status = -1;
}

/*
 * Displays the current processes in the process table and any relevant information
 */
void dumpProc(){
    USLOSS_Console("\n   NAME   |   PID   |   PRIORITY   |  STATUS   |   PPID   |\n");
    USLOSS_Console("-----------------------------------------------------------------------------------\n");
    int i;
    for(i = 0; i < 6; i++){
        USLOSS_Console(" %-9s| %-8d| %-13d|", procTable[i].name, procTable[i].pid, procTable[i].priority);
        switch(procTable[i].status){
            case READY:
                USLOSS_Console(" READY     ");
                break;
            case WAIT_BLOCKED:
                USLOSS_Console(" WBLOCKED  ");
                break;
            case JOIN_BLOCKED:
                USLOSS_Console(" JBLOCKED  ");
                break;
            default:
                USLOSS_Console("           ");
        }
        USLOSS_Console("| %-9d| %-12d| %-8d|\n", procTable[i].parentPid);
        USLOSS_Console("-----------------------------------------------------------------------------------\n");
    }
    
    USLOSS_Console("\n");
}



















