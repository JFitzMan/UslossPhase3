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

//process table
struct procSlot procTable[MAXPROC];
//process table editing mailbox
int procTable_mutex;
int semTable_mutex;
//table of semaphores
struct semaphore semTable[MAXSEMS];

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
    semTable_mutex = MboxCreate(1, 0);

    int i;
    //initialize  syscalls to nullsys3 function
    for(i = 0; i<MAXSYSCALLS; i++)
        systemCallVec[i] = nullsys3;


    //no idea why spawn_num is set to 3, other syscalls being used?
    systemCallVec[3] = spawn;
    systemCallVec[4] = wait1;
    systemCallVec[5] = terminate;
    //again, don't know why this jump happens
    systemCallVec[16] = semCreate;
    systemCallVec[17] = semP;
    systemCallVec[18] = semV;
    systemCallVec[19] = semFree;
    systemCallVec[20] = getTimeOfDay1;
    systemCallVec[21] = cpuTime;
    systemCallVec[22] = getPID;

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
        procTable[i].nextProc = NULL;
    }
    //proc table setup, in case we do a dump_proc later
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

    //inititalize semTable
    for(i = 0; i < MAXSEMS; i++){
        semTable[i].value = -1;
        semTable[i].nextBlockedProc = NULL;
        semTable[i].semID = -1;
    }

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
     //dumpProc();

     setToUserMode();
     if (DEBUG3 && debugflag3)
            USLOSS_Console("start2 is about to terminate\n");
     Terminate(1);


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
*   to be used in spawnLaunch. Also creates process table entry
*/
int spawnReal(char *name, int (*func)(char *), char *arg, 
    int stack_size, int priority)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): at beginning\n");
    int kpid;
    //create new process
    kpid = fork1(name, spawnLaunch, arg, stack_size, priority);
    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): called fork1() to create new process\n");
    if (kpid == -1){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): fork failed!\n");
        return -1;
    }

    //begin critical section, proc table entry creation
    if (DEBUG3 && debugflag3)
        USLOSS_Console("spawnReal(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);

    procTable[kpid].pid = kpid;
    procTable[kpid].start_func = func;
    procTable[kpid].name = name;
    procTable[kpid].status = READY;

    if(arg == NULL) {
        procTable[kpid].arg = NULL;
    }
    else {
        procTable[kpid].arg = &arg[0];
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): copied arg over, arg: %s\n", procTable[kpid].arg);
    }
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
        int i = 1;
        //there are other children in the list, add to end
        procPtr cur = procTable[getpid()].nextChild;
        while (cur->nextSib != NULL){
            cur = cur->nextSib;
            i++;
        }
        //cur now points to last sib in the list
        cur->nextSib = &procTable[kpid];
        if (DEBUG3 && debugflag3){
            USLOSS_Console("spawnReal(): this the %d child of process %d\n", i, getpid());
            cur = procTable[getpid()].nextChild;
            USLOSS_Console("List of children: ");
            while (cur != NULL){
                USLOSS_Console("%d,  ", cur->pid);
                cur = cur->nextSib;
            }
        }

    }else{
        //this is the parents first child
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): this is the first child of process %d\n", getpid());
        procTable[getpid()].nextChild = &procTable[kpid];
    }

    //end critical section, proc table entry creation
    if (DEBUG3 && debugflag3)
        USLOSS_Console("spawnReal(): Receiving from proc table mutex\n");
    MboxReceive(7, NULL, 0);
    //just in case the child had higher priority, it's stuck in spawnLaunch
    MboxCondSend(procTable[kpid].privateMbox, NULL, 0);

    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): added new process to the procTable\n");

    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnReal(): at end\n");

    //return kpid to spawn so it can set the return field
    return kpid;

}

/*
*   spawnLaunch will wait until spawnReal finishes the proc table entry
*   Then it will switch to usermode and begin executing the new process
*
*   If the new process returns without calling terminate, spawnlaunch will
*   make the call itself.
*/
int spawnLaunch()
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): at beginning\n");
    //checkout mailbox to get status 
    if (DEBUG3 && debugflag3)
        USLOSS_Console("spawnLaunch(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);

    //create the mailbox and block so that spawnReal can finish making the proc table before moving on!
    if (procTable[getpid()].pid != getpid()){
        procTable[getpid()].privateMbox = MboxCreate(0, sizeof(int[2]));
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): finishing process table creation\n");
        //check mailbox back in
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): Receiving from proc table mutex\n");
        MboxReceive(7, NULL, 0);
        MboxReceive(procTable[getpid()].privateMbox, 0, 0);
    }
    else{
        //still check back in anyway.
        if (DEBUG3 && debugflag3)
            USLOSS_Console("spawnLaunch(): Receiving from proc table mutex\n");
        MboxReceive(7, NULL, 0);
    }

    //check to see if it's been zapped while waiting to run, terminate if so
    if (isZapped()){
        //switch to user mode so we can easily just call Terminate(1)
        setToUserMode();

         if (DEBUG3 && debugflag3){
            USLOSS_Console("process was zapped! terminating\n");
            //USLOSS_Console("procTable[getpid()].arg:%s\n", procTable[getpid()].arg);
        }
        Terminate(1);
    }
    else{
        //switch to user mode
        setToUserMode();

        if (DEBUG3 && debugflag3){
            USLOSS_Console("spawnLaunch(): PRS set to user mode\n");
            //USLOSS_Console("procTable[getpid()].arg:%s\n", procTable[getpid()].arg);
        }

        int result = procTable[getpid()].start_func(procTable[getpid()].arg);
    
        //terminate proc when/if it gets here, may term itself before this
        Terminate(result);
    }

}
/*
*   wait1 first makes sure that the process actually has children
*   Then it calls wait real
*
*   When waitReal returns, it assigns the args to the sysargs and sets
*   the proc to user mode
*/
void wait1(systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1(): at beginning\n");
    //Wait has no input, check to make sure it was called legally
    if (DEBUG3 && debugflag3)
        USLOSS_Console("wait1(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);
    if (procTable[getpid()].nextChild == NULL){
        USLOSS_Console("wait1(): process calling Wait has no children!\n");
        args->arg1 = (void *) -1;
        args->arg2 = (void *) -1;
        if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1(): Receiving from proc table mutex\n");
        MboxReceive(7, NULL, 0);
    }
    else{
        if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1(): Receiving from proc table mutex\n");
        MboxReceive(7, NULL, 0);
    }
    int kpid, status;
    kpid = wait1Real(&status);
    //set output in args
    args->arg1 = (void *) kpid;
    args->arg2 = (void *) status;
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1(): a child terminated, returning\n");
    //setToUserMode();


}

/*
*   wait real switches the process's status to wait_blocked, then recieves
*   on its private box, essentially blocking itseldf
*
*   When it wakes up, it changes its status, and returns the proper results
*/
int wait1Real(int * status)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1Real(): blocking process on mailbox\n");
    //getting here means it just needs to wait to be woken up

    //this array contains [ -1, -1], and will be the result of the recieve
    //                  [kpid to return, status to assign]
    int result [] = {-1, -1};

    if (DEBUG3 && debugflag3)
        USLOSS_Console("wait1Real(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);

    //check to see if there are any zombie kids before blocking!
    if (procTable[getpid()].nextChild != NULL){

        //cur = first child
        procPtr cur = procTable[getpid()].nextChild;

        while (cur != NULL){
            //if cur is a zombie, we can wake it up, and we can just join
            if (cur->status == ZOMBIE){
                //check mutex back in
                if (DEBUG3 && debugflag3)
                    USLOSS_Console("wait1Real(): Receiving from proc table mutex\n");
                MboxReceive(7, NULL, 0);
                //wake up zombie kid
                MboxReceive(cur->privateMbox, result, sizeof(int[2]));
                //assign values from result array
                *status = result[1];
                if (DEBUG3 && debugflag3)
                   USLOSS_Console("wait1Real(): Zombie child! Returning\n");
                int stat;
                join(&stat);
    
                return result[0];
            }
           cur = cur->nextSib;
        }
    } 
    if (DEBUG3 && debugflag3)
        USLOSS_Console("wait1Real(): CondReceiving from proc table mutex, in case it had no zombies\n");
    MboxCondReceive(7, NULL, 0); 

    //modify status
    procTable[getpid()].status = WAIT_BLOCKED;

    //block
    MboxReceive(procTable[getpid()].privateMbox, result, sizeof(int[2]));
    if (DEBUG3 && debugflag3)
                   USLOSS_Console("wait1Real(): awake\n");

    //process has been woken up by send of terminating child    
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1Real(): process is waking up from wait block\n");

    if (DEBUG3 && debugflag3)
        USLOSS_Console("wait1Real(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);

    procTable[getpid()].status = READY;

    if (DEBUG3 && debugflag3)
        USLOSS_Console("wait1Real(): Receiving from proc table mutex\n");
    MboxReceive(7, NULL, 0);

    *status = result[1];
    if (DEBUG3 && debugflag3)
            USLOSS_Console("wait1Real(): Returning\n");
    return result[0];

}

/*
*   terminate extracts the termination code, and since it doesnt return,
*   doesn't really need to make a seperate call to any "termReal" or anything
*  
*   Terminate then checks if the process has any children
*   If it doesnt:
        It checks to see if there is a zap blocked parent
            If there is, it quits, parent will unblock automatically

*       It checks to see if there is a waitblocked parent
*           If there is it wakes up the parent
*
*       It checks to see if there is a running parent
*           Become a zombie

    If it does:
        It cycles through each one, releasing zombies and zapping kids

        It checks to see if there is a waitblocked parent
*           If there is it wakes up the parent
*
*       It checks to see if there is a running parent
*           Become a zombie

    Then it cleans the process table and calls quit.
*/

void terminate (systemArgs *args)
{

    if (DEBUG3 && debugflag3)
        USLOSS_Console("terminate(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);
    
    if (DEBUG3 && debugflag3)
        USLOSS_Console("terminate(): Receiving from proc table mutex\n");
    MboxReceive(7, NULL, 0);



    if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): at beginning\n");
    //extract arg1, the termination code
    int termCode = (int) args->arg1;

    if (DEBUG3 && debugflag3)
        USLOSS_Console("terminate(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);

    //if there isn't any children
    if (procTable[getpid()].nextChild == NULL){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): terminating process has no children\n");
        //if there parent is zap blocked, quit.
        if (procTable[getpid()].parent->status == ZAP_BLOCKED){
            if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): terminating process has been zapped! quiting\n");
            cleanProcSlot(getpid());
            //check mutex back in
            if (DEBUG3 && debugflag3)
                 USLOSS_Console("terminate(): Receiving from proc table mutex\n");
            MboxReceive(7, NULL, 0);
            quit(1);
        }
        //if the parent is wait blocked, wake it up
        else if (procTable[getpid()].parent->status == WAIT_BLOCKED){
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): terminating process's parent is wait blocked!\n");
            int message [] = {getpid(), termCode}; //build message
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): Receiving from proc table mutex\n");
            MboxReceive(7, NULL, 0);
            MboxSend( procTable[procTable[getpid()].parent->pid].privateMbox, message, sizeof(message));
        }
        //If the parent hasn't called wait, block as a zombie before quitting
        else if(procTable[getpid()].parent->status == READY){
            //set status to zombie
            procTable[getpid()].status = ZOMBIE;
            //block on private mailbox
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): terminating process's parent hasn't waited! Zombie time!\n");
            int message [] = {getpid(), termCode};
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): Receiving from proc table mutex\n");
            MboxReceive(7, NULL, 0);
            MboxSend(procTable[getpid()].privateMbox, message, sizeof(message));
        }
    }
    else{
        if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): Receiving from proc table mutex\n");
        MboxReceive(7, NULL, 0);

        if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): terminating process has children. Slay them.\n");

        if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): Sending to proc table mutex\n");
        MboxSend(7, NULL, 0);

        procPtr cur = procTable[getpid()%MAXPROC].nextChild;

        if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): Receiving from proc table mutex\n");
        MboxReceive(7, NULL, 0);

        procPtr next = NULL;
        //walk down all silblings
        while (cur != NULL){
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): Sending to proc table mutex\n");
            MboxSend(7, NULL, 0);
            //next is the handle to the next one to grab
            if (cur->nextSib == NULL)
                next = NULL;
            else
                next = cur->nextSib;

            if (cur->status == ZOMBIE){
                int result [] = {-1, -1};
                if (DEBUG3 && debugflag3)
                    USLOSS_Console("terminate(): Waking up zombie\n");
                if (DEBUG3 && debugflag3)
                    USLOSS_Console("terminate(): Receiving from proc table mutex\n");
                MboxReceive(7, NULL, 0);

                MboxReceive(cur->privateMbox, result, sizeof(int[2]));
            }
            else{
                if (DEBUG3 && debugflag3)
                    USLOSS_Console("terminate(): zapping a running child\n");
                procTable[getpid()].status = ZAP_BLOCKED;
                if (DEBUG3 && debugflag3)
                    USLOSS_Console("terminate(): Receiving from proc table mutex\n");
                MboxReceive(7, NULL, 0);
                zap(cur->pid);
                procTable[getpid()].status = READY;
            }
            cur = next;
        }
        //if the parent is wait blocked, wake it up
        if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): Sending to proc table mutex\n");
        MboxSend(7, NULL, 0);

        if (procTable[getpid()].pid == 3) {
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): Receiving from proc table mutex\n");
            MboxReceive(7, NULL, 0);
            quit(termCode);
        }

        else if (procTable[getpid()].parent->status == WAIT_BLOCKED){
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): terminating process's parent is wait blocked!\n");

            int message [] = {getpid(), termCode}; //build message
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): Receiving from proc table mutex\n");
            MboxReceive(7, NULL, 0);
            MboxSend( procTable[procTable[getpid()].parent->pid].privateMbox, message, sizeof(message));
        }
        //If the parent hasn't called wait, block as a zombie before quitting
        else if(procTable[getpid()].parent->status == READY){
            //set status to zombie
            procTable[getpid()].status = ZOMBIE;
            //block on private mailbox
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): terminating process's parent hasn't waited! Zombie time!\n");
            int message [] = {getpid(), termCode};
            if (DEBUG3 && debugflag3)
                USLOSS_Console("terminate(): Receiving from proc table mutex\n");
            MboxReceive(7, NULL, 0);
            MboxSend(procTable[getpid()].privateMbox, message, sizeof(message));
        }
        if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): CondReceiving from proc table mutex, in case none of the above cases worked\n");
        MboxCondReceive(7, NULL, 0);
    }

    if (DEBUG3 && debugflag3)
        USLOSS_Console("terminate(): Sending to proc table mutex\n");
    MboxSend(7, NULL, 0);

    if (DEBUG3 && debugflag3)
            USLOSS_Console("terminate(): %s calling quit after cleaning the proc table\n", procTable[getpid()].name);
    if ( procTable[getpid()].nextSib == NULL )
        procTable[getpid()].parent->nextChild = NULL;
    else
        procTable[getpid()].parent->nextChild = procTable[getpid()].nextSib;
    if (DEBUG3 && debugflag3){
            USLOSS_Console("terminate(): at the end for %d\n", procTable[getpid()].pid);
    }
    cleanProcSlot(getpid());
    if (DEBUG3 && debugflag3)
        USLOSS_Console("terminate(): Receiving from proc table mutex\n");
    MboxReceive(7, NULL, 0);
    
    quit(termCode);
}

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
    USLOSS_Console("\n   NAME   |   PID   |   PRIORITY   |  STATUS   |   PPID   |     ARG    |\n");
    USLOSS_Console("-----------------------------------------------------------------------------------\n");
    int i;
    for(i = 0; i < MAXPROC; i++){
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
        USLOSS_Console("| %-9d| %-12s|\n", procTable[i].parentPid, procTable[i].arg);
        USLOSS_Console("-----------------------------------------------------------------------------------\n");
    }
    
    USLOSS_Console("\n");
}

void getTimeOfDay1(systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("getTimeOfDay1(): at beginning\n");
    args->arg1 = (void *) USLOSS_Clock();
    setToUserMode();
}

void semCreate(systemArgs *arg)
{
    int handle = arg->arg1;

    //check to see if handle is valid
    if (handle < 0){
        USLOSS_Console("semCreate(): invalid handle!");
        arg->arg4 = -1;
    }

    int sem = semCreateReal(handle);
    arg->arg1 = (void *) sem; 
    if (sem == -1)
        arg->arg4 = (void *) -1;
    else
        arg->arg4 = (void *) 0;
    setToUserMode();
    
}

int semCreateReal(int initial_value)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semCreateReal(): at beginning\n");
    int i;
    //find the next free semaphore
    int newSemID = -1;
    for(i = 0; i < MAXSEMS; i++){
        //grab the id of the first open slot
        if (semTable[i].semID == -1){
            newSemID = i;
            break;
        }
    }

    //check to see if there were any free slots
    if (newSemID == -1){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semCreateReal(): No more semaphores\n");
        return newSemID;
    }
    //set initital value and return
    MboxSend(semTable_mutex, NULL, 0);
    semTable[newSemID].value = initial_value;
    semTable[newSemID].semID = newSemID;
    semTable[newSemID].mboxID = MboxCreate(1,0);
    MboxReceive(semTable_mutex, NULL, 0);
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semCreateReal(): returning sem with ID %d\n", newSemID);
    return newSemID;

}

void semP(systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semP(): at beginning\n");
    int sem = args->arg1;
    //check for valid handle
    if (semTable[sem].semID != sem){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semP(): invalid handle!\n");
        args->arg4 = (void *) -1;
        return;
    }
    //can only call this if the mutex is checked out!
    //MboxSend()
    args->arg4 = (void *) semPReal(sem);
    setToUserMode();
}

int  semPReal(int semID)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semPReal(): at beginning\n");
    MboxSend(semTable_mutex, NULL, 0);
    //if value is positive
    if (semTable[semID].value > 0){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semPReal(): value positive, decrementing\n");
        semTable[semID].value--;
        MboxReceive(semTable_mutex, NULL, 0);
        return 0;
    }
    //value is negative, block
    else{
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semPReal(): value negative, blocking\n");
        if (semTable[semID].nextBlockedProc != NULL){
            //there are other procs in the list, add to end
            procPtr cur =  semTable[semID].nextBlockedProc;
            while (cur->nextProc != NULL){
                cur = cur->nextProc;
            }
            //cur now points to last sib in the list
            cur->nextProc = &procTable[getpid()];
            MboxReceive(semTable_mutex, NULL, 0);
            if (DEBUG3 && debugflag3)
                USLOSS_Console("semPReal(): added to end of blocked list %s\n", procTable[getpid()].arg);
            int result [] = {-2, -2};
            MboxReceive(procTable[getpid()].privateMbox, result, sizeof(int[2]));
            if (DEBUG3 && debugflag3)
                USLOSS_Console("semPReal(): awoken %s\n", procTable[getpid()].arg);
            if (result[1] == -1){
                if (DEBUG3 && debugflag3)
                USLOSS_Console("semPReal(): sem was freed while blocked, terminating\n");
                setToUserMode();
                Terminate(1);
            }


        }else{
            //this is the semaphores first blocked process
            semTable[semID].nextBlockedProc = &procTable[getpid()];
            MboxReceive(semTable_mutex, NULL, 0);
            if (DEBUG3 && debugflag3)
                USLOSS_Console("semPReal(): added to front of blocked list\n");
            int result [] = {-2, -2};
            MboxReceive(procTable[getpid()].privateMbox, result, sizeof(int[2]));
            if (DEBUG3 && debugflag3)
                USLOSS_Console("semPReal(): awoken %s\n", procTable[getpid()].arg);
            if (result[1] == -1){
                if (DEBUG3 && debugflag3)
                USLOSS_Console("semPReal(): sem was freed while blocked, terminating\n");
                setToUserMode();
                Terminate(1);
            }
        }
    }
    return 0;
}

void semV(systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semV(): at beginning\n");
    int sem = args->arg1;
    //check for valid handle
    if (semTable[sem].semID != sem){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semV(): invalid handle!\n");
        args->arg4 = (void *) -1;
        return;
    }
    args->arg4 = (void *) semVReal(sem);
    setToUserMode();
}

int  semVReal(int semID)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semVReal(): at beginning\n");

    //check for blocked procs that could be woken up
    if (semTable[semID].nextBlockedProc != NULL){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semVReal(): waking up blocked proc %s\n", semTable[semID].nextBlockedProc->name);
        //adjust blocked proc list

        int mboxIDtoSend = semTable[semID].nextBlockedProc->privateMbox;
        if (semTable[semID].nextBlockedProc->nextProc == NULL){
            semTable[semID].nextBlockedProc = NULL;
        }
        else{
            semTable[semID].nextBlockedProc = semTable[semID].nextBlockedProc->nextProc;
        }
        int message = 1;
        MboxSend(mboxIDtoSend, &message, sizeof(int));
        return 0;
    }

    MboxSend(semTable_mutex, NULL, 0);
    semTable[semID].value++;
    MboxReceive(semTable_mutex, NULL, 0);
    return 0;
}

void semFree(systemArgs *args)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semFree(): at beginning\n");

    int semID = args->arg1;
    //check to make sure semID is valid
    if (semTable[semID].semID != semID){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semV(): invalid handle!\n");
        args->arg4 = (void *) -1;
        return;
    }
    args->arg4 = (void *) semFreeReal(semID);
    setToUserMode();

}

int semFreeReal(int semID)
{
    if (DEBUG3 && debugflag3)
            USLOSS_Console("semFreeReal(): at beginning\n");
    //if there are no blocked procs
    if (semTable[semID].nextBlockedProc == NULL){
        if (DEBUG3 && debugflag3)
            USLOSS_Console("semFreeReal(): no blocked procs! freeing sem\n");
        semTable[semID].value = -1;
        semTable[semID].semID = -1;
        return 0;
    }
    else{
        procPtr cur = semTable[semID].nextBlockedProc;
        procPtr next;
        while (cur != NULL){
            if (cur->nextProc == NULL){
                next = NULL;
            }
            else{
                next = cur->nextProc;
            }
            int message [] = {-1, -1};
            if (DEBUG3 && debugflag3)
                USLOSS_Console("semFreeReal(): about to wake up sem\n");
            MboxSend(cur->privateMbox, message, sizeof(int[2]));
            cur = next;
        }
        return 1;
    }
}

void getPID(systemArgs *args){
    args->arg1 = getpid();
    setToUserMode();

}

void cpuTime(systemArgs *args){
    args->arg1 = readtime();
}


















