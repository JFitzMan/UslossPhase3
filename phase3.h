/*
 * These are the definitions for phase 3 of the project
 */

#ifndef _PHASE3_H
#define _PHASE3_H

#define DEBUG3 			1
#define MAXSEMS         200

extern int  start2 (char *);
extern int 	start3 (char *);
extern int 	inKernelMode(char *procName);
extern void	setToUserMode();
extern void cleanProcSlot(int pid);
extern void dumpProc();
extern int 	start2(char *arg);
extern void spawn(systemArgs *args);
extern int 	spawnReal(char *name, int (*func)(char *), char *arg, 
	int stack_size, int priority);
extern int 	spawnLaunch();
extern void wait1(systemArgs *args);
extern int 	wait1Real(int * status);
extern void terminate(systemArgs *args);
extern void getTimeOfDay1(systemArgs *args);
extern void semCreate(systemArgs *args);
extern int  semCreateReal(int initial_value);
extern void semP(systemArgs *args);
extern int  semPReal(int semID);
extern void semV(systemArgs *args);
extern int  semVReal(int semID);
extern void semFree(systemArgs *args);
extern int 	semFreeReal (int semID);
extern void getPID(systemArgs *args);
extern void cpuTime(systemArgs *args);


typedef struct procSlot *procPtr;
typedef struct semaphore *semaphore;

struct procSlot {
	int			pid;
	int			parentPid;
	int 		(* start_func) (char *);
	char*		name;
	int			status;
	char*		arg;
	int			stack_size;
	int			priority;
	procPtr		nextChild;
	procPtr		nextSib;
	procPtr		parent;
	procPtr		nextProc;
	int			privateMbox;
	int			termCode;

};

struct sem {
	int		value;
}; 

struct semaphore {
	int 		value;
	int 		semID;
	int 		mboxID;
	procPtr		nextBlockedProc;
};

#define READY 	0
#define JOIN_BLOCKED 1
#define ZOMBIE		 2
#define WAIT_BLOCKED 11
#define ZAP_BLOCKED 12

#endif /* _PHASE3_H */

