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
extern int 	start2(char *arg);
extern void spawn(systemArgs *args);
extern int 	spawnReal(char *name, int (*func)(char *), char *arg, 
	int stack_size, int priority);
extern int spawnLaunch();
extern void wait1(systemArgs *args);
extern int 	wait1Real(int * status);


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
	int			privateMbox;
	int			termCode;

};

struct semaphore {
	int 		value;
	procPtr		nextBlockedProc;
};

#define READY 	0

#endif /* _PHASE3_H */

