/*
 * These are the definitions for phase 3 of the project
 */

#ifndef _PHASE3_H
#define _PHASE3_H

#define DEBUG3 			1

#define MAXSEMS         200

extern int inKernelMode(char *procName);
extern int start2(char *arg);
extern void spawn(systemArgs *args);

typedef struct procSlot *procPtr;
typedef struct semaphore *semaphore;

struct procSlot {
	int			pid;
	procPtr		nextProc;

};

struct semaphore {
	int 		value;
	procPtr		nextBlockedProc;
};

#endif /* _PHASE3_H */

