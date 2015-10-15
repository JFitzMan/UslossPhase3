/*
 * These are the definitions for phase 3 of the project
 */

#ifndef _PHASE3_H
#define _PHASE3_H

#define DEBUG3 0

#define MAXSEMS         200

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

