///NRUUU
#include "request.h"
#include "server_thread.h"
#include "common.h"

#define LOCK(a) pthread_mutex_lock(a)
#define UNLOCK(a) pthread_mutex_unlock(a)


typedef struct HashNode {
    struct HashNode *HMRU;
    struct HashNode *HLRU;
    char *hashKey;
    int presVal;
    struct file_data *HCashData;
    struct HashNode *nextNode;
} StHashNode;

typedef struct {
    long HashSize;
    StHashNode **hashTable;
    // int testval

} StHashTable;

/// function dec
static void file_data_free(struct file_data *data);
int clearCash(struct server *sv, int clear);
int HashFunc(char *data, long HashSize);
StHashNode *hashSearch(struct server *sv, StHashTable *ht, char *str, int ipoint);
StHashNode *entryCash(struct server *sv, struct file_data *fd, StHashTable *ht);
struct server {
    int nr_threads;
    int max_requests;
    int max_cache_size;
    int exiting;
    /* add any other parameters you need */
    int *conn_buf;
    pthread_t *threads;
    int request_head;
    int request_tail;
    pthread_mutex_t mutex;
    pthread_cond_t prod_cond;
    pthread_cond_t cons_cond;
    StHashTable *hashCacheTable;
    StHashNode *nodeLRU;
    StHashNode *nodeMRU;
    int SrvCacheLeft;

    pthread_mutex_t *SrvCacheLock;
};

StHashTable *HashInit(int hashsize) {
    StHashTable *ht;
    ht = (StHashTable *) malloc(sizeof (StHashTable));

    ht->hashTable = (StHashNode **) malloc(hashsize * sizeof (StHashNode *));

    ht->HashSize = hashsize;
    return ht;
}



// Hashfunction for clearing cahs algo - Same used in lab1 tweaked

int HashFunc(char *data, long HashSize) {
    int tmp = 0;
    int hashipoint = 6381;
    while ((tmp = *data) != 0) {
        int a = hashipoint << 5;
        hashipoint = (a + hashipoint) + tmp;
        data++;
    }

    if (hashipoint < 0)
        hashipoint = hashipoint*-1;

    return hashipoint % HashSize;
}

StHashNode *hashSearch(struct server *sv, StHashTable *ht, char *str, int ipoint) {
    if (!ht->hashTable[ipoint]) {
        return NULL;
    }

    StHashNode *curipoint = ht->hashTable[ipoint];
    do {
        if (0 != strcmp(str, curipoint->HCashData->file_name)) {
            curipoint = curipoint -> nextNode;
        } else {
            if (sv->nodeMRU == curipoint) {
                UNLOCK(sv->SrvCacheLock);
                return curipoint;
            } else {
                curipoint->HMRU->HLRU = curipoint->HLRU;
                StHashNode *tmp = curipoint->HMRU;
                curipoint->HMRU = NULL;

                if (sv->nodeLRU == curipoint) {
                    sv->nodeLRU = tmp;
                } else {
                    curipoint->HLRU->HMRU = tmp;
                }

                sv->nodeMRU->HMRU = curipoint;
                curipoint->HLRU = sv->nodeMRU;
                sv->nodeMRU = curipoint;
                UNLOCK(sv->SrvCacheLock);

                return curipoint;
            }
        }
    }while (NULL != curipoint);

    return NULL;
}

StHashNode *entryCash(struct server *sv, struct file_data *fd, StHashTable *ht) {

    if (fd->file_size > sv->max_cache_size) {
        return NULL;
    }
    int retVall = HashFunc(fd->file_name, sv->max_cache_size);
    StHashNode *res = hashSearch(sv, sv->hashCacheTable, fd->file_name, retVall);
    if (res) {
        return res;
    }

    if (fd->file_size > sv->SrvCacheLeft) {
        if (clearCash(sv, fd->file_size - sv->SrvCacheLeft)) {
            return NULL;
        }
    }

    int ipoint = HashFunc(fd->file_name, ht->HashSize);
    if (ht->hashTable[ipoint] != NULL) {
        StHashNode *tmplist = ht->hashTable[ipoint];
        while (tmplist != NULL) {
            if (0 == strcmp(tmplist->HCashData->file_name, fd->file_name)) {
                return tmplist;
            }

            tmplist = tmplist->nextNode;
        }

        StHashNode *node = (StHashNode *) malloc(sizeof (StHashNode));
        node->HCashData = fd;
        node->nextNode = NULL;

        ht->hashTable[ipoint]->HMRU = NULL;
        ht->hashTable[ipoint]->HLRU = sv->nodeMRU;
        if (sv->nodeMRU == NULL) {
            sv->nodeLRU = ht->hashTable[ipoint];

        }
        else
            sv->nodeMRU->HMRU = ht->hashTable[ipoint];
        sv->nodeMRU = ht->hashTable[ipoint];
        tmplist->nextNode = node;
    } else {
        ht->hashTable[ipoint] = (StHashNode *) malloc(sizeof (StHashNode));
        ht->hashTable[ipoint]->nextNode = NULL;
        ht->hashTable[ipoint]->presVal = 0;

        ht->hashTable[ipoint]->HCashData = fd;


        ht->hashTable[ipoint]->HMRU = NULL;


        ht->hashTable[ipoint]->HLRU = sv->nodeMRU;


        if (sv->nodeMRU == NULL) {
            sv->nodeLRU = ht->hashTable[ipoint];
        }
        else
            sv->nodeMRU->HMRU = ht->hashTable[ipoint];


        sv->nodeMRU = ht->hashTable[ipoint];
    }

    sv->SrvCacheLeft -= fd->file_size;
    return ht->hashTable[ipoint];
}

int clearCash(struct server *sv, int clearBytes) {
    StHashNode *tempUsed = sv->nodeLRU;
    int bVal = 0;
    do {
        if (tempUsed->presVal) {

            bVal = bVal + tempUsed->HCashData->file_size;
        }

        tempUsed = tempUsed->HMRU;
    } while (tempUsed != NULL);

    if (clearBytes > sv->max_cache_size - bVal) {

        return 1;
    }



    StHashNode *ipoint = sv->hashCacheTable->hashTable[HashFunc(sv->nodeLRU->HCashData->file_name, sv->max_cache_size)];
    StHashNode *ppoint = NULL;


    StHashNode *pushI = sv->nodeLRU;
    int clearB = 0;
    StHashNode *tempoN;

    do {

        if (pushI->presVal != 0) {
            pushI = pushI->HMRU;
        } else {
            tempoN = pushI;
            pushI = pushI->HMRU;

            if (sv->hashCacheTable->hashTable[HashFunc(tempoN->HCashData->file_name, sv->max_cache_size)]->nextNode != NULL) {
                do {
                    ppoint = ipoint;
                    ipoint = ipoint->nextNode;
                } while (ipoint != NULL && strcmp(ipoint->HCashData->file_name, tempoN->HCashData->file_name) != 0);

                if (ppoint != NULL)
                    ppoint->nextNode = ipoint->nextNode; //maintain ordering within HashFunc table
                else
                    sv->hashCacheTable->hashTable[HashFunc(tempoN->HCashData->file_name, sv->max_cache_size)] = ipoint->nextNode;

                if (tempoN != sv->nodeLRU) {
                    tempoN->HLRU->HMRU = tempoN->HMRU;
                    if (tempoN == sv->nodeMRU) {
                        sv->nodeMRU = tempoN->HLRU;
                    }
                    else {
                        tempoN->HMRU->HLRU = tempoN->HLRU;
                    }


                } else {
                    sv->nodeLRU = sv->nodeLRU->HMRU;
                    if (sv->nodeLRU == NULL) {
                        sv->nodeMRU = NULL;
                    }

                }

                sv->SrvCacheLeft += tempoN->HCashData->file_size;
                file_data_free(tempoN->HCashData);
                free(tempoN);
            }
            else {
                if (tempoN != sv->nodeLRU) {
                    tempoN->HLRU->HMRU = tempoN->HMRU;
                    if (tempoN != sv->nodeMRU) {
                        tempoN->HMRU->HLRU = tempoN->HLRU;
                    }
                    else {
                        sv->nodeMRU = tempoN->HLRU;
                    }

                } else {
                    sv->nodeLRU = sv->nodeLRU->HMRU;
                    if (sv->nodeLRU == NULL) {
                        sv->nodeMRU = NULL;
                    }


                }

                sv->SrvCacheLeft += tempoN->HCashData->file_size;
                sv->hashCacheTable->hashTable[HashFunc(tempoN->HCashData->file_name, sv->max_cache_size)] = NULL;
                file_data_free(tempoN->HCashData);
                free(tempoN);
            }
        }

    } while (clearB < clearBytes && pushI != NULL);

    return 0;
}

static struct file_data *
file_data_init(void) {
    struct file_data *data;

    data = Malloc(sizeof (struct file_data));
    data->file_name = NULL;
    data->file_buf = NULL;
    data->file_size = 0;
    return data;
}

static void
file_data_free(struct file_data *data) {
    free(data->file_name);
    free(data->file_buf);
    free(data);
}

static void
do_server_request(struct server *sv, int connfd) {
    int ret;
    struct request *rq;
    struct file_data *data;
    StHashNode *cacheinfo;
    data = file_data_init();


    rq = request_init(connfd, data);
    if (!rq) {
        file_data_free(data);
        return;
    }

    if (sv->max_cache_size <= 0) {
        ret = request_readfile(rq);
        if (!ret)
            goto out;

        request_sendfile(rq);
    } else {
        LOCK(sv->SrvCacheLock);
        cacheinfo = hashSearch(sv, sv->hashCacheTable, data->file_name, HashFunc(data->file_name, sv->max_cache_size));
        if (cacheinfo != NULL) //cache miss
        {

            data->file_buf = cacheinfo->HCashData->file_buf;
            data->file_size = cacheinfo->HCashData->file_size;
            cacheinfo->presVal++;
            UNLOCK(sv->SrvCacheLock);

            request_sendfile(rq);

            LOCK(sv->SrvCacheLock);
            cacheinfo->presVal--;

            UNLOCK(sv->SrvCacheLock);
            goto out;
        } else {

            UNLOCK(sv->SrvCacheLock);

            ret = request_readfile(rq);
            LOCK(sv->SrvCacheLock);
            cacheinfo = entryCash(sv, data, sv->hashCacheTable);
            if (cacheinfo) {
                cacheinfo->presVal++;
            }
            UNLOCK(sv->SrvCacheLock);
        }

        if (!ret)
            goto out;

        request_sendfile(rq);
        if (cacheinfo != NULL) {
            LOCK(sv->SrvCacheLock);
            cacheinfo->presVal--;

            UNLOCK(sv->SrvCacheLock);
        }
    }
out:
    request_destroy(rq);

}
/// test func

static void *
do_server_thread(void *arg) {
    struct server *sv = (struct server *) arg;
    int connfd;

    while (1) {
        pthread_mutex_lock(&sv->mutex);
        while (sv->request_head == sv->request_tail) {
            /* buffer is empty */
            if (sv->exiting) {
                pthread_mutex_unlock(&sv->mutex);
                goto out;
            }
            pthread_cond_wait(&sv->cons_cond, &sv->mutex);
        }
        /* get request from tail */
        connfd = sv->conn_buf[sv->request_tail];
        /* consume request */
        sv->conn_buf[sv->request_tail] = -1;
        sv->request_tail = (sv->request_tail + 1) % sv->max_requests;

        pthread_cond_signal(&sv->prod_cond);
        pthread_mutex_unlock(&sv->mutex);
        /* now serve request */
        do_server_request(sv, connfd);
    }
out:
    return NULL;
}

/* entry point functions */
/// test func

struct server *
server_init(int nr_threads, int max_requests, int max_cache_size) {
    struct server *sv;
    int i;

    sv = Malloc(sizeof (struct server));
    sv->nr_threads = nr_threads;
    /* we add 1 because we queue at most max_request - 1 requests */
    sv->max_requests = max_requests + 1;
    sv->max_cache_size = max_cache_size;
    sv->exiting = 0;
    // cleared labcode
    sv->SrvCacheLock = (pthread_mutex_t *) malloc(sizeof (pthread_mutex_t));
    pthread_mutex_init(sv->SrvCacheLock, NULL);
    sv->nodeMRU = NULL;
    sv->nodeLRU = NULL;

    if (nr_threads > 0 || max_requests > 0 || max_cache_size > 0) {

        sv->conn_buf = Malloc(sizeof (*sv->conn_buf) * sv->max_requests);
        for (i = 0; i < sv->max_requests; i++) {
            sv->conn_buf[i] = -1;
        }
        sv->request_head = 0;
        sv->request_tail = 0;


        pthread_mutex_init(&sv->mutex, NULL);
        pthread_cond_init(&sv->prod_cond, NULL);
        pthread_cond_init(&sv->cons_cond, NULL);



        if (nr_threads > 0) {
            sv->threads = Malloc(sizeof (pthread_t) * nr_threads);
            for (i = 0; i < nr_threads; i++) {
                SYS(pthread_create(&(sv->threads[i]), NULL, do_server_thread,
                        (void *) sv));
            }
        }

        if (max_cache_size > 0) {
            sv->hashCacheTable = HashInit(max_cache_size);
            sv->SrvCacheLeft = max_cache_size;
        }
    }

    return sv;
}
/// test func

void
server_request(struct server *sv, int connfd) {
    if (sv->nr_threads == 0) { /* no worker threads */
        do_server_request(sv, connfd);
    } else {
        /*  Save the relevant info in a buffer and have one of the
         *  worker threads do the work. */

        pthread_mutex_lock(&sv->mutex);
        while (((sv->request_head - sv->request_tail + sv->max_requests)
                % sv->max_requests) == (sv->max_requests - 1)) {
            /* buffer is full */
            pthread_cond_wait(&sv->prod_cond, &sv->mutex);
        }
        /* fill conn_buf with this request */
        assert(sv->conn_buf[sv->request_head] == -1);
        sv->conn_buf[sv->request_head] = connfd;
        sv->request_head = (sv->request_head + 1) % sv->max_requests;
        pthread_cond_signal(&sv->cons_cond);
        pthread_mutex_unlock(&sv->mutex);
    }
}

void
server_exit(struct server *sv) {
    int i;
    /* when using one or more worker threads, use sv->exiting to indicate to
     * these threads that the server is exiting. make sure to call
     * pthread_join in this function so that the main server thread waits
     * for all the worker threads to exit before exiting. */
    pthread_mutex_lock(&sv->mutex);
    sv->exiting = 1;
    pthread_cond_broadcast(&sv->cons_cond);
    pthread_mutex_unlock(&sv->mutex);
    for (i = 0; i < sv->nr_threads; i++) {
        pthread_join(sv->threads[i], NULL);
    }

    /* make sure to free any allocamaketed resources */
    free(sv->conn_buf);
    free(sv->threads);
    free(sv);
}
