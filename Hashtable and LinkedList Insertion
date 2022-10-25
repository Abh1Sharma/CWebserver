#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "wc.h"
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>

//long valSize = size;
//wc * hash_table[valSize];
//wc * hash_table[];
//struct wc * hash_table[400000000];



struct wc {
	/* you can define this struct to have whatever fields you want. */
   int numItemsInWC;
   int sizeOfWC;
   struct llItem ** hashTablellPTR;  // WC IS OUR HASHTABLE WHICH HAS AN ARRAY OF POINTERS TO our Linked List Items, 
                                   // these
};
struct llItem{ 
   char* name;   /// the word in
   int freq;
   int flag;
   struct llItem * next;
//    struct llItem * next;
};

struct llItem* llItemCreate(char* word,struct wc* wc);
int hashValueCalc(char* word, struct wc *wc);
/* Initialize wc data structure, returning pointer to it. The input to this
 * function is an array of characters. The length of this array is size.  The
 * array contains a sequence of words, separated by spaces. You need to parse
 * this array for words, and initialize your data structure with the words in
 * the array. You can use the isspace() function to look for spaces between
 * words. You can use strcmp() to compare for equality of two words. Note that
 * the array is read only and cannot be modified. */
struct wc* wc_init(char *word_array, long size)
{
    
    struct wc *wc;
    wc = (struct wc*) malloc(sizeof(struct wc));
    assert(wc);
    wc->sizeOfWC = size;
    wc->hashTablellPTR = calloc((sizeof(struct llItem**)),size );

//    char * charArr;
//    charArr = (char *)malloc(sizeof(charArr)*10);
//    free(charArr);
    char word[70];
    word[70] = '\0'; // null term precaution edge case, resize if need
    int nBits = 0;
    for (int i = 0; i < size; i++){
        int strSize = 0;
        for(int nSpot = i; nSpot < size; i++){ // have a placeholder for the index where i was last not empty
            if( isspace(word_array[nSpot]) == 0){
                nSpot = nSpot + 1;
		strSize = strSize+1;
            } else{
                i = nSpot;
                break;
            }
             
        }
//        printf("__%c__",word_array[i]);
        nBits = i-strSize;
        
	if (strSize != 0){ //
            memset(word,'\0',strlen(word)+1);
            
//              printf("__%c__",word_array[i]);
//            printf("__%d__",nBits);

//            word = strdup(&word);
//            word[ sizeof(word) + 1] = '\0';
            strncpy(word,word_array+nBits,strSize);
//            printf("word: _%s_\n", word);
//            printf("word: _%s_%ls\n", word,size);
            
            int hashVal = hashValueCalc(word,wc);
            struct llItem *llItemPtr = wc->hashTablellPTR[hashVal];
//            printf("str:_%s_ | HV: _%d_ \n", word, hashVal);
//        5 steps:
//        1. if empty, insert. 
//        2. else if hashval corresponds to not empty:
//        3. Search for the name,
 //       4.if its found, increment freq, 
//        5. if its not found, create word. 
   
            if( (llItemPtr == NULL)  ){  /// STEP 1.
                struct llItem *nPtr = (struct llItem *)malloc(sizeof(struct llItem*));
                nPtr = llItemCreate(word,wc); 
//              printf("inserted");
                wc->hashTablellPTR[hashVal] = nPtr; 
                
            }
            else if(llItemPtr != NULL){
                struct llItem *pPtr = (struct llItem *)malloc(sizeof(struct llItem*));
                pPtr = NULL;
        //        assert(pPtr);
                while ( (llItemPtr != NULL) && (strcmp(word,llItemPtr->name) != 0 ) ){ // STEP 2.3 searching till true
                    pPtr = llItemPtr;
                    llItemPtr = llItemPtr ->next;
//                    if(llItemPtr == NULL){
//                        printf("found null");
//                        break;
//                    }
                    //printf("entered list checking");
                }
                if( llItemPtr != NULL && (strcmp(word,llItemPtr->name) == 0) ){ // Step 4 
                    if(llItemPtr->freq == 0){
                        llItemPtr->freq = 1;
                    }else{
                    llItemPtr->freq = llItemPtr->freq + 1;
//                    printf("name:%s | Increment freq: %d", llItemPtr->name,llItem->freq);
                    }
                    
                }
        
                else if( (llItemPtr == NULL)  )  { // Step 5
                    struct llItem *nPtr = (struct llItem *)malloc(sizeof(struct llItem*));
                    nPtr = llItemCreate(word,wc); 
            
                    if(pPtr != NULL){ 
                        pPtr->next = nPtr;
                        
                    }
                    else{
                        wc->hashTablellPTR[hashVal] = nPtr;
                        free(nPtr);
                    }
                    
                    
                    //free(pPtr);
                }
                
        
                
                
        
//        if( strcmp(word,pPtr->name) != 0){printf("wokau"); // STEP 4 value found
//            pPtr->freq = pPtr->freq + 1;
//        }       
//        struct llItem *newPtr = llItemCreate(word);
      
        // issue we are now facing is that we do not have the        
//        printf("okay");
//        if( strcmp(word,pPtr->name) != 0){printf("hi"); // STEP 4 value found
//            llItemPtr->freq = llItemPtr->freq + 1;
//     
//        }
        
    
            }   
   
	}//
    }   
    return wc;
    
}

int hashValueCalc(char* word, struct wc *wc){ /// djb2 hashfunction from online
   int hash = 5381;
   int c;

   while ((c = *word++)){
       hash = ((hash << 5) + hash) + c; 
   }
   if(hash < 0){
       hash = hash*-1;
   }
   return hash%(wc->sizeOfWC);
}


struct llItem* llItemCreate(char* word,struct wc*wc){
    
//    struct llItem* itemPtr = NULL;
    struct llItem* itemPtr = (struct llItem*)malloc(sizeof(struct llItem));

    itemPtr->freq = 1;
//    itemPtr->freq = 0;
    itemPtr -> name = strdup(word);
    itemPtr-> next = NULL;
    itemPtr-> flag = 0; //LP test
    
//    strcpy(itemPtr -> name,word);
//    itemPtr->name[sizeof(itemPtr->name)] = '\0';
    return itemPtr;
}
/* wc_output produces output, consisting of unique words that have been inserted
 * in wc (in wc_init), and a count of the number of times each word has been
 * seen.
 *
 * The output should be sent to standard output, i.e., using the standard printf
 * function.
 *
 * The output should be in the format shown below. The words do not have to be
  * sorted in any order. Do not add any extra whitespace.
word1:5
word2:10
word3:30
word4:1
 */
void wc_output(struct wc *wc){   
    for( int i = 0; i < wc->sizeOfWC; i++){ // go through ht, at each non empty spot, check all its items and show vals
        while(wc->hashTablellPTR[i] != NULL){
            printf("%s:%d\n",wc->hashTablellPTR[i]->name ,wc->hashTablellPTR[i]->freq);
//          printf("test"); 
            wc->hashTablellPTR[i] = wc->hashTablellPTR[i]->next;
        }
    }

}
// ./test_wc /cad2/ece344f/src/wc-big.txt > wc-big.out
// /cad2/ece344f/src/wc-big.res

void wc_destroy(struct wc *wc)
{   
//    free(wc->numItemsInWC);
    free(wc);
}






























