#ifndef _GLOBAL_H
#define _GLOBAL_H
/*--------------------------------------------------------------------------------
										Libraries
--------------------------------------------------------------------------------*/
// Data Structures: 
#include <vector>
#include <string>
#include <queue>
#include <list>
#include <iterator>

// Streams  & Filesystem:
#include <fstream>
#include <iostream>
#include <sstream>

// Utility:
#include <cmath>
#include <cassert>
#include <chrono>
#include <algorithm>
#include <numeric>  
#include <unistd.h>

// Threads & Synchronization:
#include <pthread.h>




/*--------------------------------------------------------------------------------
									   Typedefs
--------------------------------------------------------------------------------*/
using std::string;
using std::vector;
using std::queue;

using std::ostream;
using std::ifstream;
using std::fstream;
using std::istringstream;
using std::chrono::time_point;
using std::cout;
using std::cerr;
using std::endl;


typedef unsigned int uint;

typedef vector<vector<uint>> vvi;
typedef vector<vector<bool>> bool_mat; // Use this as your Game Field

struct tile_record {
    double tile_compute_time; // Compute time for the tile
    uint thread_id; // The thread responsible for the compute
};

/*--------------------------------------------------------------------------------
								  Defines & Macros
--------------------------------------------------------------------------------*/
#define PRINT_BOARD true // Boolean flag - Responsible for controling whether the board is printed or not
#define GEN_SLEEP_USEC 300000 // Default : 300000. The approximate time the board is displayed each generation in micro-seconds
#define DEF_MAT_DELIMITER ' ' // The seperator betweens 0s and 1s in your matrix input file 
#define DEF_RESULTS_FILE_NAME "results.csv" // The filename of the results
#define DEF_TILE_RESULTS_FILE_NAME "results_tile.csv" // The filename of the results

// Macros - For your comfort
#define DEBUG 0
#define DEBUG_MES(mes) if(DEBUG) cout << mes << endl;
#define user_error(mes,exp) if(!exp){cerr << "Fatal: " <<  mes << endl; exit(1);}

#define BIRTH 3
#define SURVIVE_1 2
#define SURVIVE_2 3

#endif

