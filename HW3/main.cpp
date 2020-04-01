#include "Game.hpp"

static inline game_params parse_input_args(int argc, char **argv);
static inline void usage(const char* mes);
static void calc_and_append_statistics(uint n_threads, const vector<double>& gen_hist, const vector<tile_record>& tile_hist);
static void calc_and_append_tile_statistics(const vector<tile_record>& tile_hist);

/*--------------------------------------------------------------------------------
										Main
--------------------------------------------------------------------------------*/
int main(int argc, char **argv) {

	game_params params = parse_input_args(argc, argv);
	Game g(params);
	g.run();
    calc_and_append_statistics(g.thread_num(), g.gen_hist(), g.tile_hist());
    calc_and_append_tile_statistics(g.tile_hist());
	return 0;
}
/*--------------------------------------------------------------------------------
							 Auxiliary Implementation
--------------------------------------------------------------------------------*/
static inline game_params parse_input_args(int argc, char **argv) {

	if (argc != 6) // ./gameoflife filename.txt 100 20 Y Y 
		usage("Wrong number of arguments - expected 5");

	game_params g;
	g.filename = argv[1];
	g.n_gen = strtoul(argv[2], NULL, 10);
	g.n_thread = strtoul(argv[3], NULL, 10);

	string inter = string(argv[4]); 
	string print = string(argv[5]); 
	g.interactive_on = (inter == "y" || inter == "Y") ? true : false; 
	g.print_on = (print == "y" || print == "Y") ? true : false; 

	if (g.n_gen <= 0 || g.n_thread <= 0)
		usage("Invalid number of generations/number of threads (Required: integer >0)");
	return g;
}

static inline void usage(const char* mes) {
	cerr << "Usage Error : " << mes
		<< "\nUse format: ./GameOfLife <matrixfile.txt> <number_of_generations> <number_of_threads> <Y/N> <Y/N>\n"
		<< "Last two are flags for (1) interactive mode , (2) output to screen\n";
	exit(1);
}


static void calc_and_append_statistics(uint n_threads, const vector<double>& gen_hist, const vector<tile_record>& tile_hist) {

	double total_time = (double)accumulate(gen_hist.begin(), gen_hist.end(), 0.0);
	double avg_gen_time = total_time / gen_hist.size();

	double avg_tile_time = 0; 
	for(uint i=0 ; i<tile_hist.size() ; ++i)
		avg_tile_time += tile_hist[i].tile_compute_time;
	avg_tile_time /= tile_hist.size();  
	double gen_rate = gen_hist.size() / total_time;
	double tile_rate = tile_hist.size() / total_time;

	ifstream ifile(DEF_RESULTS_FILE_NAME);
	bool file_exists = ifile.good();
	ifile.close();

	std::ofstream results_file(DEF_RESULTS_FILE_NAME, std::ofstream::app | std::ofstream::out);
	if (!file_exists)
	{
		results_file << "EffectiveThreadNum,GenNum,Gen_Rate[1/us],Avg_Gen_Time[us],Tile_Rate[1/us],Avg_Tile_Time[us],Total_Time[us]" << endl;
		// cout << "Successfully created results file: " << DEF_RESULTS_FILE_NAME << endl;
	}

	results_file << n_threads << "," << gen_hist.size() << "," << gen_rate << "," << avg_gen_time << "," << tile_rate
		<< "," << avg_tile_time << "," << total_time << endl;  

	results_file.close();
}

static void calc_and_append_tile_statistics(const vector<tile_record>& tile_hist) {

    ifstream ifile(DEF_TILE_RESULTS_FILE_NAME);
    bool file_exists = ifile.good();
    ifile.close();

    std::ofstream results_file(DEF_TILE_RESULTS_FILE_NAME, std::ofstream::app | std::ofstream::out);
    if (!file_exists) {
        results_file << "TileIndex,ThreadId,Time" << endl;
    }

    for (int i = 0; i < tile_hist.size(); ++i) {
        results_file << i << "," << tile_hist[i].thread_id << "," << tile_hist[i].tile_compute_time << endl;
    }

    results_file.close();
}