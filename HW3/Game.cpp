#include "Game.hpp"
#include "Headers.hpp"
#include "GolThread.hpp"
#include "Task.hpp"
#include "RevSem.hpp"
#include "utils.hpp"

using namespace utils;

/*--------------------------------------------------------------------------------
								
--------------------------------------------------------------------------------*/
Game::Game(game_params gp) : m_gen_num(gp.n_gen), m_thread_num(gp.n_thread),
                             m_file_name(gp.filename),
                             interactive_on(gp.interactive_on),
                             print_on(gp.print_on), m_height(0), m_width(0),m_curr_gen(0) {

    pthread_mutexattr_init(&m_mutex_attr);
    pthread_mutexattr_settype(&m_mutex_attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&m_mutex_lock, &m_mutex_attr);
    pthread_cond_init(&m_cond, nullptr);

    // TODO read todo at RevSem
}

Game::~Game() {
    pthread_mutex_destroy(&m_mutex_lock);
    pthread_mutexattr_destroy(&m_mutex_attr);
    pthread_cond_destroy(&m_cond);
}

void Game::run() {
    _init_game(); // Starts the threads and all other variables you need
    print_board("Initial Board");
    for (uint i = 0; i < m_gen_num; ++i) {
        auto gen_start = std::chrono::system_clock::now();
        _step(i); // Iterates a single generation
        auto gen_end = std::chrono::system_clock::now();
        m_gen_hist.push_back(
                (double) std::chrono::duration_cast<std::chrono::microseconds>(
                        gen_end - gen_start).count());
        print_board(nullptr);
    } // generation loop
    print_board("Final Board");
    _destroy_game();
}

void Game::_init_game() {

    // Create game fields - Consider using utils:read_file, utils::split
    // Create & Start threads
    // Testing of your implementation will presume all threads are started here

    vector<string> lines;
    lines = read_lines(m_file_name);

    vvi grid;
    vector<string> grid_line;
    for (uint i = 0; i < lines.size(); ++i) { // Creating game fields
        grid.push_back(vector<uint>());
        grid_line = split(lines[i], ' ');
        for (uint j = 0; j < grid_line.size(); ++j) {
            istringstream string_to_int(grid_line[j]);
            uint num;
            string_to_int >> num;
            grid[i].push_back(num);
        }
    }
    m_curr.swap(grid);

    m_height = m_curr.size();
    m_width = m_curr[0].size();
    initNext();

    if (m_height < m_thread_num) {
        _setThreadNum(m_height);
    }

    m_rev_sem.initRevSem(m_thread_num);

    for (uint k = 0; k < m_thread_num; ++k) {   // Thread creation.
        Thread *t = new GolThread(k, m_task_queue, m_tile_hist, m_mutex_lock, m_rev_sem);
        m_threadpool.push_back(t);
    }

    for (uint l = 0; l < m_thread_num; ++l) { // Thread starting.
        m_threadpool[l]->start();
        if (DEBUG) cout << "GolThread " << l << " was invoked" << endl;
    }

    if (DEBUG) cout << "All GolThreads were invoked" << endl;

}

void Game::_step(uint curr_gen) {
    // Push jobs to queue
    // Wait for the workers to finish calculating
    // Swap pointers between current and next field
    // NOTE: Threads must not be started here - doing so will lead to a heavy penalty in your grade
    // TODO were not using curr gen ?! need to put it in info or something ~!~!~!
    size_t tile_length = m_height / m_thread_num;
    for (uint k = 0; k < m_thread_num - 1; ++k) { // 
        m_task_queue.push(Task(m_curr, m_next, k * tile_length, (k + 1) * tile_length - 1));
    }
    m_task_queue.push(Task(m_curr, m_next, (m_thread_num - 1) * tile_length, m_height - 1));

    m_rev_sem.wait(); //TODO in init i set it to thread number how do init the counter again ?
    m_curr_gen = curr_gen;
    m_curr.swap(m_next); // Swapping curr and next field.
    initNext(); // TODO Maybe we need to put pointers and switch them ?

}

void Game::_destroy_game() {
    // Destroys board and frees all threads and resources
    // Not implemented in the Game's destructor for testing purposes.
    // All threads must be joined here

    for (uint k = 0; k < m_thread_num; ++k) { // Poison all threads.
        m_task_queue.push(Task(m_curr, m_next, 0, 0, true));
    }

    for (uint i = 0; i < m_thread_num; ++i) { // Join all threads.
        m_threadpool[i]->join();
    }

    for (uint k = 0; k < m_thread_num; ++k) { // Delete all threads allocations.
        delete (m_threadpool[k]);
    }

    // TODO think maybe delete something more.
}

/*--------------------------------------------------------------------------------
								
--------------------------------------------------------------------------------*/
inline void Game::print_board(const char *header) {

    if (print_on) {

        // Clear the screen, to create a running animation
        if (interactive_on)
            system("clear");

        // Print small header if needed
        if (header != nullptr)
            cout << "<------------" << header << "------------>" << endl;

        // Print the board
        cout << u8"╔" << string(u8"═") * m_width << u8"╗" << endl;
        for (uint i = 0; i < m_height; ++i) {
            cout << u8"║";
            for (uint j = 0; j < m_width; ++j) {
                cout << (m_curr[i][j] ? u8"█" : u8"░");
            }
            cout << u8"║" << endl;
        }
        cout << u8"╚" << string(u8"═") * m_width << u8"╝" << endl;

        // Display for GEN_SLEEP_USEC micro-seconds on screen
        if (interactive_on)
            usleep(GEN_SLEEP_USEC);

    }

}

void Game::_setThreadNum(uint thread_num) {
    m_thread_num = thread_num;
}

void Game::initNext() {
    m_next = vvi(m_height, vector<uint>(m_width, 0));
}

const vector<double> Game::gen_hist() const {
    return m_gen_hist;
}

const vector<tile_record> Game::tile_hist() const {
    return m_tile_hist;
}

uint Game::thread_num() const {
    return m_thread_num;
}

/* Function sketch to use for printing the board. You will need to decide its placement and how exactly 
	to bring in the field's parameters. 

		cout << u8"╔" << string(u8"═") * field_width << u8"╗" << endl;
		for (uint i = 0; i < field_height ++i) {
			cout << u8"║";
			for (uint j = 0; j < field_width; ++j) {
				cout << (field[i][j] ? u8"█" : u8"░");
			}
			cout << u8"║" << endl;
		}
		cout << u8"╚" << string(u8"═") * field_width << u8"╝" << endl;
*/








