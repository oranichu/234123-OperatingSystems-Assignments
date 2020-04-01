//
// Created by user on 23/05/2019.
//

#include "Task.hpp"
#include "utils.hpp"
#include "Headers.hpp"

Task::Task(const vvi &curr, vvi &next, size_t lower_bond, size_t upper_bond, bool p)
        : m_curr(curr), m_next(next), m_lower_bond(lower_bond), m_upper_bond(upper_bond),
          m_poison(p) {
    m_height = curr.size();
    m_width = curr[0].size();
}

void Task::exe() {
    for (size_t i = m_lower_bond; i <= m_upper_bond; ++i) {
        for (uint j = 0; j < m_width; ++j) {
            uint live_neighbours = getAliveNeighbours(i, j);
            if (isCellDead(i, j)) {
                if (live_neighbours == BIRTH) {
                    giveBirth(i, j);
                }
            } else {
                if (live_neighbours == SURVIVE_1 ||
                    live_neighbours == SURVIVE_2) {
                    survive(i, j);
                }
            }
        }
    }
}

bool Task::isPoison() {
    return m_poison;
}

uint Task::getAliveNeighbours(uint i, uint j) {

    // Corner case : 1 row and 1 col.
    if (m_width == 1 && m_height == 1) {
        return 0;
    }

    //Corner case : 1 row
    if (m_height == 1) {
        if (j == 0) { // first cell.
            return m_curr[0][1];
        } else if (j == m_width -1) { // last cell.
            return m_curr[0][m_width-1];
        } else {
            return m_curr[0][j-1] + m_curr[0][j+1];
        }
    }

    //Corner case : 1 col
    if (m_width == 1) {
        if (i == 0) { // first cell.
            return m_curr[1][0];
        } else if (i == m_height -1) { // last cell.
            return m_curr[m_height-2][0];
        } else {
            return m_curr[i-1][0] + m_curr[i+1][0];
        }
    }

    // case 1 : top left corner.
    if (i == 0 && j == 0) {
        return m_curr[0][1] + m_curr[1][0] + m_curr[1][1];
    }

    // case 2 : top right corner.
    if (i == 0 && j == m_width - 1) {
        return m_curr[0][m_width - 2] + m_curr[1][m_width - 1] +
               m_curr[1][m_width - 2];
    }

    // case 3 : low left corner.
    if (i == m_height - 1 && j == 0) {
        return m_curr[m_height - 2][0] + m_curr[m_height - 1][1] +
               m_curr[m_height - 2][1];
    }

    // case 4 : low right corner.
    if (i == m_height - 1 && j == m_width - 1) {
        return m_curr[m_height - 2][m_width - 1] +
               m_curr[m_height - 2][m_width - 2] +
               m_curr[m_height - 1][m_width - 2];
    }

    // case 5 : left col.
    if (j == 0) {
        return m_curr[i - 1][0] + m_curr[i - 1][1] + m_curr[i][1] +
               m_curr[i + 1][1] + m_curr[i + 1][0];
    }

    // case 6 : right col.
    if (j == m_width - 1) {
        return m_curr[i - 1][m_width - 1] + m_curr[i - 1][m_width - 2] +
               m_curr[i][m_width - 2] + m_curr[i + 1][m_width - 2] +
               m_curr[i + 1][m_width - 1];
    }

    // case 7 : top row.
    if (i == 0) {
        return m_curr[0][j - 1] + m_curr[1][j - 1] + m_curr[1][j] +
               m_curr[1][j + 1] + m_curr[0][j + 1];
    }

    // case 8 : bottom row.
    if (i == m_height - 1) {
        return m_curr[m_height - 1][j - 1] + m_curr[m_height - 2][j - 1] +
               m_curr[m_height - 2][j] + m_curr[m_height - 2][j + 1] +
               m_curr[m_height - 1][j + 1];
    }

    // case 9 : center.
    return m_curr[i - 1][j - 1] + m_curr[i - 1][j] + m_curr[i - 1][j + 1] +
           m_curr[i][j - 1] + m_curr[i][j + 1] +
           m_curr[i + 1][j - 1] + m_curr[i + 1][j] + m_curr[i + 1][j + 1];
}

bool Task::isCellDead(uint i, uint j) {
    return m_curr[i][j] == 0;
}

void Task::giveBirth(uint i, uint j) {
    m_next[i][j] = 1;
}

void Task::survive(uint i, uint j) {
    m_next[i][j] = 1;
}



