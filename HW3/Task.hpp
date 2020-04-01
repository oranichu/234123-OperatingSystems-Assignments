//
// Created by user on 23/05/2019.
//

#ifndef OS_WET3_TASK_H
#define OS_WET3_TASK_H

#include "Headers.hpp"

class Task {
public:

    Task(const vvi &curr, vvi &next, size_t lower_bond, size_t upper_bond, bool p = false);

    void exe();

    bool isPoison();


private:
    const vvi &m_curr;
    vvi &m_next;

    size_t m_lower_bond;
    size_t m_upper_bond;
    bool m_poison;

    size_t m_height;
    size_t m_width;

    uint getAliveNeighbours(uint i, uint j);

    bool isCellDead(uint i, uint j);


    void giveBirth(uint i, uint j);

    void survive(uint i, uint j);

};


#endif //OS_WET3_TASK_H
