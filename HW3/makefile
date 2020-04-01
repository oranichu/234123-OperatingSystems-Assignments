##----------------------------------------------------------------------
##							Makefile Variables
##----------------------------------------------------------------------
TARGET := GameOfLife

CXX := g++
CXXFLAGS := -std=c++11 -g -Wall -pedantic-errors -pthread 
LDFLAGS := -lpthread -static-libstdc++
RM := rm -f

SRC := $(shell find . -name "*.cpp")
OBJS  := $(patsubst %.cpp, %.o, $(SRC))
##----------------------------------------------------------------------
##								Make Functions
##----------------------------------------------------------------------
all: $(TARGET)
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

depend: .depend

.depend: $(SRC)
	rm -f ./.depend
	$(CXX) $(CXXFLAGS) -MM $^>>./.depend;

clean:
	$(RM) $(OBJS)

include .depend
