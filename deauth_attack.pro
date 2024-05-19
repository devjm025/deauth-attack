TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        attack.cpp \
        mac.cpp \
        main.cpp

HEADERS += \
    attack.h \
    mac.h
