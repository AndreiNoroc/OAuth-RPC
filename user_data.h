#ifndef _USERDATA_H_
#define _USERDATA_H_

#include <fstream>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <stdlib.h>
#include <queue>
#include <algorithm>

using namespace std;

// Structura informatii jetoane client
class UserData {
public:
    string id;
    string req_token;
    string acc_token;
    string refresh_token;
    int availability;

    UserData() {};

    UserData(string id) {
        id = id;
        refresh_token =  "";
    };

    UserData(UserData &user) {
        id = user.id;
        req_token = user.req_token;
        acc_token = user.acc_token;
        refresh_token = user.refresh_token;
        availability = user.availability;
    };
};

// Structura informatii jeton acces si permisiuni clienti
class AppReqTok {
public:
    string permission;
    bool sign;

    AppReqTok() {};

    AppReqTok(AppReqTok &tok) {
        permission = tok.permission;
        sign = tok.sign;
    };

    AppReqTok(string perm, bool s) {
        permission = perm;
        sign = s;
    };    
};

#endif 