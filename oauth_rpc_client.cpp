#include <rpc/rpc.h>

#include "oauth.h"
#include "user_data.h"

#define PROTOCOL "tcp"
#define SERVER_ADDRESS "127.0.0.1"

using namespace std;

// Map pentru retinerea jetoanelor de acces in functie de id-ul clientului
map<string, pair<string, string>> acctokuser;

// Eliberam memoria structurilor de request si raspuns
void freeResponse(resp_info *rsp) {
    free(rsp->access_token);
    free(rsp->message);
    free(rsp->reg_access_token);
    free(rsp->req_token);
}

void freeRequest(req_info *req) {
    free(req->access_token);
    free(req->op_type);
    free(req->permissions);
    free(req->req_token);
    free(req->resource);
}

int main(int argc, char const *argv[])
{
    // Initierea clientului
	CLIENT *handle;
	req_info reqdata;
    resp_info *rspdata = (resp_info*)malloc(sizeof(resp_info));

	if (argc != 3) {
		fprintf(stderr, "Usage:\n\t%s <SERVER_ADDRESS> <OPERATION_FILE>\n", argv[0]);
		return -1;
	}

    handle = clnt_create(SERVER_ADDRESS, OAUTH_PROG, OAUTH_VERS, PROTOCOL);
	if (!handle) {
		perror("Failed to create client handle");
		clnt_pcreateerror(argv[0]);
		return -2;
	}

    // Deschidem fisierul de operatii, citim si urmam flowul

    string line; 
    ifstream opfile(argv[2]);
    char* new_id;
    char* action;
    char* resources;
    char* new_access_token;
    char* new_req_token;
    char* new_permissions;

    while (getline(opfile, line)) {
        // Citim fiecare operatie si retinem valorile campurilor
        new_id = strdup((char *)line.substr(0, 15).c_str());

        auto com1 = line.find(',');
        auto com2 = line.find(',', com1 + 1);
        action = strdup((char *)line.substr(16, com2 - com1 - 1).c_str());

        int len = line.size();
        resources = strdup((char *)line.substr(com2 + 1, len - com2).c_str());

        new_access_token = strdup("0");
        new_req_token = strdup("0");
        new_permissions = strdup("0");

        reqdata.id = new_id;
        reqdata.op_type = action;
        reqdata.resource = resources;
        reqdata.access_token = new_access_token;
        reqdata.req_token = new_req_token;
        reqdata.permissions = new_permissions;

        // Verificam daca este un Request sau o operatie
        if (strcmp(action, "REQUEST") == 0) {
            // Generam un jeton pentru autorizare
            rspdata = req_auth_1(&reqdata, handle);
            if (strcmp(rspdata->message, "USER_NOT_FOUND") == 0) {
                cout << "USER_NOT_FOUND\n";
                continue;
            }

            // Eliberam memoria si retinem jetonul returnat
            free(new_req_token);
            new_req_token = strdup(rspdata->req_token);
            reqdata.req_token = new_req_token;

            // Semnam jetonul si ii setam permisiunile
            freeResponse(rspdata);
            rspdata = app_req_tok_1(&reqdata, handle);

            // Generam jetonul de acces si afisam jetoanele generate
            freeResponse(rspdata);
            rspdata = req_acc_token_1(&reqdata, handle);
            if (strcmp(rspdata->message, "REQUEST_DENIED") == 0) {
                cout << "REQUEST_DENIED\n";
            } else {
                acctokuser[string(reqdata.id)] = {rspdata->access_token, rspdata->reg_access_token};
                if (strcmp(resources, "1") == 0) {
                    cout << rspdata->req_token << " -> " << rspdata->access_token << "," << rspdata->reg_access_token << '\n';
                } else {
                    cout << rspdata->req_token << " -> " << rspdata->access_token << '\n';
                }
            }
        } else {
             // Eliberam memoria
            freeResponse(rspdata);

            // Verificam daca operatia poate fi executata si intoarcem mesajul corespunzator
            free(new_access_token);
            new_access_token = strdup(acctokuser[string(reqdata.id)].first.c_str());
            reqdata.access_token = new_access_token;
            rspdata = val_del_ac_1(&reqdata, handle);
            cout << rspdata->message << '\n';

            // Verificam daca s-a regenerat un jeton de acces si retinem informatiile necesare
            if (strlen(rspdata->reg_access_token) == 15) {
                acctokuser[string(reqdata.id)] = {rspdata->access_token, rspdata->reg_access_token};
            }
        }

        // Eliberam memoria
        freeRequest(&reqdata);
    }
    opfile.close();

    // Distrugem clientul
    clnt_destroy(handle);

    return 0;
}