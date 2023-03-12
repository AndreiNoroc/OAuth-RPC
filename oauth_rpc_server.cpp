#include "oauth_svc.h"
#include "token.h"
#include "user_data.h"

// Map informatii clienti
map<string, UserData> users;

// Lista resurse
vector<string> resources;

// Coada permisiuni
queue<string> approvals;

// Map tokens(initial request dupa care acces) cu semnare si permisiuni 
map<string, AppReqTok> reqtokens;

// Map token acces cu id client
map<string, string> acctokid;

// Valabilitatea tokenurilor
int av = -1;

// Functie pentru jeton autorizare
resp_info *req_auth_1_svc(req_info *data, struct svc_req *cl) {
    static resp_info rsp;

	cout << "BEGIN " << data->id << " AUTHZ\n";

	// Intoarcem mesajul si jetonul in functie de existenta clientului
    if (users.find(data->id) != users.end()) {
		rsp.req_token = strdup(generate_access_token(data->id));
        rsp.message = strdup("USER_FOUND");
		cout << "  RequestToken = " << rsp.req_token << '\n';
    } else {
        rsp.message = strdup("USER_NOT_FOUND");
    }

	// Umplem restul campurilor cu informati dummy
	rsp.reg_access_token = strdup("0");
	rsp.access_token = strdup("0");
	rsp.available_period = 0;

	fflush(stdout);
    return &rsp;
}

// Functia intoarce tokenul de acces
resp_info *req_acc_token_1_svc(req_info *data, struct svc_req *cl) {
	static resp_info rsp;

	// Verificam daca tokenul a fost semnat si retinem informatiile pentru client
	if (reqtokens[string(data->req_token)].sign) {
		users[string(data->id)].req_token = string(data->req_token);
		users[string(data->id)].acc_token = string(generate_access_token(data->req_token));
		if (strcmp(data->resource, "1") == 0) {
			users[string(data->id)].refresh_token = string(generate_access_token((char *)users[string(data->id)].acc_token.c_str()));
		}

		// Verificam daca se tine cont de valabilitate jetoanelor
		if (av > 0) {
			users[string(data->id)].availability = av;
		}

		// Retinem pentru fiecare jeton de acces id ul clientului
		acctokid[users[string(data->id)].acc_token] = string(data->id);

		// Modificam tokenul de autorizare ca si cheie cu tokenul de acces pentru semnatura si permisiuni
		reqtokens[users[string(data->id)].acc_token] = AppReqTok(reqtokens[string(data->req_token)]);		
		reqtokens.erase(string(data->req_token));

		// Populam structura de raspuns
		rsp.access_token = strdup(users[string(data->id)].acc_token.c_str());
		rsp.reg_access_token = strdup(users[string(data->id)].refresh_token.c_str());
		rsp.available_period = users[string(data->id)].availability;
		rsp.req_token = strdup(data->req_token);
		rsp.message = strdup("0");
		cout << "  AccessToken = " << rsp.access_token << '\n';
		if (strcmp(data->resource, "1") == 0) {
			cout << "  RefreshToken = " << rsp.reg_access_token << '\n';
		}
	} else {
		rsp.access_token = strdup("0");
		rsp.reg_access_token = strdup("0");
		rsp.available_period = 0;
		rsp.req_token = strdup("0");
		rsp.message = strdup("REQUEST_DENIED");
	}

	// Scriem restul de informatii stocate in bufferul stdout-ului si returnam raspunsul
	fflush(stdout);
	return &rsp;
}

// Functia intoarce daca clientul are permisiunile sa execute o operatie sau nu
resp_info *val_del_ac_1_svc(req_info *data, struct svc_req *cl) {
    static resp_info rsp;

	rsp.access_token = strdup("0");
	rsp.reg_access_token = strdup("0");
	rsp.available_period = 0;
	rsp.req_token = strdup("0");

	// Verificam existenta userului in baza de date
	if (users.find(acctokid[string(data->access_token)]) == users.end()) {
		cout << "DENY (" << data->op_type << "," << data->resource << ",,0)\n";
		rsp.message = strdup("PERMISSION_DENIED");
		fflush(stdout);
		return &rsp;
	}

	// Verificam valabilitatea jetonului
	if (users[acctokid[string(data->access_token)]].availability != -1) {
		// Verificam daca acesta este expirat
		if (users[acctokid[string(data->access_token)]].availability == 0) {
			string tmpid = acctokid[string(data->access_token)];
			if (users[tmpid].refresh_token.compare("") == 0) {
				rsp.message = strdup("TOKEN_EXPIRED");
				cout << "DENY (" << data->op_type << "," << data->resource << ",,0)\n";
				fflush(stdout);
				return &rsp;
			} else {
				// Reinnoim valabilitatea jetonului daca asa a fost setat in cererea de request
				// Actualizam informatiile clientului
				users[tmpid].acc_token = string(generate_access_token((char *)users[tmpid].refresh_token.c_str()));
				users[tmpid].refresh_token = string(generate_access_token((char *)users[tmpid].acc_token.c_str()));
				users[tmpid].availability = av;

				reqtokens[users[tmpid].acc_token] = AppReqTok(reqtokens[string(data->access_token)]);
				reqtokens.erase(string(data->access_token));

				acctokid[users[tmpid].acc_token] = acctokid[string(data->access_token)];
				acctokid.erase(string(data->access_token));

				rsp.access_token = strdup((char *)users[tmpid].acc_token.c_str());
				rsp.reg_access_token = strdup((char *)users[tmpid].refresh_token.c_str());

				free(data->access_token);
				data->access_token = strdup((char *)users[tmpid].acc_token.c_str());

				cout << "BEGIN " << tmpid << " AUTHZ REFRESH\n";
				cout << "  AccessToken = " << rsp.access_token << '\n';
				cout << "  RefreshToken = " << rsp.reg_access_token << '\n';
			}
		}

		// Scadem valabilitate jetonului la fiecare operatie incercata
		users[acctokid[string(data->access_token)]].availability--;
	}

	// Verificam existenta resursei
	if (find(resources.begin(), resources.end(), string(data->resource)) == resources.end()) {
		cout << "DENY (" << data->op_type << "," << data->resource << "," << data->access_token << ',' << users[acctokid[string(data->access_token)]].availability << ")\n";
		rsp.message = strdup("RESOURCE_NOT_FOUND");
		fflush(stdout);
		return &rsp;
	}
	
	// Verificam daca clientul are permisiunile pentru a executa o operatie
	string perms = reqtokens[string(data->access_token)].permission;
	int len = perms.size();
	int ind = perms.find(data->resource);

	if (ind == string::npos) {
		cout << "DENY (" << data->op_type << "," << data->resource << "," << data->access_token << ',' << users[acctokid[string(data->access_token)]].availability << ")\n";
		rsp.message = strdup("OPERATION_NOT_PERMITTED");
		fflush(stdout);
		return &rsp;
	}

	int pos = perms.find(',', ind + 1);
					
	char c = 'n';
	if (strcmp(data->op_type, "MODIFY") == 0) {
		c = 'M';
	} else if (strcmp(data->op_type, "EXECUTE") == 0) {
		c = 'X';
	} else if (strcmp(data->op_type, "INSERT") == 0) {
		c = 'I';
	} else if (strcmp(data->op_type, "DELETE") == 0) {
		c = 'D';
	} else if (strcmp(data->op_type, "READ") == 0) {
		c = 'R';
	}

	pos++;
	while (pos < len && perms[pos] != ',') {
		if (perms[pos] == c) {
			cout << "PERMIT (" << data->op_type << "," << data->resource << "," << data->access_token << "," << users[acctokid[string(data->access_token)]].availability << ")\n";
			rsp.message = strdup("PERMISSION_GRANTED");
			break;
		}

		pos++;
	}

	if (pos == len || perms[pos] == ',') {
		cout << "DENY (" << data->op_type << "," << data->resource << "," << data->access_token << ',' << users[acctokid[string(data->access_token)]].availability << ")\n";
		rsp.message = strdup("OPERATION_NOT_PERMITTED");
	}

	// Scriem restul de informatii stocate in bufferul stdout-ului si returnam raspunsul
	fflush(stdout);
	return &rsp;
}

// Functia intoarce jetonul semnat si cu permisiunile corespunzatoare
resp_info *app_req_tok_1_svc(req_info *data, struct svc_req *cl) {
    static resp_info rsp;

	// Verificam daca clientul are permisiuni si semnam sau nu in functie de acest aspect
	if (approvals.front().compare("*,-") == 0) {
		reqtokens[string(data->req_token)] = AppReqTok(approvals.front(), false);
	} else {
		reqtokens[string(data->req_token)] = AppReqTok(approvals.front(), true);
	}

	approvals.pop();

	// Umplem structura cu informatii
	rsp.req_token = strdup(data->req_token);
	rsp.message = strdup("0");
	rsp.reg_access_token = strdup("0");
	rsp.access_token = strdup("0");
	rsp.available_period = 0;

	// Scriem restul de informatii stocate in bufferul stdout-ului si returnam raspunsul
	fflush(stdout);
	return &rsp;
}

int
main (int argc, char **argv)
{
	// Verificam numarul de argumente
	if (argc < 4) {
		fprintf(stderr, "Usage:\n\t%s <CLIENTS_FILE> <RESOURCES_FILE> <APPROVES_FILE> \\ <AVAILABLE_TOKENS>\n", argv[0]);
		return -1;
	}

	string line;

	// Citim valabilitate jetoanelor
	if (argc == 5) {
		ifstream avfile(argv[4]);
		avfile >> av;
		avfile.close();
	}

	// Deschidem fisierul de clienti, ii citim si retinem
    ifstream clientsfile(argv[1]);
    getline(clientsfile, line);
	while (getline(clientsfile, line)) {
        users[line] = UserData(string(line));
	}
	clientsfile.close();

	// Deschidem fisierul de resurse, le citim si retinem
    ifstream resourcesfile(argv[2]);
    getline(resourcesfile, line);
	while (getline(resourcesfile, line)) {
        resources.push_back(line);
	}
	resourcesfile.close();

	// Deschidem fisierul de permisiuni, le citim si retinem
	ifstream approvalsfile(argv[3]);
	while (getline(approvalsfile, line)) {
        approvals.push(line);
	}
	approvalsfile.close();

	register SVCXPRT *transp;

	pmap_unset(OAUTH_PROG, OAUTH_VERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}

	if (!svc_register(transp, OAUTH_PROG, OAUTH_VERS, oauth_prog_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (OAUTH_PROG, OAUTH_VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}

	if (!svc_register(transp, OAUTH_PROG, OAUTH_VERS, oauth_prog_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (OAUTH_PROG, OAUTH_VERS, tcp).");
		exit(1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}