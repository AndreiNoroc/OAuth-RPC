/* Structura date request */
struct req_info {
    string id<15>;
    string req_token<>;
    string permissions<>;
    string op_type<>;
    string resource<>;
    string access_token<>;
};

/* Structura date raspuns */
struct resp_info {
    string req_token<>;
    string access_token<>;
    string reg_access_token<>;
    int available_period; 
    string message<>;
};

/* Procedurile utilizate in flowul aplicatiei */
program OAUTH_PROG {
    version OAUTH_VERS {
        resp_info req_auth(struct req_info) = 1;
        resp_info req_acc_token(struct req_info) = 2;
        resp_info val_del_ac(struct req_info) = 3;
        resp_info app_req_tok(struct req_info) = 4;
    } = 1;
} = 1;