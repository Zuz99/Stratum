
#include "stratum.h"

// sql injection security, unwanted chars
void db_check_user_input(char* input)
{
	char *p = NULL;
	if (input && input[0]) {
		p = strpbrk(input, " \"'\\");
		if(p) *p = '\0';
	}
}

void db_check_coin_symbol(YAAMP_DB *db, char* symbol)
{
	if (!symbol) return;
	size_t len = strlen(symbol);
	if (len >= 2 && len <= 12) {
		if (!g_autoexchange)
			db_query(db, "SELECT symbol FROM coins WHERE installed AND algo='%s' AND symbol='%s'", g_stratum_algo, symbol);
		else
			db_query(db, "SELECT symbol FROM coins WHERE installed AND (symbol='%s' OR symbol2='%s')", symbol, symbol);

		MYSQL_RES *result = mysql_store_result(&db->mysql);
		*symbol = '\0';
		if (!result) return;
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row) {
			strcpy(symbol, row[0]);
		}
		mysql_free_result(result);
	} else {
		*symbol = '\0';
	}
}

// Return coin id for a given coin symbol (must be installed)
static int db_get_coinid_by_symbol(YAAMP_DB *db, const char* symbol)
{
	if(!db || !symbol || !symbol[0]) return 0;
	// installed coins only (same rule as db_check_coin_symbol when g_autoexchange is off)
	if (!g_autoexchange)
		db_query(db, "SELECT id FROM coins WHERE installed AND algo='%s' AND symbol='%s' LIMIT 1", g_stratum_algo, symbol);
	else
		db_query(db, "SELECT id FROM coins WHERE installed AND (symbol='%s' OR symbol2='%s') LIMIT 1", symbol, symbol);

	MYSQL_RES *result = mysql_store_result(&db->mysql);
	if(!result) return 0;
	MYSQL_ROW row = mysql_fetch_row(result);
	int id = (row && row[0]) ? atoi(row[0]) : 0;
	mysql_free_result(result);
	return id;
}

static void db_set_account_wallet(YAAMP_DB *db, int account_id, const char* symbol_in, const char* address_in)
{
	if(!db || account_id <= 0 || !symbol_in || !symbol_in[0] || !address_in || !address_in[0]) return;

	char symbol[16] = {0};
	char address[128] = {0};
	strncpy(symbol, symbol_in, sizeof(symbol)-1);
	strncpy(address, address_in, sizeof(address)-1);

	// basic sanitization (sql injection guard)
	db_check_user_input(symbol);
	db_check_user_input(address);

	int coinid = db_get_coinid_by_symbol(db, symbol);
	if(!coinid) return;

	// account_wallets table must exist on the frontend DB
	// unique key on (account_id, coinid) is expected
	db_query(db,
		"INSERT INTO account_wallets (account_id, coinid, address, created, updated) "
		"VALUES (%d, %d, '%s', UNIX_TIMESTAMP(), UNIX_TIMESTAMP()) "
		"ON DUPLICATE KEY UPDATE address=VALUES(address), updated=VALUES(updated)",
		account_id, coinid, address);
}

void db_add_user(YAAMP_DB *db, YAAMP_CLIENT *client)
{
	db_clean_string(db, client->username);
	db_clean_string(db, client->password);
	db_clean_string(db, client->version);
	db_clean_string(db, client->notify_id);
	db_clean_string(db, client->worker);

	bool guest = false;
	int gift = -1;
	client->solo = false;

	std::string symbol;
	std::vector<std::string> commandlist;
	std::string passwordstring(client->password);

	string_tokenize(passwordstring, ',' , commandlist);

	for (auto &command_pairs: commandlist) {
		std::vector<std::string> command;
		string_tokenize(command_pairs, '=', command);

		if (command.size() > 1) {
			// set payout symbol
			if (command.at(0) == "c") {
				symbol = command.at(1);
			}
			else if (command.at(0) == "s") {
				symbol = command.at(1);
			}
			else if (command.at(0) == "m") {
				if (command.at(1) == "solo") client->solo = true;
			}
			// set list of specific coins to mine only
			else if (command.at(0) == "mc") {
				string_tokenize(command.at(1), '/', client->coins_mining_list);
			}
			// set list of specific coins to skip in selection
			else if (command.at(0) == "nc") {
				string_tokenize(command.at(1), '/', client->coins_ignore_list);
			}
			// Secondary payout address for merged mining / multi-coin payouts
			//  - da=<DOGE_ADDRESS>  (shortcut for DOGE)
			//  - aw=SYMBOL:ADDRESS/SYMBOL:ADDRESS
			else if (command.at(0) == "da") {
				client->payout_addresses.push_back(std::make_pair(std::string("DOGE"), command.at(1)));
			}
			else if (command.at(0) == "aw") {
				std::vector<std::string> parts;
				string_tokenize(command.at(1), '/', parts);
				for(auto &p: parts) {
					std::vector<std::string> kv;
					string_tokenize(p, ':', kv);
					if(kv.size() == 2) {
						client->payout_addresses.push_back(std::make_pair(kv.at(0), kv.at(1)));
					}
				}
			}
#ifdef ALLOW_CUSTOM_DONATIONS
			else if (command.at(0) == "g") {
				gift = atoi(command.at(1).c_str());
				if(gift > 100) gift = 100;
			}
#endif

		}

	}

	db_check_user_input(client->username);
	if(strlen(client->username) < MIN_ADDRESS_LEN) {
		// allow benchmark / test / donate usernames
		if (!strcmp(client->username, "benchmark") || !strcmp(client->username, "donate") || !strcmp(client->username, "test")) {
			guest = true;
			if (g_list_coind.first) {
				CLI li = g_list_coind.first;
				YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
				if (!strlen(client->worker)) strcpy(client->worker, client->username);
				strcpy(client->username, coind->wallet);
				if (!strcmp(client->username, "benchmark")) strcat(client->password, ",stats");
				if (!strcmp(client->username, "donate")) gift = 100;
			}
		}
		if (!guest) {
			debuglog("Invalid user address '%s'\n", client->username);
			return;
		}
	}

	// debuglog("user %s %s gives %d %\n", client->username, symbol, gift);
	db_query(db, "SELECT id, is_locked, logtraffic, coinid, donation FROM accounts WHERE username='%s'", client->username);

	MYSQL_RES *result = mysql_store_result(&db->mysql);
	if(!result) return;

	MYSQL_ROW row = mysql_fetch_row(result);
	if(row)
	{
		if(row[1] && atoi(row[1])) client->userid = -1;
		else client->userid = atoi(row[0]);

		client->logtraffic = row[2] && atoi(row[2]);
		client->coinid = row[3] ? atoi(row[3]) : 0;
		if (gift == -1) gift = row[4] ? atoi(row[4]) : 0; // keep current
	}

	mysql_free_result(result);

	db_check_user_input((char*)symbol.substr(0,15).c_str());
	db_check_coin_symbol(db, (char*)symbol.substr(0,15).c_str());

	if (gift < 0) gift = 0;
	client->donation = gift;

	if(client->userid == -1)
		return;

	else if(client->userid == 0 && strlen(client->username) >= MIN_ADDRESS_LEN)
	{
		db_query(db, "INSERT INTO accounts (username, coinsymbol, balance, donation, hostaddr) values ('%s', '%s', 0, %d, '%s')",
			client->username, symbol.substr(0,15).c_str(), gift, client->sock->ip);
		client->userid = (int)mysql_insert_id(&db->mysql);
	}

	else {
		db_query(db, "UPDATE accounts SET coinsymbol='%s', swap_time=%u, donation=%d, hostaddr='%s' WHERE id=%d AND balance = 0"
			" AND (SELECT COUNT(id) FROM payouts WHERE account_id=%d AND tx IS NULL) = 0" // failed balance
			" AND (SELECT pending FROM balanceuser WHERE userid=%d ORDER by time DESC LIMIT 1) = 0" // pending balance
			, symbol.substr(0,15).c_str(), (uint) time(NULL), gift, client->sock->ip, client->userid, client->userid, client->userid);
		if (mysql_affected_rows(&db->mysql) > 0 && (symbol.size() > 0)) {
			debuglog("%s: %s coinsymbol set to %s ip %s uid (%d)\n",
				g_current_algo->name, client->username, symbol.substr(0,15).c_str(), client->sock->ip, client->userid);
		}
	}

	// Save optional per-coin payout addresses (account_wallets)
	if(client->userid > 0 && !client->payout_addresses.empty()) {
		for(auto &it: client->payout_addresses) {
			// limit size, prevent abuse
			std::string sym = it.first.substr(0, 12);
			std::string addr = it.second.substr(0, 120);
			// upper-case symbol
			for (auto &c : sym) c = toupper(c);
			db_set_account_wallet(db, client->userid, sym.c_str(), addr.c_str());
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////

void db_clear_worker(YAAMP_DB *db, YAAMP_CLIENT *client)
{
	if(!client->workerid)
		return;

	db_query(db, "DELETE FROM workers WHERE id=%d", client->workerid);
	client->workerid = 0;
}

void db_add_worker(YAAMP_DB *db, YAAMP_CLIENT *client)
{
	char password[128] = { 0 };
	char version[128] = { 0 };
	char worker[128] = { 0 };
	int now = time(NULL);

	db_clear_worker(db, client);

	db_check_user_input(client->username);
	db_check_user_input(client->version);
	db_check_user_input(client->password);
	db_check_user_input(client->worker);

	// strip for recent mysql defaults (error if fields are too long)
	if (strlen(client->password) > 64)
		clientlog(client, "password too long truncated: %s", client->password);
	if (strlen(client->version) > 64)
		clientlog(client, "version too long truncated: %s", client->version);
	if (strlen(client->worker) > 64)
		clientlog(client, "worker too long truncated: %s", client->worker);

	strncpy(password, client->password, 64);
	strncpy(version, client->version, 64);
	strncpy(worker, client->worker, 64);

	db_query(db, "INSERT INTO workers (userid, ip, name, difficulty, version, password, worker, algo, time, pid) "\
		"VALUES (%d, '%s', '%s', %f, '%s', '%s', '%s', '%s', %d, %d)",
		client->userid, client->sock->ip, client->username, client->difficulty_actual,
		version, password, worker, g_stratum_algo, now, getpid());

	client->workerid = (int)mysql_insert_id(&db->mysql);
}

void db_update_workers(YAAMP_DB *db)
{
	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted) continue;
		if(!client->workerid) continue;

		if(client->speed < YAAMP_CLIENT_MINSPEED)
		{
			clientlog(client, "speed %f", client->speed);
			shutdown(client->sock->sock, SHUT_RDWR);
			db_clear_worker(db, client);
			object_delete(client);
			continue;
		}

		client->speed *= 0.8;
		if(client->difficulty_written == client->difficulty_actual) continue;

		db_query(db, "UPDATE workers SET difficulty=%f, subscribe=%d WHERE id=%d",
			client->difficulty_actual, client->extranonce_subscribe, client->workerid);
		client->difficulty_written = client->difficulty_actual;
	}

	//client_sort();
	g_list_client.Leave();
}

void db_init_user_coinid(YAAMP_DB *db, YAAMP_CLIENT *client)
{
	if (!client->userid)
		return;

	if (!client->coinid)
		db_query(db, "UPDATE accounts SET coinid=NULL WHERE id=%d", client->userid);
	else
		db_query(db, "UPDATE accounts SET coinid=%d WHERE id=%d AND IFNULL(coinid,0) = 0",
			client->coinid, client->userid);
}

