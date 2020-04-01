#include "utils.hpp"

/*--------------------------------------------------------------------------------
									Misc Utils Implementation
--------------------------------------------------------------------------------*/
vector<string> utils::read_lines(const string& filename) {

	ifstream file(filename);
	user_error(string("Invalid file: ") + filename, file.good());
	vector<string> lines;
	string curr;

	while (getline(file, curr))
	{
		if (curr.size() > 0)
			lines.push_back(curr);
	}
	file.close();
	return lines;
}

vector<string> utils::split(const string& s, char delimiter)
{
	vector<string> tokens;
	string token;
	istringstream token_stream(s);
	while (getline(token_stream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

/*--------------------------------------------------------------------------------
								String Extentions
--------------------------------------------------------------------------------*/

string repeat(string str, const size_t n)
{
	if (n == 0) {
		str.clear();
		str.shrink_to_fit();
		return str;
	}
	else if (n == 1 || str.empty()) {
		return str;
	}
	const auto period = str.size();
	if (period == 1) {
		str.append(n - 1, str.front());
		return str;
	}
	str.reserve(period * n);
	size_t m{ 2 };
	for (; m < n; m *= 2) str += str;
	str.append(str.c_str(), (n - (m / 2)) * period);
	return str;
}

string operator*(string str, size_t n)
{
	return repeat(move(str), n);
}

