#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <sstream>
#include <vector>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

vector<string> split_dot(const string& str) {
    vector<string> parts;
    stringstream ss(str);
    string part;

    while (getline(ss, part, '.')) {
        parts.push_back(part);
    }

    return parts;
}

vector<string> split_hyphen(const string& str) {
    vector<string> parts;
    stringstream ss(str);
    string part;

    while (getline(ss, part, '-')) {
        parts.push_back(part);
    }

    return parts;
}

vector<string> split_comma(const string& str) {
    vector<string> parts;
    stringstream ss(str);
    string part;

    while (getline(ss, part, ',')) {
        parts.push_back(part);
    }

    return parts;
}


void store_hashes(const string& domain, unordered_map<int, unordered_map<string, int>>& hashes) {
    vector<string> parts = split_dot(domain);

    for (size_t i = 0; i < parts.size(); ++i) {
        string level = parts[parts.size() - 1 - i];
        
        vector<string> sub_comma = split_comma(level);

        for (const string& part_comma : sub_comma) {
            vector<string> sub_hyphen = split_hyphen(part_comma);

            for (const string& final_token : sub_hyphen) {
                if (hashes[i].find(final_token) == hashes[i].end()) {
                    hashes[i][final_token] = 1;
                } else {
                    hashes[i][final_token]++;
                }
            }
        }
    }
}


void write_in_files(const fs::path& output_directory, const unordered_map<int, unordered_map<string, int>>& hashes) {
    for (const auto& level : hashes) {
        fs::path output_file = output_directory / ("wordlist_level_" + to_string(level.first) + ".txt");
        
        ofstream file(output_file);

        if (!file.is_open()) {
            cerr << "Error when creating the file" << output_file << ".\n";
            continue;
        }

        for (const auto& sublevel : level.second) {
            file << sublevel.first << "," << sublevel.second << endl;
        }

        file.close();
    }
}

int main(int argc, char* argv[]){

    if (argc != 3) {
        cerr << "Input : " << argv[0] << " <rdns_file> <directory_to_save>\n";
        return 1;
    }

    fs::path rdns_file = argv[1];
    fs::path output_directory = argv[2];

    if (!fs::exists(rdns_file)) {
        cerr << "Input file not found.\n";
        return 1;
    }

    if (!fs::is_directory(output_directory)) {
        cerr << "Output directory not found.\n";
        return 1;
    }

    ifstream file(rdns_file);
    string line;
    unordered_map<int, unordered_map<string, int>> hashes;

    if (!file.is_open()) {
        cerr << "Error opening the file\n";
        return 1;
    }

    while (getline(file, line)) {
        size_t pos_type = line.find("\"type\":\"ptr\"");
        if (pos_type != string::npos) {
            size_t pos_value = line.find("\"value\":\"");
            if (pos_value != string::npos) {
                pos_value += 9;
                size_t pos_end = line.find("\"", pos_value);
                if (pos_end != string::npos) {
                    string domain = line.substr(pos_value, pos_end - pos_value);
                    store_hashes(domain, hashes);
                }
            }
        }
    }

    write_in_files(output_directory, hashes);

    file.close();
    return 0;
}
