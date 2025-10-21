#pragma once
#include <string>
#include <vector>
#include <utility>

std::string transform_ciphertext(const std::string& ciphertext);
std::vector<std::pair<int, int>> get_divisor_frequency(const std::string& ciphertext);
std::vector<std::string> get_column_substrings(const std::string& input, size_t n);
std::vector<int> initialize_key_shifts(std::vector<std::string> column_substrings, std::string language);
std::vector<std::string> caesar_decrypt_columns(const std::vector<std::string>& column_substrings, const std::vector<int>& key_shifts);
std::string reassemble_plaintext(const std::vector<std::string>& decrypted_columns, const std::string cipher_text);
std::string create_key(const std::vector<int>& key_shifts);