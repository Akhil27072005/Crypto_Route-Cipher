#include <cctype>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace route_cipher {

static std::string read_all_stdin_bytes() {
  std::istreambuf_iterator<char> it(std::cin.rdbuf());
  std::istreambuf_iterator<char> end;
  return std::string(it, end);
}

static std::string to_hex8_upper(uint32_t x) {
  std::ostringstream oss;
  oss << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x;
  return oss.str();
}

// Custom 32-bit hash per spec.
std::string custom_hash_hex8(const std::string& input) {
  uint32_t h = 2654435769u;
  for (size_t i = 0; i < input.size(); ++i) {
    uint32_t value = static_cast<unsigned char>(input[i]);  // ASCII/byte value (UTF-8 bytes preserved)
    uint32_t mixed = (h << 5) + (h >> 2) + value + static_cast<uint32_t>(i);
    h = h ^ mixed;
    h &= 0xFFFFFFFFu;
  }

  h = h ^ (h >> 16);
  h = static_cast<uint32_t>((static_cast<uint64_t>(h) * 0x45d9f3bu) & 0xFFFFFFFFu);
  h = h ^ (h >> 16);

  return to_hex8_upper(h);
}

static std::pair<size_t, size_t> compute_grid_dims(size_t L) {
  if (L == 0) return {0, 0};
  long double root = std::sqrt(static_cast<long double>(L));
  size_t rows = static_cast<size_t>(std::ceil(root));
  size_t cols = static_cast<size_t>(std::ceil(static_cast<long double>(L) / static_cast<long double>(rows)));
  return {rows, cols};
}

static std::vector<std::vector<char>> make_grid(size_t rows, size_t cols, char fill = 'X') {
  return std::vector<std::vector<char>>(rows, std::vector<char>(cols, fill));
}

static std::string spiral_read_clockwise(const std::vector<std::vector<char>>& grid) {
  const size_t rows = grid.size();
  const size_t cols = rows ? grid[0].size() : 0;
  if (rows == 0 || cols == 0) return {};

  std::string out;
  out.reserve(rows * cols);

  size_t top = 0, bottom = rows - 1;
  size_t left = 0, right = cols - 1;
  while (top <= bottom && left <= right) {
    for (size_t c = left; c <= right; ++c) out.push_back(grid[top][c]);
    if (top == bottom) break;
    ++top;

    for (size_t r = top; r <= bottom; ++r) out.push_back(grid[r][right]);
    if (left == right) break;
    if (right == 0) break;
    --right;

    for (size_t c = right + 1; c-- > left;) out.push_back(grid[bottom][c]);
    if (bottom == 0) break;
    --bottom;

    for (size_t r = bottom + 1; r-- > top;) out.push_back(grid[r][left]);
    ++left;
  }

  return out;
}

static void spiral_fill_clockwise(std::vector<std::vector<char>>& grid, const std::string& text) {
  const size_t rows = grid.size();
  const size_t cols = rows ? grid[0].size() : 0;
  if (rows == 0 || cols == 0) return;
  if (text.size() != rows * cols) {
    throw std::invalid_argument("spiral_fill_clockwise: text length must equal rows*cols");
  }

  size_t idx = 0;
  size_t top = 0, bottom = rows - 1;
  size_t left = 0, right = cols - 1;
  while (top <= bottom && left <= right) {
    for (size_t c = left; c <= right; ++c) grid[top][c] = text[idx++];
    if (top == bottom) break;
    ++top;

    for (size_t r = top; r <= bottom; ++r) grid[r][right] = text[idx++];
    if (left == right) break;
    if (right == 0) break;
    --right;

    for (size_t c = right + 1; c-- > left;) grid[bottom][c] = text[idx++];
    if (bottom == 0) break;
    --bottom;

    for (size_t r = bottom + 1; r-- > top;) grid[r][left] = text[idx++];
    ++left;
  }
}

static std::vector<std::vector<char>> fill_row_wise_with_padding(const std::string& text, size_t rows, size_t cols) {
  auto grid = make_grid(rows, cols, 'X');
  size_t idx = 0;
  for (size_t r = 0; r < rows; ++r) {
    for (size_t c = 0; c < cols; ++c) {
      if (idx < text.size()) grid[r][c] = text[idx++];
      else grid[r][c] = 'X';
    }
  }
  return grid;
}

static std::string read_row_wise(const std::vector<std::vector<char>>& grid) {
  const size_t rows = grid.size();
  const size_t cols = rows ? grid[0].size() : 0;
  std::string out;
  out.reserve(rows * cols);
  for (size_t r = 0; r < rows; ++r) {
    for (size_t c = 0; c < cols; ++c) out.push_back(grid[r][c]);
  }
  return out;
}

std::string encrypt(const std::string& plaintext) {
  const std::string h = custom_hash_hex8(plaintext);
  const std::string combined = plaintext + h;

  const auto dims = compute_grid_dims(combined.size());
  const size_t rows = dims.first;
  const size_t cols = dims.second;
  auto grid = fill_row_wise_with_padding(combined, rows, cols);
  return spiral_read_clockwise(grid);
}

struct DecryptResult {
  std::string plaintext;
  std::string extracted_hash;
  std::string recomputed_hash;
  bool valid = false;
};

DecryptResult decrypt_and_validate(const std::string& ciphertext) {
  DecryptResult res;

  const auto dims = compute_grid_dims(ciphertext.size());
  const size_t rows = dims.first;
  const size_t cols = dims.second;
  auto grid = make_grid(rows, cols, 'X');
  spiral_fill_clockwise(grid, ciphertext);

  std::string combined = read_row_wise(grid);
  while (!combined.empty() && combined.back() == 'X') combined.pop_back();

  if (combined.size() < 8) {
    res.plaintext = combined;
    res.extracted_hash = "";
    res.recomputed_hash = custom_hash_hex8(res.plaintext);
    res.valid = false;
    return res;
  }

  res.extracted_hash = combined.substr(combined.size() - 8);
  res.plaintext = combined.substr(0, combined.size() - 8);
  res.recomputed_hash = custom_hash_hex8(res.plaintext);
  res.valid = (res.recomputed_hash == res.extracted_hash);
  return res;
}

}  // namespace route_cipher

static void print_usage(const char* exe) {
  std::cerr
      << "Usage:\n"
      << "  " << exe << "            (interactive menu)\n"
      << "  " << exe << " encrypt   < stdin > stdout\n"
      << "  " << exe << " decrypt   < stdin > stdout\n\n"
      << "Notes:\n"
      << "  - Input is read as raw bytes from stdin (spaces/newlines preserved).\n"
      << "  - encrypt outputs ciphertext.\n"
      << "  - decrypt outputs plaintext, then a newline, then VALID/TAMPERED.\n";
}

static std::string read_line(const std::string& prompt) {
  std::cout << prompt;
  std::cout.flush();
  std::string s;
  std::getline(std::cin, s);
  return s;
}

static void print_grid(const std::vector<std::vector<char>>& grid) {
  const size_t rows = grid.size();
  const size_t cols = rows ? grid[0].size() : 0;
  std::cout << "Grid (" << rows << "x" << cols << "):\n";
  for (size_t r = 0; r < rows; ++r) {
    std::cout << "  ";
    for (size_t c = 0; c < cols; ++c) {
      std::cout << grid[r][c];
      if (c + 1 < cols) std::cout << ' ';
    }
    std::cout << "\n";
  }
}

static void encrypt_verbose(const std::string& plaintext) {
  std::cout << "\n=== ENCRYPT (step-by-step) ===\n";
  std::cout << "Plaintext: [" << plaintext << "]\n";

  const std::string h = route_cipher::custom_hash_hex8(plaintext);
  std::cout << "Step 1) Hash (8 hex chars): " << h << "\n";

  const std::string combined = plaintext + h;
  std::cout << "Step 2) Combined (plaintext+hash): [" << combined << "]\n";
  std::cout << "        Combined length: " << combined.size() << "\n";

  const auto dims = route_cipher::compute_grid_dims(combined.size());
  const size_t rows = dims.first;
  const size_t cols = dims.second;
  std::cout << "Step 3) Grid dimensions: rows=" << rows << ", cols=" << cols << "\n";

  const auto grid = route_cipher::fill_row_wise_with_padding(combined, rows, cols);
  std::cout << "Step 4) Fill grid row-wise (pad with 'X'):\n";
  print_grid(grid);

  const std::string ciphertext = route_cipher::spiral_read_clockwise(grid);
  std::cout << "Step 5) Read grid in clockwise spiral => Ciphertext:\n";
  std::cout << ciphertext << "\n";
}

static void decrypt_verbose(const std::string& ciphertext) {
  std::cout << "\n=== DECRYPT (step-by-step) ===\n";
  std::cout << "Ciphertext: [" << ciphertext << "]\n";
  std::cout << "Ciphertext length: " << ciphertext.size() << "\n";

  const auto dims = route_cipher::compute_grid_dims(ciphertext.size());
  const size_t rows = dims.first;
  const size_t cols = dims.second;
  std::cout << "Step 1) Grid dimensions from ciphertext length: rows=" << rows << ", cols=" << cols << "\n";

  auto grid = route_cipher::make_grid(rows, cols, 'X');
  route_cipher::spiral_fill_clockwise(grid, ciphertext);
  std::cout << "Step 2) Fill grid in clockwise spiral:\n";
  print_grid(grid);

  std::string combined = route_cipher::read_row_wise(grid);
  std::cout << "Step 3) Read grid row-wise => Combined (with padding): [" << combined << "]\n";

  size_t trimmed = 0;
  while (!combined.empty() && combined.back() == 'X') {
    combined.pop_back();
    ++trimmed;
  }
  std::cout << "Step 4) Trim trailing padding 'X': trimmed=" << trimmed << "\n";
  std::cout << "        Combined (trimmed): [" << combined << "]\n";

  if (combined.size() < 8) {
    std::cout << "Step 5) Combined too short to contain hash (need >= 8). Marking TAMPERED.\n";
    const std::string recomputed = route_cipher::custom_hash_hex8(combined);
    std::cout << "        Plaintext: [" << combined << "]\n";
    std::cout << "        Recomputed hash: " << recomputed << "\n";
    std::cout << "Result: TAMPERED\n";
    return;
  }

  const std::string extracted_hash = combined.substr(combined.size() - 8);
  const std::string plaintext = combined.substr(0, combined.size() - 8);
  std::cout << "Step 5) Extract last 8 chars as hash:\n";
  std::cout << "        Plaintext: [" << plaintext << "]\n";
  std::cout << "        Extracted hash: " << extracted_hash << "\n";

  const std::string recomputed_hash = route_cipher::custom_hash_hex8(plaintext);
  std::cout << "Step 6) Recompute hash(plaintext): " << recomputed_hash << "\n";

  const bool valid = (recomputed_hash == extracted_hash);
  std::cout << "Step 7) DECRYPT: compare recomputed vs extracted => " << (valid ? "VALID" : "TAMPERED") << "\n";
}

static void interactive_menu() {
  std::cout << "Route Cipher Demo (interactive)\n";
  std::cout << "--------------------------------\n";

  while (true) {
    std::cout << "\nMenu:\n";
    std::cout << "  1) Encrypt text\n";
    std::cout << "  2) Decrypt text (and validate)\n";
    std::cout << "  3) Encrypt then decrypt automatically\n";
    std::cout << "  0) Exit\n\n";

    const std::string choice = read_line("Choice: ");

    if (choice == "0") return;

    if (choice == "1") {
      const std::string plaintext = read_line("Enter plaintext (single line): ");
      encrypt_verbose(plaintext);
      continue;
    }

    if (choice == "2") {
      const std::string ciphertext = read_line("Enter ciphertext (single line): ");
      decrypt_verbose(ciphertext);
      continue;
    }

    if (choice == "3") {
      const std::string plaintext = read_line("Enter plaintext (single line): ");
      const std::string ciphertext = route_cipher::encrypt(plaintext);
      encrypt_verbose(plaintext);
      decrypt_verbose(ciphertext);
      continue;
    }

    std::cout << "Invalid choice. Try again.\n";
  }
}

int main(int argc, char** argv) {
  try {
    if (argc == 1) {
      interactive_menu();
      return 0;
    }

    if (argc != 2) {
      print_usage(argv[0]);
      return 2;
    }

    const std::string mode = argv[1];
    const std::string input = route_cipher::read_all_stdin_bytes();

    if (mode == "encrypt") {
      std::cout << route_cipher::encrypt(input);
      return 0;
    }

    if (mode == "decrypt") {
      auto res = route_cipher::decrypt_and_validate(input);
      std::cout << res.plaintext << "\n" << (res.valid ? "VALID" : "TAMPERED");
      return res.valid ? 0 : 1;
    }

    print_usage(argv[0]);
    return 2;
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 3;
  }
}

