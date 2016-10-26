extern crate rustc_serialize as serialize;
extern crate ordered_float;
extern crate openssl;

pub use serialize::base64::{FromBase64, ToBase64};
pub use serialize::hex::{FromHex, ToHex};
pub use std::ascii::AsciiExt;
pub use std::collections::HashMap;
pub use std::collections::BTreeMap;
pub use std::collections::BinaryHeap;
pub use ordered_float::OrderedFloat;
pub use std::io;
pub use std::io::prelude::*;
pub use std::io::BufReader;
pub use std::fs::File;
pub use std::str;
pub use openssl::crypto::symm::Type;
pub use openssl::crypto::symm::decrypt as openssl_decrypt;
pub use std::iter::FromIterator;

pub fn hex_to_base64(input: &str) -> String {
    let bytes = input.from_hex().unwrap();
    return bytes.to_base64(serialize::base64::STANDARD);
}

pub fn score_english_chi2(input: &str) -> f32 {
    let mut english_frequencies: HashMap<char, f32> = HashMap::new();
    english_frequencies.insert('A', 0.0651738);
    english_frequencies.insert('B', 0.0124248);
    english_frequencies.insert('C', 0.0217339);
    english_frequencies.insert('D', 0.0349835);
    english_frequencies.insert('E', 0.1041442);
    english_frequencies.insert('F', 0.0197881);
    english_frequencies.insert('G', 0.0158610);
    english_frequencies.insert('H', 0.0492888);
    english_frequencies.insert('I', 0.0558094);
    english_frequencies.insert('J', 0.0009033);
    english_frequencies.insert('K', 0.0050529);
    english_frequencies.insert('L', 0.0331490);
    english_frequencies.insert('M', 0.0202124);
    english_frequencies.insert('N', 0.0564513);
    english_frequencies.insert('O', 0.0596302);
    english_frequencies.insert('P', 0.0137645);
    english_frequencies.insert('Q', 0.0008606);
    english_frequencies.insert('R', 0.0497563);
    english_frequencies.insert('S', 0.0515760);
    english_frequencies.insert('T', 0.0729357);
    english_frequencies.insert('U', 0.0225134);
    english_frequencies.insert('V', 0.0082903);
    english_frequencies.insert('W', 0.0171272);
    english_frequencies.insert('X', 0.0013692);
    english_frequencies.insert('Y', 0.0145984);
    english_frequencies.insert('Z', 0.0007836);
    english_frequencies.insert(' ', 0.1918182);
    let total_observed_count = input.len();

    let mut observed_counts: HashMap<char, u32> = HashMap::new();
    for c in input.to_uppercase().chars() {
        *observed_counts.entry(c).or_insert(0) += 1;
    }

    let mut chi2 = 0.0;
    for (c, expected_frequency) in english_frequencies.iter() {
        let &observed_count = observed_counts.get(c).unwrap_or(&0);
        let frequency_delta = (observed_count as f32 / total_observed_count as f32) - expected_frequency;
        chi2 = frequency_delta.powf(2.0) / expected_frequency;
    }

    return total_observed_count as f32 * chi2;
}

pub fn decrypt_single_byte_xor(input: &str) -> (OrderedFloat<f64>, u8, String) {
    let mut english_frequencies: BTreeMap<char, f64> = BTreeMap::new();
    english_frequencies.insert('A', 0.0651738);
    english_frequencies.insert('B', 0.0124248);
    english_frequencies.insert('C', 0.0217339);
    english_frequencies.insert('D', 0.0349835);
    english_frequencies.insert('E', 0.1041442);
    english_frequencies.insert('F', 0.0197881);
    english_frequencies.insert('G', 0.0158610);
    english_frequencies.insert('H', 0.0492888);
    english_frequencies.insert('I', 0.0558094);
    english_frequencies.insert('J', 0.0009033);
    english_frequencies.insert('K', 0.0050529);
    english_frequencies.insert('L', 0.0331490);
    english_frequencies.insert('M', 0.0202124);
    english_frequencies.insert('N', 0.0564513);
    english_frequencies.insert('O', 0.0596302);
    english_frequencies.insert('P', 0.0137645);
    english_frequencies.insert('Q', 0.0008606);
    english_frequencies.insert('R', 0.0497563);
    english_frequencies.insert('S', 0.0515760);
    english_frequencies.insert('T', 0.0729357);
    english_frequencies.insert('U', 0.0225134);
    english_frequencies.insert('V', 0.0082903);
    english_frequencies.insert('W', 0.0171272);
    english_frequencies.insert('X', 0.0013692);
    english_frequencies.insert('Y', 0.0145984);
    english_frequencies.insert('Z', 0.0007836);
    english_frequencies.insert(' ', 0.1918182);
    let bytes = input.from_hex().unwrap();
    // score each possible mask and push onto heap
    let mut scored_candidates = BinaryHeap::new();
    for mask in 0..127 {
        // compute candidate
        let mut candidate = Vec::new();
        for byte in &bytes {
            candidate.push(mask ^ byte);
        }
        // score candidate
        let mut score = 0.0;
        for byte in candidate.to_ascii_uppercase() {
            let c = byte as char;
            let default_score: f64 = 0.0;
            let &c_score = english_frequencies.get(&c).unwrap_or(&default_score);
            score += c_score;
        }
        scored_candidates.push((OrderedFloat::from(score), mask, candidate));
    }
    let &(score, key, ref candidate) = scored_candidates.peek().unwrap();
    return (score, key, String::from_utf8_lossy(candidate).into_owned());
}

fn hamming_distance_str(a: &str, b: &str) -> u32 {
    return hamming_distance_bytes(a.as_bytes(), b.as_bytes())
}

fn hamming_distance_bytes(a: &[u8], b: &[u8]) -> u32 {
    assert_eq!(a.len(), b.len());
    let mut distance = 0;
    for (idx, byte) in a.iter().enumerate() {
        let xor = byte ^ b[idx];
        distance += xor.count_ones();
    }

    return distance;
}

fn repeating_key_xor(key: &str, input: &str) -> Vec<u8> {
    let key_len = key.len();
    let _key = key.as_bytes();
    let mut output = Vec::new();
    for (idx, byte) in input.as_bytes().iter().enumerate() {
        let mask = _key[idx % key_len];
        output.push(mask ^ byte);
    }

    return output;
}

fn guess_key_size(bytes: &[u8], max_key_size: usize) -> Vec<usize> {
    let mut key_sizes = BinaryHeap::new();
    for key_size in 2..max_key_size {
        let mut chunks = bytes.chunks(key_size);
        let mut last_chunk = chunks.next().unwrap();
        let mut acc_distance = 0;
        let mut num_comparisons: u32 = 0;
        for chunk in chunks {
            if chunk.len() < last_chunk.len() {
                break;
            }
            acc_distance += hamming_distance_bytes(last_chunk, chunk);
            num_comparisons += 1;
            last_chunk = chunk;
        }
        let avg_distance = acc_distance as f32 / num_comparisons as f32;
        let normalized_distance = avg_distance / (key_size as f32);
        key_sizes.push((OrderedFloat::from(normalized_distance), key_size));
    }
    let sorted_guesses: Vec<usize> = key_sizes.into_sorted_vec().iter()
        .map(|&(_, key_size)| key_size)
        .collect();
    return sorted_guesses;
}

fn transpose_bytes(bytes: &[u8], key_size: usize) -> (Vec<u8>, usize) {
    let mut padded_len = bytes.len();
    if !(0 == padded_len % key_size) {
        let padding = key_size - (padded_len % key_size);
        padded_len += padding;
    }
    let rows = padded_len / key_size;
    let mut padded_bytes = Vec::with_capacity(padded_len);
    padded_bytes.extend_from_slice(bytes);
    padded_bytes.resize(padded_len, 0);
    let mut transposed_bytes = vec![0; padded_len];
    for i in 0..key_size {
        for j in 0..rows {
            transposed_bytes[i * rows + j] = padded_bytes[i + j * key_size];
        }
    }

    return (transposed_bytes, rows);
}

fn decrypt_repeating_key_xor(bytes: &[u8], max_key_size: usize) -> Vec<String> {
    let key_size_guesses = guess_key_size(&bytes, max_key_size);
    let mut possible_keys = Vec::new();
    for key_size in key_size_guesses.iter().take(3) {
        let (transposed, cols) = transpose_bytes(bytes, *key_size);
        let mut keys = Vec::new();
        for row in transposed.chunks(cols) {
            let (_, key, _) = decrypt_single_byte_xor(&row.to_hex());
            keys.push(key);
        }
        let key = String::from_utf8(keys).unwrap();
        possible_keys.push(key);
    }

    return possible_keys;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn _1_1_hex_to_base64_test() {
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        assert_eq!(expected, hex_to_base64(input));
    }

    #[test]
    fn _1_2_fixed_xor() {
        let expected = "746865206b696420646f6e277420706c6179";
        let x1 = "1c0111001f010100061a024b53535009181c";
        let x2 = "686974207468652062756c6c277320657965";
        let x1_bytes = x1.from_hex().unwrap();
        let x2_bytes = x2.from_hex().unwrap();
        let mut xor_bytes = Vec::new();
        for (idx, byte) in x1_bytes.iter().enumerate() {
            xor_bytes.push(byte ^ x2_bytes[idx]);
        }
        assert_eq!(expected, xor_bytes.to_hex())
    }

    #[test]
    fn _1_3_decrypt_xor() {
       let (_, key, msg) = decrypt_single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        println!("Most likely candidate: {} with key: {}", msg, key);
    }

    #[test]
    fn _1_4_detect_xor() {
        let mut candidates = BinaryHeap::new();
        let f = File::open("fixtures/1/4.txt").unwrap();
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let candidate = decrypt_single_byte_xor(line.unwrap().as_str());
            candidates.push(candidate);
        }
        let &(_, _, ref candidate) = candidates.peek().unwrap();
        println!("Most likely candidate: {}", candidate);
    }

    #[test]
    fn test_hamming_distance() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        assert_eq!(37, super::hamming_distance_str(a, b));
    }

    #[test]
    fn _1_5_repeating_key_xor() {
        let key = "ICE";
        let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let actual = super::repeating_key_xor(key, input).to_hex();
        println!("Encoded {} as {}", input, actual);
        assert_eq!(expected, actual);
    }

    #[test]
    fn _1_6_1_break_repeating_key_xor() {
        let cipher_text = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let cipher_bytes = cipher_text.from_hex().unwrap();
        let possible_keys = super::decrypt_repeating_key_xor(&cipher_bytes, 10);
        for key in possible_keys {
            let plain_text = super::repeating_key_xor(&key, str::from_utf8(&cipher_bytes).unwrap());
            let candidate = String::from_utf8(plain_text).unwrap();
            println!("_1_6_1 key: {}, candidate: {}, score: {}", key, candidate, super::score_english_chi2(&candidate));
        }
    }

    #[test]
    fn _1_6_break_repeating_key_xor() {
        let max_key_size = 40;
        let f = File::open("fixtures/1/6.txt").unwrap();
        let mut reader = BufReader::new(f);
        let mut cipher_text = String::new();
        reader.read_to_string(&mut cipher_text).unwrap();
        let cipher_bytes = cipher_text.from_base64().unwrap();
        let possible_keys = super::decrypt_repeating_key_xor(&cipher_bytes, max_key_size);
        for key in possible_keys {
            let plain_text = super::repeating_key_xor(&key, str::from_utf8(&cipher_bytes).unwrap());
            let candidate = String::from_utf8(plain_text).unwrap();
            println!("_1_6 key: {}\n candidate: {}\n score: {}", key, candidate, super::score_english_chi2(&candidate));
        }
    }

    #[test]
    fn test_transpose_bytes() {
        let input: Vec<u8> = vec![1, 2, 3,
                                  4, 5, 6];
        let (output, cols) = super::transpose_bytes(&input, 3);
        assert_eq!(2, cols);
        assert_eq!(vec![1, 4, 2, 5, 3, 6], output);

        let input2: Vec<u8> = vec![1, 2, 3,
                                   4, 5, 6,
                                   7];
        let (output2, cols2) = super::transpose_bytes(&input2, 3);
        assert_eq!(3, cols2);
        assert_eq!(vec![1, 4, 7, 2, 5, 0, 3, 6, 0], output2);
    }

    #[test]
    fn _1_7_decrypt_aes() {
        let f = File::open("fixtures/1/7.txt").unwrap();
        let mut reader = BufReader::new(f);
        let mut cipher_text = String::new();
        reader.read_to_string(&mut cipher_text).unwrap();
        let cipher_bytes = cipher_text.from_base64().unwrap();
        let decrypted_bytes = super::openssl_decrypt(Type::AES_128_ECB, "YELLOW SUBMARINE".as_bytes(), None, &cipher_bytes)
            .unwrap();
        println!("Decrypted with key: YELLOW SUBMARINE as: {}", String::from_utf8(decrypted_bytes).unwrap());
    }

    #[test]
    fn _1_8_detect_aes() {
        let f = File::open("fixtures/1/8.txt").unwrap();
        let mut reader = BufReader::new(f);
        let mut coincidences = BinaryHeap::new();
        for line in reader.lines() {
            let mut cipher_text = line.unwrap();
            let cipher_bytes = cipher_text.from_hex().unwrap();
            let cipher_blocks: Vec<&[u8]> = Vec::from_iter(cipher_bytes.chunks(16));
            let mut coincidence = 0;
            for i in 0..(cipher_blocks.len() - 1) {
                for j in 0..(cipher_blocks.len() -1) {
                    if i == j {
                        break;
                    }

                    let distance = super::hamming_distance_bytes(cipher_blocks[i], cipher_blocks[j]);
                    if distance == 0 {
                        coincidence += 1;
                    }
                }
            }
            cipher_text.truncate(10);
            coincidences.push((coincidence, cipher_text));
        }
        let (top_score, cipher_text) = coincidences.pop().unwrap();
        println!("Found {} repeating blocks in ciphertext starting with {}...", top_score, cipher_text);
    }
}

