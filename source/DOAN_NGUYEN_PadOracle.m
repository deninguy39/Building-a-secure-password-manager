% ----------------------- LAB 2 - Padding Oracle Attack -----------------------

% -------- Part 2 : Implement a padding oracle attack on the CBC Mode -------- %

% ---------- Startup ---------- %

% Clear
clear all;
close all;
clc;

% Define the ciphertext to attack and decipher
ciphertext =[152 182 162 107 74 151 206 122 49 166 194 235 125 70 14 8 232 202 138 150 18 231 233 212 131 197 38 38 106 84 160 247 168 206 1 7 187 209 215 7 29 245 96 133 28 203 62 37 235 183 132 7 86 36 16 78 199 197 123 104 129 45 218 153];

% ---------- Decipher block recovery test with for exemple k = 1 ----------%
% block_1 = blockRecoveryPOA(ciphertext,1);

% ---------- Now let's try to recover the deciphered text ---------- %

% Define a 16-byte secret key in ASCII
key_ascii = 'Who are Newjeans';

% Define a nonce
nonce_ascii = num2str(cputime*1e14);

% Force nonce to have 16 elements
nonce_pad_len = 16-length(nonce_ascii);
nonce_ascii_16 = [nonce_ascii,zeros(1,nonce_pad_len)];

% Convert key in double
key = double(key_ascii);
nonce = double(nonce_ascii_16);

% Generate the IV
IV = cipher(nonce, key);

% Add IV to the ciphertext
complete_ciphertext = [IV,ciphertext];
len_text = length(complete_ciphertext);
block_len = 16;

% We might need the completed ciphertext without the last 16-bytes long block
decrypt_ciphertext = complete_ciphertext(1:end-16);

% number of blocks
num_chainIV = length(complete_ciphertext)/block_len; 
num_chain = length(decrypt_ciphertext)/block_len;

decipheredVect = [];

for i = 1:num_chainIV
    decipheredBlock = blockRecoveryPOA(complete_ciphertext,i);
    decipheredVect = [decipheredVect,decipheredBlock];
end

% Finally the recovered message
recovered_msg = bitxor(decipheredVect,complete_ciphertext);
char(recovered_msg);

