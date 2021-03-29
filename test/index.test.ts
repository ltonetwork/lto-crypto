import {
  address,
  keyPair,
  publicKey,
  privateKey,
  signBytes,
  verifySignature,
  base58encode,
  base58decode,
  keyPairFromSeedHash,
  chainIdOf,
  deriveAddress,
} from '../src'

const seed = '1f98af466da54014bdc08bfbaaaf3c67';
const seedHash = '7eUDZzhroaFfBz8QDbSdCAh6BRAds5a5V7QPfR8gJTWw';

test('address', () => {
  expect(address(seed)).toBe('3JhHfA9kxKE37HuBVnzK9ZMSL5xzD8oN9nD');
  expect(address(seed, 'L', 1)).toBe('3JtVW6MW7wWpVAMLcVPrwwtA7C9rGvzkPQN');
});

test('address testnet', () => {
  expect(address(seed, 'T')).toBe('3MuzV329Fzfk7qNJBzLyhSMcd813kuH32c3');
  expect(address(seed, 'T', 1)).toBe('3N7CKyDtRcxXVhpTJgkXVptLQEBupfH8xWD');
});

test('address', () => {
  expect(address(seed)).toBe('3JhHfA9kxKE37HuBVnzK9ZMSL5xzD8oN9nD');
  expect(address(seed, 'L', 1)).toBe('3JtVW6MW7wWpVAMLcVPrwwtA7C9rGvzkPQN');
});

test('keyPair', () => {
  expect(keyPair(seed)).toEqual({
    public: '94cXghv1RRwmEjDM5BS88euGt8mUR1wGmhw4BdakmrYT',
    private: '2c8zS9dasxdrqLXjooujeDwME1nrGcNVMDJaqfVGyzidUqdVow7yt2Pu5B7L8Lg3dt9Ci89rtK6jyHjPYBMT6fTH'
  })
});

test('keyPairFromSeedHash', () =>
  expect(keyPairFromSeedHash(seedHash)).toEqual({
    public: '94cXghv1RRwmEjDM5BS88euGt8mUR1wGmhw4BdakmrYT',
    private: '2c8zS9dasxdrqLXjooujeDwME1nrGcNVMDJaqfVGyzidUqdVow7yt2Pu5B7L8Lg3dt9Ci89rtK6jyHjPYBMT6fTH'
  })
);

test('publicKey', () => {
  expect(publicKey(seed)).toBe('94cXghv1RRwmEjDM5BS88euGt8mUR1wGmhw4BdakmrYT')
});

test('privateKey', () => {
  expect(privateKey(seed)).toBe('2c8zS9dasxdrqLXjooujeDwME1nrGcNVMDJaqfVGyzidUqdVow7yt2Pu5B7L8Lg3dt9Ci89rtK6jyHjPYBMT6fTH')
});

test('signature roundtrip', () => {
  const bytes = Uint8Array.from([1, 2, 3, 4]);
  const sig = signBytes(bytes, seed);
  const valid = verifySignature(publicKey(seed), bytes, sig);
  const invalid = verifySignature(publicKey(seed), Uint8Array.from([4, 3, 2, 1]), sig);
  expect(valid).toBe(true);
  expect(invalid).toBe(false);
});

test('base58 roundtrip', () => {
  const base58 = '5k1XmKDYbpxqAN';
  const result = base58encode(base58decode(base58));
  expect(result).toEqual(base58);
});

test('chainIdOf', () => {
  expect(chainIdOf('3JhHfA9kxKE37HuBVnzK9ZMSL5xzD8oN9nD')).toBe('L');
  expect(chainIdOf('3MuzV329Fzfk7qNJBzLyhSMcd813kuH32c3')).toBe('T');
});

test('deriveAddress', () => {
  expect(deriveAddress(
    {public: '94cXghv1RRwmEjDM5BS88euGt8mUR1wGmhw4BdakmrYT'},
    '62K'
  )).toBe('3JrfUdbJ1Z15dgTjZ4knjteWjJi3WXdg8YD');
});

test('deriveAddress', () => {
  expect(deriveAddress(
    {public: '94cXghv1RRwmEjDM5BS88euGt8mUR1wGmhw4BdakmrYT'},
    '62K',
    'T'
  )).toBe('3N5NJWTgKESneDvrFG7THmeh2Lk74CRJkZT');
});
