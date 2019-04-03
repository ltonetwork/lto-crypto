import {
  address,
  keyPair,
  publicKey,
  privateKey,
  signBytes,
  verifySignature,
  base58encode,
  base58decode,
} from '../src'

const seed = '1f98af466da54014bdc08bfbaaaf3c67';

test('address', () =>
  expect(address(seed)).toBe('3JhHfA9kxKE37HuBVnzK9ZMSL5xzD8oN9nD')
);

test('keyPair', () =>
  expect(keyPair(seed)).toEqual({
    public: '94cXghv1RRwmEjDM5BS88euGt8mUR1wGmhw4BdakmrYT',
    private: '2c8zS9dasxdrqLXjooujeDwME1nrGcNVMDJaqfVGyzidUqdVow7yt2Pu5B7L8Lg3dt9Ci89rtK6jyHjPYBMT6fTH'
  })
);

test('publicKey', () =>
  expect(publicKey(seed)).toBe('94cXghv1RRwmEjDM5BS88euGt8mUR1wGmhw4BdakmrYT')
);

test('privateKey', () =>
  expect(privateKey(seed)).toBe('2c8zS9dasxdrqLXjooujeDwME1nrGcNVMDJaqfVGyzidUqdVow7yt2Pu5B7L8Lg3dt9Ci89rtK6jyHjPYBMT6fTH')
);

test('signature roundtrip', () => {
  const bytes = Uint8Array.from([1, 2, 3, 4]);
  const sig = signBytes(bytes, seed);
  const valid = verifySignature(publicKey(seed), bytes, sig);
  const invalid = verifySignature(publicKey(seed), Uint8Array.from([4, 3, 2, 1]), sig);
  expect(valid).toBe(true);
  expect(invalid).toBe(false)
});

test('base58 roundtrip', () => {
  const base58 = '5k1XmKDYbpxqAN';
  const result = base58encode(base58decode(base58));
  expect(result).toEqual(base58)
});
