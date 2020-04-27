declare interface PublicKey {
	public: string;
}

declare interface KeyPair extends PublicKey {
	private: string;
}

declare namespace RSA {
	export function generate(keySize: number): Promise<PublicKey>;
	export function generateKeys(keySize: number): Promise<KeyPair>;
	export function encrypt(data: string, key: string): Promise<string>;
	export function decrypt(data: string, key: string): Promise<string>;
	export function sign(data: string, key: string): Promise<string>;
	export function signWithAlgorithm(data: string, key: string, signature?: 'SHA256withRSA' | 'SHA512withRSA'): Promise<string>;
	export function verify(data: string, secretToVerify: string, key: string): Promise<boolean>;
	export function verifyWithAlgorithm(data: string, secretToVerify: string, key: string, signature?: 'SHA256withRSA' | 'SHA512withRSA'): Promise<boolean>;
	export const SHA256withRSA: string;
	export const SHA512withRSA: string;
}

declare namespace RSAKeychain {
	export function generate(keyTag: string, keySize: number): Promise<PublicKey>;
	export function generateKeys(keyTag: string, keySize: number): Promise<PublicKey>;
	export function deletePrivateKey(keyTag: string): Promise<boolean>;
	export function encrypt(data: string, keyTag: string): Promise<string>;
	export function decrypt(data: string, keyTag: string): Promise<string>;
	export function sign(data: string, keyTag: string): Promise<string>;
	export function signWithAlgorithm(data: string, keyTag: string, signature?: 'SHA256withRSA' | 'SHA512withRSA'): Promise<string>;
	export function verify(data: string, secretToVerify: string, keyTag: string): Promise<boolean>;
	export function verifyWithAlgorithm(data: string, secretToVerify: string, keyTag: string, signature?: 'SHA256withRSA' | 'SHA512withRSA'): Promise<boolean>;
	export function getPublicKey(keyTag: string): Promise<string | undefined>;
	export function hasPublicKey(keyTag: string): Promise<boolean>;
	export const SHA256withRSA: string;
	export const SHA512withRSA: string;
}

export { RSA, RSAKeychain };